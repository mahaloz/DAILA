"""Codex App Server backend for DAILA.

Uses the locally installed and authenticated `codex` CLI. Requires no extra
Python dependencies. One App Server process is reused, but each query gets a
fresh (ephemeral) thread to prevent context leaking between requests.

"""

import json
import queue
import subprocess
import sys
import threading
from typing import Optional


class CodexBackend:
    def __init__(self, codex_executable: str = "codex", timeout: float = 120):
        self.timeout = timeout
        self._messages = queue.Queue()
        self._next_id = 1
        self._lock = threading.RLock()
        self._closed = False
        self._proc = subprocess.Popen(
            [codex_executable, "app-server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # Preserve Codex diagnostics on the terminal.
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_messages, daemon=True)
        self._reader.start()
        try:
            self._request("initialize", {
                "clientInfo": {
                    "name": "daila_codex_backend",
                    "title": "DAILA Codex Backend",
                    "version": "0.1.0",
                },
            })
            self._send({"method": "initialized", "params": {}})
        except Exception:
            self.close()
            raise

    def _read_messages(self):
        try:
            for line in self._proc.stdout:
                try:
                    self._messages.put(json.loads(line))
                except json.JSONDecodeError:
                    print(f"Non-JSON Codex output: {line.rstrip()}", file=sys.stderr)
        finally:
            self._messages.put(None)

    def _send(self, message):
        if self._closed or self._proc.poll() is not None:
            raise RuntimeError("Codex App Server is not running")
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(message) + "\n")
        self._proc.stdin.flush()

    def _receive(self):
        try:
            message = self._messages.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise TimeoutError(f"No Codex message received within {self.timeout:g} seconds") from exc
        if message is None:
            raise RuntimeError("Codex App Server closed its output")
        return message

    def _reject_server_request(self, message):
        # This prompt-only client does not handle requests for interactive tools.
        self._send({
            "id": message["id"],
            "error": {"code": -32601, "message": "Unsupported client request"},
        })

    def _request(self, method, params):
        request_id = self._next_id
        self._next_id += 1
        self._send({"id": request_id, "method": method, "params": params})
        while True:
            message = self._receive()
            if message.get("id") == request_id and "method" not in message:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message["result"]
            if "id" in message and "method" in message:
                self._reject_server_request(message)
            # Other notifications are informational for this prototype.

    def query_model(self, prompt: str) -> tuple[str, Optional[float]]:
        """Return (assistant_text, estimated_api_cost).

        `None` means cost is not calculated; it does NOT imply unlimited usage.
        """
        with self._lock:
            thread = self._request("thread/start", {
                "ephemeral": True,
                "approvalPolicy": "never",
                "sandbox": "read-only",
            })["thread"]
            thread_id = thread["id"]

            turn = self._request("turn/start", {
                "threadId": thread_id,
                "input": [{"type": "text", "text": prompt}],
            })["turn"]
            turn_id = turn["id"]

            answers = []
            while True:
                message = self._receive()
                method = message.get("method")
                params = message.get("params", {})
                if (method == "item/completed"
                        and params.get("threadId") == thread_id
                        and params.get("turnId") == turn_id):
                    item = params.get("item", {})
                    if item.get("type") == "agentMessage" and item.get("text"):
                        answers.append(item["text"])
                elif (method == "turn/completed"
                      and params.get("threadId") == thread_id
                      and params.get("turn", {}).get("id") == turn_id):
                    finished = params["turn"]
                    if finished.get("status") != "completed":
                        raise RuntimeError(
                            f"Codex turn ended with status {finished.get('status')}: "
                            f"{finished.get('error')}"
                        )
                    if not answers:
                        raise RuntimeError("Codex completed without returning assistant text")
                    return "\n".join(answers), None
                elif "id" in message and "method" in message:
                    self._reject_server_request(message)

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
        if self._proc.stdin is not None:
            self._proc.stdin.close()
        if self._proc.stdout is not None:
            self._proc.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
