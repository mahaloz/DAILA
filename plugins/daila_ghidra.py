# Activates DAILA where the user will be able to select from a series of possible commands
#@category AI
#@menupath Tools.DAILA: Run a DAILA operation...
#@keybinding ctrl alt shift d
import os

import xmlrpclib
from time import sleep
import subprocess

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

fpapi = FlatProgramAPI(getState().getCurrentProgram())
fdapi = FlatDecompilerAPI(fpapi)


#
# Ghidra decompiler utils
#

def current_func():
    func = fpapi.getFunctionContaining(currentAddress)
    return func if func else None


def decompile_curr_func():
    func = current_func()
    if func is None:
        return None

    decomp = fdapi.decompile(func)
    if not decomp:
        return None

    return str(decomp)


def set_func_comment(comment):
    func = current_func()
    if func is None:
        return False

    func.setComment(comment)
    return True

#
# DAILA feature funcs
#


class ServerCtx:
    def __init__(self, host="http://localhost", port=44414):
        self.proxy_host = "%s:%d" % (host, port)

        self.server_proc = None
        self.server = None

    def __enter__(self, *args, **kwargs):
        self._start_server()
        key = os.getenv("OPENAI_API_KEY")
        if key:
            self.server.set_api_key(key)

        return self.server

    def __exit__(self, *args, **kwargs):
        self._stop_server()

    def _start_server(self):
        self.server_proc = subprocess.Popen(["python3", "-m", "daila", "-server"])
        sleep(3)
        self.server = xmlrpclib.ServerProxy(self.proxy_host)

        try:
            self.server.ping()
        except BaseException as e:
            print("[!] Encountered an error when creating the py3 server", e)
            if self.server_proc is not None:
                self.server_proc.kill()

            self.server_proc = None
            self.server = None

    def _stop_server(self):
        if self.server_proc is None or self.server is None:
            return

        self.server.shutdown()
        self.server_proc.kill()
        self.server = None
        self.server_proc = None

#
# DAILA API
#


def identify_function():
    with ServerCtx() as server:
        decomp = decompile_curr_func()
        if decomp is None:
            return None

        resp = server.identify_function(decomp)
        if not resp:
            return None

        set_func_comment(resp)


def explain_function():
    with ServerCtx() as server:
        decomp = decompile_curr_func()
        if decomp is None:
            return None

        resp = server.explain_function(decomp)
        if not resp:
            return None

        set_func_comment(resp)


def set_api_key():
    old_key = os.getenv("OPENAI_API_KEY")
    key = askString("DAILA", "Enter your OpenAI API Key: ", old_key)
    if not key:
        return

    with ServerCtx() as server:
        server.set_api_key("")

    os.putenv("OPENAI_API_KEY", key)

#
# Operation Selector
#


DAILA_OPS = {
    "Identify function source": identify_function,
    "Explain function": explain_function,
    "Set OpenAPI Key...": set_api_key,
}


def select_and_run_daila_op():
    daila_op_keys = list(DAILA_OPS.keys())
    choice = askChoice("DAILA Operation Selector", "Please choose a DAILA operation", daila_op_keys, daila_op_keys[0])
    if not choice:
        print("[+] Cancelled...")
        return

    op_func = DAILA_OPS[choice]
    op_func()


if __name__ == "__main__":
    print("[+] Starting DAILA Operations selector for " + str(current_func()))
    select_and_run_daila_op()

