import re
from typing import Optional, Dict
import os
import textwrap
import json
from functools import wraps

from openai import OpenAI
import tiktoken

from .generic_ai_interface import GenericAIInterface
from ..utils import HYPERLINK_REGEX


def addr_ctx_when_none(f):
    @wraps(f)
    def _addr_ctx_when_none(self: "OpenAIInterface", *args, **kwargs):
        func_addr = kwargs.get("func_addr", None)
        if func_addr is None:
            func_addr = self._current_function_addr()
            kwargs.update({"func_addr": func_addr, "edit_dec": True})
        return f(self, *args, **kwargs)
    return _addr_ctx_when_none

JSON_REGEX = re.compile(r"\{.*\}", flags=re.DOTALL)
QUESTION_START = "Q>"
QUESTION_REGEX = re.compile(rf"({QUESTION_START})([^?]*\?)")
ANSWER_START = "A>"

DEFAULT_MODEL = "gpt-4"
MODEL_TO_TOKENS = {
    "gpt-4": 8000,
    "gpt-3.5-turbo": 4096
}

class OpenAIInterface(GenericAIInterface):
    # API Command Constants
    SUMMARIZE_CMD = "daila_summarize"
    RENAME_FUNCS_CMD = "daial_rename_funcs"
    RENAME_VARS_CMD = "daila_rename_vars"
    RETYPE_VARS_CMD = "daila_retype_vars"
    FIND_VULN_CMD = "daila_find_vuln"
    ID_SOURCE_CMD = "daila_id_source"
    ANSWER_QUESTION_CMD = "daila_answer_question"
    AI_COMMANDS = {
        RENAME_VARS_CMD: {"json_response": True},
        RETYPE_VARS_CMD: {"json_response": True},
        SUMMARIZE_CMD: {},
        RENAME_FUNCS_CMD: {"json_response": True},
        ID_SOURCE_CMD: {"increase_new_text": False},
        FIND_VULN_CMD: {},
        ANSWER_QUESTION_CMD: {"extra_handler": "answer_questions_in_decompilation"},
    }

    # replacement strings for API calls
    DECOMP_REPLACEMENT_LABEL = "<DECOMPILATION>"
    SNIPPET_REPLACEMENT_LABEL = "<SNIPPET>"
    SNIPPET_TEXT = f"\n\"\"\"{SNIPPET_REPLACEMENT_LABEL}\"\"\""
    DECOMP_TEXT = f"\n\"\"\"{DECOMP_REPLACEMENT_LABEL}\"\"\""
    PROMPTS = {
        RENAME_VARS_CMD: 'Analyze what the following function does. Suggest better variable names. '
                         'Reply with only a JSON array where keys are the original names and values are '
                         f'the proposed names. Here is an example response: {{"v1": "buff"}}  {DECOMP_TEXT}',
        RETYPE_VARS_CMD: "Analyze what the following function does. Suggest better C types for the variables. "
                         "Reply with only a JSON where keys are the original names and values are the "
                         f"proposed types: {DECOMP_TEXT}",
        SUMMARIZE_CMD: f"Please summarize the following code:{DECOMP_TEXT}",
        FIND_VULN_CMD: "Can you find the vulnerability in the following function and suggest the "
                       f"possible way to exploit it?{DECOMP_TEXT}",
        ID_SOURCE_CMD: "What open source project is this code from. Please only give me the program name and "
                       f"package name:{DECOMP_TEXT}",
        RENAME_FUNCS_CMD: "The following code is C/C++. Rename the function according to its purpose using underscore_case. Reply with only a JSON array where keys are the "
                          f"original names and values are the proposed names:{DECOMP_TEXT}",
        ANSWER_QUESTION_CMD: "You are a code comprehension assistant. You answer questions based on code that is "
                             f"provided. Here is some code: {DECOMP_TEXT}. Focus on this snippet of the code: "
                             f"{SNIPPET_TEXT}\n\n Answer the following question as concisely as possible, guesses "
                             f"are ok: "
    }

    def __init__(self, openai_api_key=None, model=DEFAULT_MODEL, decompiler_controller=None):
        super().__init__(decompiler_controller=decompiler_controller)
        self.model = model

        self.menu_commands = {
            "daila_set_key": ("Update OpenAPI Key...", self.ask_api_key),
            f"{self.ID_SOURCE_CMD}": ("Identify the source code", self.find_source_of_function),
            f"{self.SUMMARIZE_CMD}": ("Summarize function", self.summarize_function),
            f"{self.FIND_VULN_CMD}": ("Find vulnerabilities", self.find_vulnerability_in_function),
            f"{self.RENAME_FUNCS_CMD}": ("Rename functions used in function", self.rename_functions_in_function),
            f"{self.RENAME_VARS_CMD}": ("Rename variables in function", self.rename_variables_in_function),
            f"{self.RETYPE_VARS_CMD}": ("Retype variables in function", self.retype_variables_in_function),
            f"{self.ANSWER_QUESTION_CMD}": ("Answer questions in function", self.answer_questions),
        }

        for menu_str, callback_info in self.menu_commands.items():
            callback_str, callback_func = callback_info
            self._register_menu_item(menu_str, callback_str, callback_func)

        self._api_key = os.getenv("OPENAI_API_KEY") or openai_api_key
        self._openai_client = OpenAI(api_key=self._api_key)


    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, data):
        self._api_key = data
        

    #
    # OpenAI Interface
    #

    def _query_openai_model(
        self,
        question: str,
        model: Optional[str] = None,
        temperature=0.1,
        max_tokens=None,
        frequency_penalty=0,
        presence_penalty=0
    ):
        # TODO: at some point add back frequency_penalty and presence_penalty to be used
        try:
            response = self._openai_client.chat.completions.create(model=model or self.model,
            messages=[
                {"role": "user", "content": question}
            ],
            max_tokens=max_tokens,
            timeout=60,
            stop=['}'])
        except openai.OpenAIError as e:
            raise Exception(f"ChatGPT could not complete the request: {str(e)}")

        answer = None
        try:
            answer = response.choices[0].message.content
        except (KeyError, IndexError) as e:
            pass

        return answer

    def _query_openai(self, prompt: str, json_response=False, increase_new_text=True, **kwargs):
        freq_penalty = 0
        pres_penalty = 0
        default_response = {} if json_response else None

        if increase_new_text:
            freq_penalty = 1
            pres_penalty = 1

        resp = self._query_openai_model(prompt, frequency_penalty=freq_penalty, presence_penalty=pres_penalty)
        if resp is None:
            return default_response

        if json_response:
            # if the response of OpenAI gets cut off, we have an incomplete JSON
            if "}" not in resp:
                resp += "}"

            json_matches = JSON_REGEX.findall(resp)
            if not json_matches:
                return default_response

            json_data = json_matches[0]
            try:
                data = json.loads(json_data)
            except Exception:
                data = {}

            return data

        return resp

    def query_openai_for_function(
        self, func_addr: int, prompt: str, decompile=True, json_response=False, increase_new_text=True,
        **kwargs
    ):
        default_response = {} if json_response else None
        if decompile:
            decompilation = self._decompile(func_addr, **kwargs)
            if not decompilation:
                return default_response

            prompt = prompt.replace(self.DECOMP_REPLACEMENT_LABEL, decompilation)
        else:
            decompilation = kwargs.get("decompilation", None)

        if "extra_handler" in kwargs:
            extra_handler = getattr(self, kwargs.pop("extra_handler"))
            kwargs["decompilation"] = decompilation
            return extra_handler(func_addr, prompt, **kwargs)
        else:
            return self._query_openai(prompt, json_response=json_response, increase_new_text=increase_new_text)

    def query_for_cmd(self, cmd, func_addr=None, decompilation=None, edit_dec=False, **kwargs):
        if cmd not in self.AI_COMMANDS:
            raise ValueError(f"Command {cmd} is not supported")

        kwargs.update(self.AI_COMMANDS[cmd])
        if func_addr is None and decompilation is None:
            raise Exception(f"You must provide either a function address or decompilation!")

        prompt = self.PROMPTS[cmd]
        if decompilation is not None:
            prompt = prompt.replace(self.DECOMP_REPLACEMENT_LABEL, decompilation)

        return self.query_openai_for_function(func_addr, prompt, decompile=decompilation is None, decompilation=decompilation, **kwargs)

    #
    # Extra Handlers
    #

    def answer_questions_in_decompilation(self, func_addr, prompt: str, context_window=25, **kwargs) -> Dict[str, str]:
        questions = [m for m in QUESTION_REGEX.finditer(prompt)]
        if not questions:
            return {}

        decompilation = kwargs.get("decompilation", None)
        if decompilation is None:
            print("Decompilation is required for answering questions!")
            return {}

        dec_lines = decompilation.split("\n")
        snippets = {}
        for question in questions:
            full_str = question.group(0)
            for i, line in enumerate(dec_lines):
                if full_str in line:
                    break
            else:
                snippets[full_str] = None
                continue

            context_window_lines = dec_lines[i+1:i+1+context_window]
            snippets[full_str] = "\n".join(context_window_lines)

        answers = {}
        for question in questions:
            full_str = question.group(0)
            question_str = question.group(2)
            snippet = snippets.get(full_str, None)

            if snippet is None:
                continue

            if full_str.endswith("X?"):
                normalized_prompt = question_str.replace("X?", "?")
            else:
                normalized_prompt = prompt.replace(self.SNIPPET_REPLACEMENT_LABEL, snippet) + question_str

            answer = self.query_openai_for_function(
                func_addr, normalized_prompt, decompile=False, **kwargs
            )
            if answer is not None:
                answers[full_str] = f"A> {answer}"

        return answers

    #
    # API Alias Wrappers
    #

    @addr_ctx_when_none
    def answer_questions(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> Dict[str, str]:
        resp = self.query_for_cmd(self.ANSWER_QUESTION_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        if resp and edit_dec:
            out = ""
            for q, a in resp.items():
                out += f"{q}\n{a}\n\n"

            self._cmt_func(func_addr, out)

        return resp

    @addr_ctx_when_none
    def summarize_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> str:
        resp = self.query_for_cmd(self.SUMMARIZE_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        if resp:
            resp = f"\nGuessed Summarization:\n{resp}"
        
        if edit_dec and resp:
            self._cmt_func(func_addr, resp)

        return resp

    @addr_ctx_when_none
    def find_vulnerability_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> str:
        resp = self.query_for_cmd(self.FIND_VULN_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        if resp:
            resp = f"\nGuessed Vuln:\n{resp}" 
        
        if edit_dec and resp:
            self._cmt_func(func_addr, resp)

        return resp

    @addr_ctx_when_none
    def find_source_of_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> str:
        resp = self.query_for_cmd(self.ID_SOURCE_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        links = re.findall(HYPERLINK_REGEX, resp)
        if not links:
            return ""

        resp = f"\nGuessed Source:\n{links}"
        if edit_dec:
            self._cmt_func(func_addr, resp)

        return resp

    @addr_ctx_when_none
    def rename_functions_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> dict:
        resp: Dict = self.query_for_cmd(self.RENAME_FUNCS_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        if edit_dec and resp:
            # TODO: reimplement this code with self.decompiler_controller.set_function(func)
            pass
        
        return resp

    @addr_ctx_when_none
    def rename_variables_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> dict:
        resp: Dict = self.query_for_cmd(self.RENAME_VARS_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        if edit_dec and resp:
            # TODO: reimplement this code with self.decompiler_controller.set_function(func)
            pass
        
        return resp

    @addr_ctx_when_none
    def retype_variables_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> dict:
        resp: Dict = self.query_for_cmd(self.RETYPE_VARS_CMD, func_addr=func_addr, decompilation=decompilation, **kwargs)
        if edit_dec and resp:
            # TODO: reimplement this code with self.decompiler_controller.set_function(func)
            pass

        return resp

    #
    # helpers
    #

    @staticmethod
    def estimate_token_amount(content: str, model=DEFAULT_MODEL):
        enc = tiktoken.encoding_for_model(model)
        tokens = enc.encode(content)
        return len(tokens)

    @staticmethod
    def content_fits_tokens(content: str, model=DEFAULT_MODEL):
        max_token_count = MODEL_TO_TOKENS[model]
        token_count = OpenAIInterface.estimate_token_amount(content, model=model)
        return token_count <= max_token_count - 1000

    @staticmethod
    def fit_decompilation_to_token_max(decompilation: str, delta_step=10, model=DEFAULT_MODEL):
        if OpenAIInterface.content_fits_tokens(decompilation, model=model):
            return decompilation

        dec_lines = decompilation.split("\n")
        last_idx = len(dec_lines) - 1
        # should be: [func_prototype] + [nop] + [mid] + [nop] + [end_of_code]
        dec_lines = dec_lines[0:2] + ["// ..."] + dec_lines[delta_step:last_idx-delta_step] + ["// ..."] + dec_lines[-2:-1]
        decompilation = "\n".join(dec_lines)

        return OpenAIInterface.fit_decompilation_to_token_max(decompilation, delta_step=delta_step, model=model)
