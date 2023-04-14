import re
from typing import Optional, Dict
import os
import textwrap
import json
from functools import wraps

import openai
from binsync.data import (
    Function
)


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


class OpenAIInterface(GenericAIInterface):
    # API Command Constants
    SUMMARIZE_CMD = "daila_summarize"
    RENAME_FUNCS_CMD = "daial_rename_funcs"
    RENAME_VARS_CMD = "daila_rename_vars"
    RETYPE_VARS_CMD = "daila_retype_vars"
    FIND_VULN_CMD = "daila_find_vuln"
    ID_SOURCE_CMD = "daila_id_source"
    COMMANDS_WITH_ARGS = {
        SUMMARIZE_CMD: {},
        RENAME_VARS_CMD: {"json_response": True},
        RENAME_FUNCS_CMD: {"json_response": True},
        RETYPE_VARS_CMD: {"json_response": True},
        FIND_VULN_CMD: {},
        ID_SOURCE_CMD: {"increase_new_text": False}
    }

    # replacement strings for API calls
    REPLACEMENT_LABEL = "<DECOMPILATION>"
    DECOMP_TEXT = f"\n\"\"\"{REPLACEMENT_LABEL}\"\"\""
    PROMPTS = {
        SUMMARIZE_CMD: f"Please summarize the following code:{DECOMP_TEXT}",
        RENAME_FUNCS_CMD: "Rename the functions in this code. Reply with only a JSON array where keys are the "
                          f"original names and values are the proposed names:{DECOMP_TEXT}",
        RENAME_VARS_CMD: "Analyze what the following function does. Suggest better variable names. "
                         "Reply with only a JSON array where keys are the original names and values are "
                         f"the proposed names:{DECOMP_TEXT}",
        RETYPE_VARS_CMD: "Analyze what the following function does. Suggest better C types for the variables. "
                         "Reply with only a JSON where keys are the original names and values are the "
                         f"proposed types: {DECOMP_TEXT}",
        FIND_VULN_CMD: "Can you find the vulnerability in the following function and suggest the "
                       f"possible way to exploit it?{DECOMP_TEXT}",
        ID_SOURCE_CMD: "What open source project is this code from. Please only give me the program name and "
                       f"package name:{DECOMP_TEXT}",
    }

    def __init__(self, openai_api_key=None, model="gpt-3.5-turbo"):
        super().__init__()
        self.model = model

        self.menu_commands = {
            "daila_set_key": ("Update OpenAPI Key...", self.ask_api_key),
            f"{self.ID_SOURCE_CMD}": ("Identify the source code", self.find_source_of_function),
            f"{self.SUMMARIZE_CMD}": ("Summarize function", self.summarize_function),
            f"{self.FIND_VULN_CMD}": ("Find vulnerabilities", self.find_vulnerability_in_function),
            f"{self.RENAME_FUNCS_CMD}": ("Rename functions used in function", self.rename_functions_in_function),
            f"{self.RENAME_VARS_CMD}": ("Rename variables in function", self.rename_variables_in_function),
            f"{self.RETYPE_VARS_CMD}": ("Retype variables in function", self.retype_variables_in_function),
        }

        for menu_str, callback_info in self.menu_commands.items():
            callback_str, callback_func = callback_info
            self._register_menu_item(menu_str, callback_str, callback_func)

        self._api_key = os.getenv("OPENAI_API_KEY") or openai_api_key
        openai.api_key = self._api_key

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, data):
        self._api_key = data
        openai.api_key = self._api_key

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
        try:
            response = openai.Completion.create(
                model=model or self.model,
                prompt=question,
                temperature=temperature,
                max_tokens=max_tokens,
                frequency_penalty=frequency_penalty,
                presence_penalty=presence_penalty,
                timeout=60,
                stop=['}']
            )
        except openai.OpenAIError as e:
            raise Exception(f"ChatGPT could not complete the request: {str(e)}")

        answer = None
        try:
            answer = response["choices"][0]["text"]
        except (KeyError, IndexError) as e:
            pass

        return answer

    def _query_openai(self, prompt: str, json_response=False, increase_new_text=True):
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

            try:
                data = json.loads(resp)
            except Exception:
                data = {}

            return data

        return resp

    def query_openai_for_function(
        self, func_addr: int, prompt: str, replace_decompilation=True, json_response=False, increase_new_text=True
    ):
        default_response = {} if json_response else None
        if replace_decompilation:
            decompilation = self._decompile(func_addr)
            if not decompilation:
                return default_response

            prompt = prompt.replace(self.REPLACEMENT_LABEL, decompilation)

        return self._query_openai(prompt, json_response=json_response, increase_new_text=increase_new_text)

    def query_for_cmd(self, cmd, func_addr=None, decompilation=None, edit_dec=False):
        if cmd not in self.COMMANDS_WITH_ARGS:
            raise ValueError(f"Command {cmd} is not supported")

        kwargs = self.COMMANDS_WITH_ARGS[cmd]
        if func_addr is None and decompilation is None:
            raise Exception(f"You must provide either a function address or decompilation!")

        prompt = self.PROMPTS[cmd]
        if decompilation is not None:
            prompt.replace(self.REPLACEMENT_LABEL, decompilation)

        return self.query_openai_for_function(func_addr, prompt, replace_decompilation=decompilation is None, **kwargs)

    #
    # API Alias Wrappers
    #

    @addr_ctx_when_none
    def summarize_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> str:
        resp = self.query_for_cmd(self.SUMMARIZE_CMD, func_addr=func_addr, decompilation=decompilation)
        if edit_dec and resp:
            self._cmt_func(func_addr, resp)

        return resp

    @addr_ctx_when_none
    def find_vulnerability_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> str:
        resp = self.query_for_cmd(self.FIND_VULN_CMD, func_addr=func_addr, decompilation=decompilation)
        if edit_dec and resp:
            self._cmt_func(func_addr, resp)

        return resp

    @addr_ctx_when_none
    def find_source_of_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> str:
        resp = self.query_for_cmd(self.ID_SOURCE_CMD, func_addr=func_addr, decompilation=decompilation)
        if edit_dec and resp:
            self._cmt_func(func_addr, resp)

        return resp

    @addr_ctx_when_none
    def rename_functions_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> dict:
        resp: Dict = self.query_for_cmd(self.RENAME_FUNCS_CMD, func_addr=func_addr, decompilation=decompilation)
        if edit_dec and resp:
            for addr, _ in self.decompiler_controller.functions().items():
                func = self.decompiler_controller.functions(addr)
                if func.name in resp:
                    new_name = resp[func.name]
                    func.name = new_name
                    # TODO change this
                    self.decompiler_controller.fill_function(artifact=func)
        
        return resp

    @addr_ctx_when_none
    def rename_variables_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> dict:
        resp: Dict = self.query_for_cmd(self.RENAME_VARS_CMD, func_addr=func_addr, decompilation=decompilation)
        if edit_dec and resp:
            func = self.decompiler_controller.function(func_addr)
            if func:
                updates = False
                for soff in func.stack_vars:
                    svar = func.stack_vars[soff]
                    if svar.name in resp:
                        new_name = resp[svar.name]
                        svar.name = new_name
                        func.stack_vars[soff] = svar
                        updates = True
                
                if updates:
                    # TODO change this
                    self.decompiler_controller.fill_function(artifact=func)
        
        return resp

    @addr_ctx_when_none
    def retype_variables_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs) -> dict:
        resp: Dict = self.query_for_cmd(self.RETYPE_VARS_CMD, func_addr=func_addr, decompilation=decompilation)
        if edit_dec and resp:
            func = self.decompiler_controller.function(func_addr)
            if func:
                updates = False
                for soff in func.stack_vars:
                    svar = func.stack_vars[soff]
                    if svar.type in resp:
                        new_type = resp[svar.type]
                        svar.type = new_type
                        func.stack_vars[soff] = svar
                        updates = True

                if updates:
                    # TODO change this
                    self.decompiler_controller.fill_function(artifact=func)

        return resp
