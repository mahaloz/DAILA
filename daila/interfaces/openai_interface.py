import re
from typing import Optional, Dict
import os
import textwrap
import json

import openai
from binsync.data import (
    Function
)


from .generic_ai_interface import GenericAIInterface
from ..utils import HYPERLINK_REGEX


class OpenAIInterface(GenericAIInterface):
    # API Command Constants
    SUMMARIZE_CMD = "daila_summarize"
    RENAME_FUNCS_CMD = "daial_rename_funcs"
    RENAME_VARS_CMD = "daila_rename_vars"
    RETYPE_VARS_CMD = "daila_retype_vars"
    FIND_VULN_CMD = "daila_find_vuln"
    ID_SOURCE_CMD = "daila_id_source"

    # Replacement strings for API calls
    REPLACEMENT_LABEL = "<DECOMPILATION>"
    DECOMP_TEXT = f"\n\"\"\"{REPLACEMENT_LABEL}\"\"\""

    # Commands:
    COMMANDS = {
        SUMMARIZE_CMD: {},
        RENAME_VARS_CMD: {"json_response": True},
        RENAME_FUNCS_CMD: {"json_response": True},
        RETYPE_VARS_CMD: {"json_response": True},
        FIND_VULN_CMD: {},
        ID_SOURCE_CMD: {"increase_new_text": False}
    }

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
        self.menu_operations = {
            "daila:get_key": ("Update OpenAPI Key...", self.ask_api_key),
            "daila:identify_func": ("Identify the source of the current function", self.identify_current_function),
            "daila:explain_func": ("Explain what the current function does", self.explain_current_function),
            "daila:find_vuln_func": ("Find the vuln in the current function", self.find_vuln_current_function),
            "daila:rename_vars": ("Rename variables to better names", self.rename_variables_current_function),
        }
        for menu_str, callback_info in self.menu_operations.items():
            callback_str, callback_func = callback_info
            self._register_menu_item(menu_str, callback_str, callback_func)

        self._api_key = os.getenv("OPENAI_API_KEY") or openai_api_key
        openai.api_key = self._api_key

    #
    # OpenAI Interface
    #

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, data):
        self._api_key = data
        openai.api_key = self._api_key

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

    def query_for_cmd(self, cmd, func_addr=None, decompilation=None):
        if cmd not in self.COMMANDS:
            raise ValueError(f"Command {cmd} is not supported")

        kwargs = self.COMMANDS[cmd]
        if func_addr is None and decompilation is None:
            raise Exception(f"You must provide either a function address or decompilation!")

        prompt = self.PROMPTS[cmd]
        if decompilation is not None:
            prompt.replace(self.REPLACEMENT_LABEL, decompilation)

        return self.query_openai_for_function(func_addr, prompt, replace_decompilation=decompilation is None, **kwargs)

    #
    # API Alias Wrappers
    #

    def summarize_function(self, func_addr=None, decompilation=None) -> str:
        return self.query_for_cmd(self.SUMMARIZE_CMD, func_addr=func_addr, decompilation=decompilation)

    def find_vulnerability_in_function(self, func_addr=None, decompilation=None) -> str:
        return self.query_for_cmd(self.FIND_VULN_CMD, func_addr=func_addr, decompilation=decompilation)

    def find_source_of_in_function(self, func_addr=None, decompilation=None) -> str:
        return self.query_for_cmd(self.ID_SOURCE_CMD, func_addr=func_addr, decompilation=decompilation)

    def rename_functions_in_function(self, func_addr=None, decompilation=None) -> dict:
        return self.query_for_cmd(self.RENAME_FUNCS_CMD, func_addr=func_addr, decompilation=decompilation)

    def rename_variables_in_function(self, func_addr=None, decompilation=None) -> dict:
        return self.query_for_cmd(self.RENAME_VARS_CMD, func_addr=func_addr, decompilation=decompilation)

    def retype_variables_in_function(self, func_addr=None, decompilation=None) -> dict:
        return self.query_for_cmd(self.RETYPE_VARS_CMD, func_addr=func_addr, decompilation=decompilation)

    #
    # API In-Place editors
    #

    def rename_variables(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        response: Optional[str] = self._ask_openai(
            'Analyze what the following function does. Suggest better variable names and its own function name. Do not suggest names for inside functions. Reply whit a JSON array where keys are the original names and values are the propossed names:\n'
            f'{dec}'
            '"""',
            temperature=0.6,
            max_tokens=512,
            frequency_penalty=1,
            presence_penalty=1
        )

        if response is None:
            return False, None

        # patch the output, since it can be weird sometimes
        if "}" not in response:
            response += "}"

        try:
            var_map = json.loads(response)
        except Exception:
            var_map = None

        update = False
        if isinstance(var_map, dict):
            update = self._rename_variables_by_name(func_addr, var_map)

        return update

    def rename_variables_current_function(self, *args, **kwargs):
        func_addr = self._current_function_addr(**kwargs)
        if func_addr is None:
            return False

        success = self.rename_variables(func_addr, **kwargs)
        return success
