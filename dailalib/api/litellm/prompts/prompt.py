import json
import re
from typing import Optional, Union, Dict, Callable
import textwrap

from ...ai_api import AIAPI
from ..litellm_api import LiteLLMAIAPI
from .prompt_type import PromptType

from libbs.artifacts import Comment
from jinja2 import Template, StrictUndefined

JSON_REGEX = re.compile(r"\{.*}", flags=re.DOTALL)


class Prompt:
    DECOMP_REPLACEMENT_LABEL = "<DECOMPILATION>"
    SNIPPET_REPLACEMENT_LABEL = "<SNIPPET>"
    SNIPPET_TEXT = f"\n\"\"\"{SNIPPET_REPLACEMENT_LABEL}\"\"\""
    DECOMP_TEXT = f"\n\"\"\"{DECOMP_REPLACEMENT_LABEL}\"\"\""

    def __init__(
        self,
        name: str,
        template_text: str,
        desc: str = None,
        pretext_response: Optional[str] = None,
        posttext_response: Optional[str] = None,
        json_response: bool = True,
        response_key: str = None,
        ai_api=None,
        # callback(result, function, ai_api)
        gui_result_callback: Optional[Callable] = None
    ):
        self.name = name
        self.template = Template(textwrap.dedent(template_text), undefined=StrictUndefined)
        self._pretext_response = pretext_response
        self._posttext_response = posttext_response
        self._json_response = json_response
        self._response_key = response_key
        self._gui_result_callback = gui_result_callback
        self.desc = desc or name
        self.ai_api: "LiteLLMAIAPI" = ai_api

    def query_model(self, *args, function=None, dec_text=None, use_dec=True, **kwargs):
        if self.ai_api is None:
            raise Exception("api must be set before querying!")

        @AIAPI.requires_function
        def _query_model(ai_api=self.ai_api, function=function, dec_text=dec_text, **_kwargs) -> Union[Dict, str]:
            if not ai_api:
                return {}

            ai_api.info(f"Querying {self.name} prompt with function {function}...")
            response = self._pretext_response if self._pretext_response and not self._json_response else ""
            # grab decompilation and replace it in the prompt, make sure to fix the decompilation for token max
            query_text = self.template.render(
                decompilation=LiteLLMAIAPI.fit_decompilation_to_token_max(dec_text),
                few_shot=bool(self.ai_api.prompt_style == PromptType.FEW_SHOT),
            )
            #ai_api.debug(f"Prompting using model: {self.ai_api.model}...")
            #ai_api.debug(f"Prompting with style: {self.ai_api.prompt_style}...")
            #ai_api.debug(f"Prompting with: {query_text}")

            ai_api.on_query(self.name, self.ai_api.model, self.ai_api.prompt_style, function, dec_text)
            response += self.ai_api.query_model(query_text)
            default_response = {} if self._json_response else ""
            if not response:
                return default_response

            # changes response type to a dict
            if self._json_response:
                # if the response of OpenAI gets cut off, we have an incomplete JSON
                if "}" not in response:
                    response += "}"

                json_matches = JSON_REGEX.findall(response)
                if not json_matches:
                    return default_response

                json_data = json_matches[0]
                try:
                    response = json.loads(json_data)
                except Exception:
                    response = {}

                if self._response_key is not None:
                    response = response.get(self._response_key, "")
            else:
                response += self._posttext_response if self._pretext_response else ""

            if isinstance(response, dict) or isinstance(response, str):
                resp_len = len(response)
                if resp_len:
                    ai_api.info(f"Response of len={resp_len} received from AI...")
                else:
                    ai_api.warning(f"Response recieved from AI, but it was empty! AI failed to answer.")
            else:
                ai_api.info("Reponse received from AI!")

            if ai_api.has_decompiler_gui and response:
                ai_api.info("Updating the decompiler with the AI response...")
                self._gui_result_callback(response, function, ai_api)

            return response
        return _query_model(ai_api=self.ai_api, function=function, dec_text=dec_text, use_dec=use_dec)

    @staticmethod
    def rename_function(result, function, ai_api: "AIAPI"):
        new_name = list(result.values())[0]
        function.name = new_name
        ai_api._dec_interface.functions[function.addr] = function

    @staticmethod
    def rename_variables(result, function, ai_api: "AIAPI"):
        ai_api._dec_interface.rename_local_variables_by_names(function, result)

    @staticmethod
    def comment_function(result, function, ai_api: "AIAPI"):
        ai_api._dec_interface.comments[function.addr] = Comment(function.addr, comment=result, func_addr=function.addr)
