import json
import re
from typing import Optional, Union, Dict, Callable
import textwrap

from dailalib.api import AIAPI
from dailalib.api.openai.openai_api import OpenAIAPI

JSON_REGEX = re.compile(r"\{.*}", flags=re.DOTALL)


class Prompt:
    DECOMP_REPLACEMENT_LABEL = "<DECOMPILATION>"
    SNIPPET_REPLACEMENT_LABEL = "<SNIPPET>"
    SNIPPET_TEXT = f"\n\"\"\"{SNIPPET_REPLACEMENT_LABEL}\"\"\""
    DECOMP_TEXT = f"\n\"\"\"{DECOMP_REPLACEMENT_LABEL}\"\"\""

    def __init__(
        self,
        name: str,
        text: str,
        desc: str = None,
        pretext_response: Optional[str] = None,
        posttext_response: Optional[str] = None,
        json_response: bool = False,
        ai_api=None,
        # callback(result, function, ai_api)
        gui_result_callback: Optional[Callable] = None
    ):
        self.name = name
        self.text = textwrap.dedent(text)
        self._pretext_response = pretext_response
        self._posttext_response = posttext_response
        self._json_response = json_response
        self._gui_result_callback = gui_result_callback
        self.desc = desc or name
        self.ai_api: "OpenAIAPI" = ai_api

    def query_model(self, *args, function=None, dec_text=None, use_dec=True, **kwargs):
        if self.ai_api is None:
            raise Exception("api must be set before querying!")

        @AIAPI.requires_function
        def _query_model(ai_api=self.ai_api, function=function, dec_text=dec_text, use_dec=use_dec) -> Union[Dict, str]:
            if not ai_api:
                return {}

            ai_api.info(f"Querying {self.name} prompt with function {function}...")
            response = self._pretext_response if self._pretext_response and not self._json_response else ""
            # grab decompilation and replace it in the prompt, make sure to fix the decompilation for token max
            query_text = self.text.replace(
                self.DECOMP_REPLACEMENT_LABEL,
                OpenAIAPI.fit_decompilation_to_token_max(dec_text)
            )
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
            else:
                response += self._posttext_response if self._pretext_response else ""

            if ai_api.has_decompiler_gui and response:
                self._gui_result_callback(response, function, ai_api)

            ai_api.info(f"Reponse recieved...")
            return response
        return _query_model(ai_api=self.ai_api, function=function, dec_text=dec_text, use_dec=use_dec)

