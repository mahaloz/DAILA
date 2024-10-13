import json
import re
from typing import Optional, Union, Dict, Callable
import textwrap

from ...ai_api import AIAPI
from ..litellm_api import LiteLLMAIAPI
from .prompt_type import PromptType

from libbs.artifacts import Comment, Function, Context
from jinja2 import Template, StrictUndefined

JSON_REGEX = re.compile(r"\{.*?}", flags=re.DOTALL)


class Prompt:
    def __init__(
        self,
        name: str,
        template_name: str,
        desc: str = None,
        pretext_response: Optional[str] = None,
        posttext_response: Optional[str] = None,
        json_response: bool = True,
        response_key: str = None,
        number_lines: bool = False,
        ai_api=None,
        # callback(result, function, ai_api)
        gui_result_callback: Optional[Callable] = None
    ):
        self.name = name
        self.template_name = template_name
        self.last_rendered_template = None
        self._pretext_response = pretext_response
        self._posttext_response = posttext_response
        self._json_response = json_response
        self._response_key = response_key
        self._gui_result_callback = gui_result_callback
        self._number_lines = number_lines
        self.desc = desc or name
        self.ai_api: LiteLLMAIAPI = ai_api

    def __str__(self):
        return f"<Prompt {self.name}>"

    def __repr__(self):
        return self.__str__()

    def _load_template(self, prompt_style: PromptType) -> Template:
        from . import get_prompt_template
        template_text = get_prompt_template(self.template_name, prompt_style)
        if template_text is None:
            raise ValueError(f"Prompt template {self.template_name} not supported in {prompt_style} style!")

        return Template(textwrap.dedent(template_text), undefined=StrictUndefined)

    def query_model(self, *args, context=None, function=None, dec_text=None, use_dec=True, **kwargs):
        if self.ai_api is None:
            raise Exception("api must be set before querying!")

        @AIAPI.requires_function
        def _query_model(ai_api=self.ai_api, function=function, dec_text=dec_text, **_kwargs) -> Union[Dict, str]:
            if not ai_api:
                return {}

            ai_api.info(f"Querying {self.name} prompt with function {function}...")
            # construct the intial template
            response = self._pretext_response if self._pretext_response and not self._json_response else ""
            template = self._load_template(self.ai_api.prompt_style)

            # grab decompilation and replace it in the prompt, make sure to fix the decompilation for token max
            line_text = ""
            if context and context.line_number is not None:
                line_text = dec_text.split("\n")[context.line_number]

            query_text = template.render(
                # decompilation lines of the target function
                decompilation=LiteLLMAIAPI.fit_decompilation_to_token_max(dec_text)
                if self.ai_api.fit_to_tokens else dec_text,
                # line text for emphasis
                line_text=line_text,
                # prompting style (engineering technique)
                few_shot=bool(self.ai_api.prompt_style == PromptType.FEW_SHOT),
            )
            self.last_rendered_template = query_text
            #ai_api.info(f"Prompting using model: {self.ai_api.model}...")
            #ai_api.info(f"Prompting with style: {self.ai_api.prompt_style}...")
            #ai_api.info(f"Prompting with: {query_text}")

            ai_api.on_query(self.name, self.ai_api.model, self.ai_api.prompt_style, function, dec_text)
            response += self.ai_api.query_model(query_text)
            #ai_api.info(f"Response received from AI: {response}")
            default_response = {} if self._json_response else ""
            if not response:
                ai_api.warning(f"Response received from AI was empty! AI failed to answer.")
                return default_response

            # changes response type to a dict
            if self._json_response:
                # if the response of OpenAI gets cut off, we have an incomplete JSON
                if "}" not in response:
                    response += "}"

                json_matches = JSON_REGEX.findall(response)
                if not json_matches:
                    return default_response

                json_data = json_matches[-1]
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
                ai_api.info("Response received from AI!")

            if ai_api.has_decompiler_gui and response:
                ai_api.info("Updating the decompiler with the AI response...")
                self._gui_result_callback(response, function, ai_api, context=context)

            return response

        return _query_model(
            ai_api=self.ai_api, function=function, dec_text=dec_text, use_dec=use_dec, number_lines=self._number_lines,
            context=context
        )

    @staticmethod
    def rename_function(result, function, ai_api: "AIAPI", **kwargs):
        if function.name in result:
            new_name = result[function.name]
        else:
            new_name = list(result.values())[0]

        new_func = Function(name=new_name, addr=function.addr)
        ai_api._dec_interface.functions[function.addr] = new_func

    @staticmethod
    def rename_variables(result, function, ai_api: "AIAPI", **kwargs):
        new_func: Function = function.copy()
        # clear out changes that are not for variables
        new_func.name = None
        new_func.type = None
        ai_api._dec_interface.rename_local_variables_by_names(function, result)

    @staticmethod
    def comment_function(result, function, ai_api: "AIAPI", **kwargs):
        curr_cmt_obj = ai_api._dec_interface.comments.get(function.addr, None)
        curr_cmt = curr_cmt_obj.comment + "\n" if curr_cmt_obj is not None else ""

        ai_api._dec_interface.comments[function.addr] = Comment(
            addr=function.addr,
            comment=curr_cmt + result,
            func_addr=function.addr
        )

    @staticmethod
    def comment_vulnerability(result, function, ai_api: "AIAPI", **kwargs):
        rendered = ""
        if "vulnerabilities" in result and "description" in result:
            rendered += "Vulnerabilities:\n"
            for vuln in result["vulnerabilities"]:
                rendered += f"- {vuln}\n"

            rendered += "\nVuln Analysis:\n"
            rendered += result["description"]
        elif isinstance(result, dict):
            for key, value in result.items():
                rendered += f"{key}: {value}\n"
        else:
            rendered = str(result)

        bs_cmt = Comment(
            addr=function.addr,
            comment=rendered,
            func_addr=function.addr
        )
        bs_cmt_lines = len(Comment.linewrap_comment(bs_cmt.comment).splitlines())

        # adjust the lines specified in the comment
        #
        # find all the line numbers in the comment of form 'lines 23-24' or '-23' or '23-'
        nums = set(re.findall("lines (\d+)", rendered)) | set(re.findall("-(\d+)", rendered)) | \
            set(re.findall("(\d+)-", rendered))
        # replace the largest digit numbers first
        sorted_nums = sorted(nums, key=lambda x: int(x), reverse=True)
        for num in sorted_nums:
            _n = int(num, 0)
            new_num = str(_n + bs_cmt_lines - 2)
            rendered = rendered.replace(num, new_num)

        ai_api._dec_interface.comments[function.addr] = Comment(
            addr=function.addr,
            comment=rendered,
            func_addr=function.addr
        )

    @staticmethod
    def comment_man_page(result, function, ai_api: "AIAPI", context=None, **kwargs):
        rendered = "\n"
        if "function" in result and "args" in result and "return" in result and "description" in result:
            rendered += f"Man Page for {result['function']}:\n"
            rendered += f"Args: {', '.join(result['args'])}\n"
            rendered += f"Return: {result['return']}\n"
            rendered += f"Description: {result['description']}\n"
        elif isinstance(result, dict):
            for key, value in result.items():
                rendered += f"{key}: {value}\n"
        else:
            rendered = str(result)

        addr = context.addr if isinstance(context, Context) and context.addr is not None else function.addr
        ai_api._dec_interface.comments[addr] = Comment(
            addr=addr,
            comment=rendered,
            func_addr=function.addr,
            decompiled=True
        )
