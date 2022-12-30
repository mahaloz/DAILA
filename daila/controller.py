import re
from typing import Optional, Dict
import os
import textwrap

import openai

LINK_REGEX = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"""


class DAILAController:
    def __init__(self, openai_api_key=None):
        self.daila_ops = {
            "daila:get_key": ("Update OpenAPI Key...", self.ask_api_key),
            "daila:identify_func": ("Identify the source of the current function", self.identify_current_function),
            "daila:explain_func": ("Explain what the current function does", self.explain_current_function),
            "daila:find_vuln_func": ("Find the vuln in the current function", self.find_vuln_current_function)
        }
        for menu_str, callback_info in self.daila_ops.items():
            callback_str, callback_func = callback_info
            self._register_menu_item(menu_str, callback_str, callback_func)

        self._api_key = os.getenv("OPENAI_API_KEY") or openai_api_key
        openai.api_key = self._api_key

    #
    # decompiler interface
    #

    def _cmt_func(self, func_addr: int, comment: str, **kwargs):
        return False

    def _decompile(self, func_addr: int, **kwargs):
        return False

    def _current_function_addr(self, **kwargs):
        return None

    def _register_menu_item(self, name, action_string, callback_func):
        return False

    #
    # gpt interface
    #

    def ask_api_key(self):
        pass

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, data):
        self._api_key = data
        openai.api_key = self._api_key

    def _ask_gpt(self, question: str, model="text-davinci-003", temperature=0.0, max_tokens=64, frequency_penalty=0,
                 presence_penalty=0):
        try:
            response = openai.Completion.create(
                model=model,
                prompt=question,
                temperature=temperature,
                max_tokens=max_tokens,
                top_p=1,
                frequency_penalty=frequency_penalty,
                presence_penalty=presence_penalty,
                timeout=60,
                stop=['"""']
            )
        except openai.OpenAIError as e:
            raise Exception(f"ChatGPT could not complete the request: {str(e)}")

        answer = None
        try:
            answer = response["choices"][0]["text"]
        except (KeyError, IndexError) as e:
            pass

        return answer

    #
    # identification public api
    #

    def explain_current_function(self, *args, **kwargs):
        func_addr = self._current_function_addr(**kwargs)
        if func_addr is None:
            return False

        success, explaination = self.explain_decompilation(func_addr, **kwargs)
        if not success or explaination is None:
            return False

        return self._cmt_func(func_addr, explaination, **kwargs)

    def explain_decompilation(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        response: Optional[str] = self._ask_gpt(
            f'{dec}'
            '"""'
            'Here is what the above source code is doing:\n',
            model="code-davinci-002",
            max_tokens=64
        )

        if response is None:
            return False, None

        id_str = f"""\
        DAILA EXPLANATION:
        {response}
        """
        return True, textwrap.dedent(id_str)

    def identify_current_function(self, *args, **kwargs):
        func_addr = self._current_function_addr(**kwargs)
        if func_addr is None:
            return False

        success, id_str = self.identify_decompilation(func_addr, **kwargs)
        if not success or id_str is None:
            return False

        return self._cmt_func(func_addr, id_str, **kwargs)

    def identify_decompilation(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        response: Optional[str] = self._ask_gpt(
            'What open source project is this code from. Please only give me the program name and package name:\n'
            f'{dec}'
            '"""',
            temperature=0.6,
            max_tokens=500
        )

        if response is None:
            return False, None

        # reduce the output text
        from_str = response.split("from")[-1].strip()

        # attempt a link lookup
        link_response: Optional[str] = self._ask_gpt(
            f"Where can I find {from_str}?"
        )
        if link_response is None:
            return True, from_str

        links = re.findall(LINK_REGEX, link_response)
        id_str = f"""\
        DAILA IDENTIFICATION:
        {from_str}
        
        Links: {links}
        """
        return True, textwrap.dedent(id_str)

    def find_vuln_decompilation(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        response: Optional[str] = self._ask_gpt(
            'Can you find the vulnerabilty in the following function and suggest the possible way to exploit it?\n'
            f'{dec}'
            '"""',
            temperature=0.6,
            max_tokens=2500,
            frequency_penalty=1,
            presence_penalty=1
        )

        if response is None:
            return False, None

        output = f"""\
        DAILA FIND-VULN:
        {response}
        """
        return True, textwrap.dedent(output)

    def find_vuln_current_function(self, *args, **kwargs):
        func_addr = self._current_function_addr(**kwargs)
        if func_addr is None:
            return False

        success, output = self.find_vuln_decompilation(func_addr, **kwargs)
        if not success or output is None:
            return False

        return self._cmt_func(func_addr, output, **kwargs)
