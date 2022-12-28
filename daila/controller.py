import re
from typing import Optional
import os
import textwrap

import openai

LINK_REGEX = r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))"""


class DAILAController:
    def __init__(self, openai_api_key=None):
        openai.api_key = os.getenv("OPENAI_API_KEY") or openai_api_key

    #
    # decompiler interface
    #

    def _cmt_func(self, func_addr: int, comment: str, **kwargs):
        return False

    def _decompile(self, func_addr: int, **kwargs):
        return False

    def _current_function_addr(self, **kwargs):
        return None

    #
    # gpt interface
    #

    def _ask_gpt(self, question: str, model: str, temperature=0, max_tokens=64, frequency_penalty=0, presence_penalty=0):
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
                stop=["\"\"\""]
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

    def id_current_function(self, option, **kwargs):
        func_addr = self._current_function_addr(**kwargs)
        if func_addr is None:
            return False
            
        # TODO: On window menu
        option = 1
        
        if option == 1:
            success, id_str = self.identify_decompilation(func_addr, **kwargs)
	
        elif option == 2:
            success, id_str = self.explain_decompilation(func_addr, **kwargs)
	
        elif option == 3:
            success, id_str = self.find_vuln_decompilation(func_addr, **kwargs)
	
        if not success or id_str is None:
            return False

        return self._cmt_func(func_addr, id_str, **kwargs)

    def identify_decompilation(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        question = "What open source project is this code from. Please only give me the program name and package name:\n" \
                 f'"{dec}"' \
                   "\"\"\""
                   
        model = "text-davinci-003"
        response: Optional[str] = self._ask_gpt(question, model, 0.6, 500, 1, 1)

        if response is None:
            return False, None

        # reduce the output text
        from_str = response.split("from")[-1].strip()

        # attempt a link lookup
        question = f"Where can I find {from_str}?"
        link_response: Optional[str] = self._ask_gpt(question, model, 0.6, 500, 1, 1)

        if link_response is None:
            return True, from_str

        links = re.findall(LINK_REGEX, link_response)
        id_str = f"""\
        DAILA IDENTIFICATION:
        {from_str}
        
        Links: {links}
        """
        return True, textwrap.dedent(id_str)
        
    def explain_decompilation(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        question = f'"{dec}"' \
                     "\"\"\"" \
                     "Here's what the above source code is doing:\n"
                   
        model = "code-davinci-002"
        response: Optional[str] = self._ask_gpt(question, model, max_tokens=64)

        if response is None:
            return False, None

        id_str = f"""\
        DAILA EXPLANATION:
        {response}
        """
        return True, textwrap.dedent(id_str)
        
    def find_vuln_decompilation(self, func_addr, dec=None, **kwargs):
        dec = dec or self._decompile(func_addr, **kwargs)
        if not dec:
            return False, None

        question = "Can you find the vulnerabilty in the following function and suggest the possible way to exploit it?\n" \
                 f'"{dec}"' \
                   "\"\"\""

        model = "text-davinci-003"
        response: Optional[str] = self._ask_gpt(question, model, 0.6, 2500, 1, 1)

        if response is None:
            return False, None

        id_str = f"""\
        DAILA FIND VULN:
        {response}
        """
        return True, textwrap.dedent(id_str)
