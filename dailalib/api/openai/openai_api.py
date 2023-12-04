import typing
from typing import Optional
import os

from openai import OpenAI
import tiktoken

from dailalib.api.ai_api import AIAPI
if typing.TYPE_CHECKING:
    from dailalib.api.openai.prompt import Prompt


class OpenAIAPI(AIAPI):
    prompts_by_name = []
    DEFAULT_MODEL = "gpt-4"
    MODEL_TO_TOKENS = {
        "gpt-4": 8000,
        "gpt-3.5-turbo": 4096
    }

    # replacement strings for API calls
    def __init__(self, api_key: Optional[str] = None, model: str = DEFAULT_MODEL, prompts: Optional[list] = None, **kwargs):
        super().__init__(**kwargs)
        self._api_key = None
        self._openai_client: OpenAI = None
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model

        # delay prompt import
        from dailalib.api.openai.prompts import PROMPTS
        prompts = prompts + PROMPTS if prompts else PROMPTS
        self.prompts_by_name = {p.name: p for p in prompts}

    def __dir__(self):
        return list(super().__dir__()) + list(self.prompts_by_name.keys())

    def __getattribute__(self, item):
        if item in object.__getattribute__(self, "prompts_by_name"):
            prompt_obj: "Prompt" = self.prompts_by_name[item]
            prompt_obj.ai_api = self
            return prompt_obj.query_model
        else:
            return object.__getattribute__(self, item)

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, value):
        self._api_key = value
        if self._api_key:
            self._openai_client = OpenAI(api_key=self._api_key)

    def ask_api_key(self, *args, **kwargs):
        self.api_key = self._dec_interface.gui_ask_for_string("Enter you OpenAI API Key:", title="DAILA")

    def query_model(
        self,
        prompt: str,
        model: Optional[str] = None,
        max_tokens=None,
    ):
        if not self._openai_client:
            raise ValueError("You must provide an API key before querying the model.")

        response = self._openai_client.chat.completions.create(
            model=model or self.model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            timeout=60,
        )

        try:
            answer = response.choices[0].message.content
        except (KeyError, IndexError) as e:
            answer = None

        return answer

    @staticmethod
    def estimate_token_amount(content: str, model=DEFAULT_MODEL):
        enc = tiktoken.encoding_for_model(model)
        tokens = enc.encode(content)
        return len(tokens)

    @staticmethod
    def content_fits_tokens(content: str, model=DEFAULT_MODEL):
        max_token_count = OpenAIAPI.MODEL_TO_TOKENS[model]
        token_count = OpenAIAPI.estimate_token_amount(content, model=model)
        return token_count <= max_token_count - 1000

    @staticmethod
    def fit_decompilation_to_token_max(decompilation: str, delta_step=10, model=DEFAULT_MODEL):
        if OpenAIAPI.content_fits_tokens(decompilation, model=model):
            return decompilation

        dec_lines = decompilation.split("\n")
        last_idx = len(dec_lines) - 1
        # should be: [func_prototype] + [nop] + [mid] + [nop] + [end_of_code]
        dec_lines = dec_lines[0:2] + ["// ..."] + dec_lines[delta_step:last_idx-delta_step] + ["// ..."] + dec_lines[-2:-1]
        decompilation = "\n".join(dec_lines)

        return OpenAIAPI.fit_decompilation_to_token_max(decompilation, delta_step=delta_step, model=model)