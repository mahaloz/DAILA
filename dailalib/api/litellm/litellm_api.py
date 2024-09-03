import typing
from typing import Optional
import os

import tiktoken

from ..ai_api import AIAPI

class LiteLLMAIAPI(AIAPI):
    prompts_by_name = []
    DEFAULT_MODEL = "gpt-4o"
    MODEL_TO_TOKENS = {
        "gpt-4-turbo": 128_000,
        "gpt-4": 8_000,
        "gpt-4o": 8_000,
        "gpt-3.5-turbo": 4_096,
        "claude-2": 200_000,
        "gemini/gemini-pro": 12_288,
        "vertex_ai_beta/gemini-pro": 12_288,
    }

    # replacement strings for API calls
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        prompts: Optional[list] = None,
        fit_to_tokens: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)
        self._api_key = None
        # default to openai api key if not provided
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.fit_to_tokens = fit_to_tokens

        # delay prompt import
        from .prompts import PROMPTS, DEFAULT_STYLE
        self.prompt_style = DEFAULT_STYLE
        prompts = prompts + PROMPTS if prompts else PROMPTS
        self.prompts_by_name = {p.name: p for p in prompts}

    def __dir__(self):
        return list(super().__dir__()) + list(self.prompts_by_name.keys())

    def __getattribute__(self, item):
        # this is how we can access the prompt functions
        if item in object.__getattribute__(self, "prompts_by_name"):
            prompt_obj: "Prompt" = self.prompts_by_name[item]
            prompt_obj.ai_api = self
            return prompt_obj.query_model
        else:
            return object.__getattribute__(self, item)

    def query_model(
        self,
        prompt: str,
        model: Optional[str] = None,
        max_tokens=None,
    ):
        # delay import because litellm attempts to query the server on import to collect cost information.
        from litellm import completion

        if not self.api_key:
            raise ValueError(f"Model API key is not set. Please set it before querying the model {self.model}")

        response = completion(
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
        # TODO: we only support one token counting for now, gpt-4
        enc = tiktoken.encoding_for_model("gpt-4")
        tokens = enc.encode(content)
        return len(tokens)

    @staticmethod
    def content_fits_tokens(content: str, model=DEFAULT_MODEL):
        max_token_count = LiteLLMAIAPI.MODEL_TO_TOKENS[model]
        token_count = LiteLLMAIAPI.estimate_token_amount(content, model=model)
        return token_count <= max_token_count - 1000

    @staticmethod
    def fit_decompilation_to_token_max(decompilation: str, delta_step=10, model=DEFAULT_MODEL):
        if LiteLLMAIAPI.content_fits_tokens(decompilation, model=model):
            return decompilation

        dec_lines = decompilation.split("\n")
        last_idx = len(dec_lines) - 1
        # should be: [func_prototype] + [nop] + [mid] + [nop] + [end_of_code]
        dec_lines = dec_lines[0:2] + ["// ..."] + dec_lines[delta_step:last_idx-delta_step] + ["// ..."] + dec_lines[-2:-1]
        decompilation = "\n".join(dec_lines)

        return LiteLLMAIAPI.fit_decompilation_to_token_max(decompilation, delta_step=delta_step, model=model)

    #
    # LMM Settings
    #

    @property
    def api_key(self):
        if not self._api_key:
            return None
        elif "gpt" in self.model:
            return os.getenv("OPENAI_API_KEY", None)
        elif "claude" in self.model:
            return os.getenv("ANTHROPIC_API_KEY", None)
        elif "gemini/gemini" in self.model:
            return os.getenv("GEMINI_API_KEY", None)
        elif "vertex" in self.model:
            return self._api_key
        else:
            return None

    @api_key.setter
    def api_key(self, value):
        self._api_key = value
        if self._api_key:
            if "gpt" in self.model:
                os.environ["OPENAI_API_KEY"] = self._api_key
            elif "claude" in self.model:
                os.environ["ANTHROPIC_API_KEY"] = self._api_key
            elif "gemini/gemini" in self.model:
                os.environ["GEMINI_API_KEY"] = self._api_key

    def ask_api_key(self, *args, **kwargs):
        api_key_or_path = self._dec_interface.gui_ask_for_string("Enter you AI API Key or Creds Path:", title="DAILA")
        if "/" in api_key_or_path or "\\" in api_key_or_path:
            # treat as path
            with open(api_key_or_path, "r") as f:
                api_key = f.read().strip()
        else:
            api_key = api_key_or_path
        self.api_key = api_key

    def ask_prompt_style(self):
        if self._dec_interface is not None:
            from .prompts import ALL_STYLES

            prompt_style = self.prompt_style
            style_choices = ALL_STYLES.copy()
            style_choices.remove(self.prompt_style)
            style_choices = [self.prompt_style] + style_choices

            p_style = self._dec_interface.gui_ask_for_choice(
                "What prompting style would you like to use?",
                style_choices,
                title="DAILA"
            )
            if p_style != prompt_style and p_style is not None:
                self.prompt_style = p_style
                self._dec_interface.info(f"Prompt style set to {p_style}")

    def ask_model(self):
        if self._dec_interface is not None:
            model_choices = list(LiteLLMAIAPI.MODEL_TO_TOKENS.keys())
            model_choices.remove(self.model)
            model_choices = [self.model] + model_choices

            model = self._dec_interface.gui_ask_for_choice(
                "What LLM model would you like to use?",
                model_choices,
                title="DAILA"
            )
            self.model = model
            self._dec_interface.info(f"Model set to {model}")
