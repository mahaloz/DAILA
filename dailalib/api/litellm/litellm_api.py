from typing import Optional
import os

import tiktoken

from ..ai_api import AIAPI
from .configuration import DAILAConfig
from .config_dialog import DAILAConfigDialog

active_model = None
active_prompt_style = None

import logging 
_l = logging.getLogger(__name__)

class LiteLLMAIAPI(AIAPI):
    prompts_by_name = []
    DEFAULT_MODEL = "gpt-4o"
    OPENAI_MODELS = {"gpt-4", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo", "o1-mini", "o1-preview"}
    # TODO: How can I get this MODEL_TO_TOKENS in the future, without hardcopy to `configuration`
    MODEL_TO_TOKENS = {
        # TODO: update the token values for o1
        "o1-mini": 8_000,
        "o1-preview": 8_000,
        "gpt-4o": 8_000,
        "gpt-4o-mini": 16_000,
        "gpt-4-turbo": 128_000,
        "claude-3-5-sonnet-20240620": 200_000,
        "gemini/gemini-pro": 12_288,
        "vertex_ai_beta/gemini-pro": 12_288,
        # perplex is on legacy mode :( 
        "perplexity/llama-3.1-sonar-small-128k-online": 127_072,
        "perplexity/llama-3.1-sonar-medium-128k-online": 127_072,
        "perplexity/llama-3.1-sonar-large-128k-online": 127_072,
        "sonar-pro": 127_072,
        "sonar": 127_072,
    }

    def load_config(self):
        self.config.load()
        self.model = self.config.model
        self.api_key = self.config.api_key
        self.prompt_style = self.config.prompt_style
        self.custom_endpoint = self.config.custom_endpoint
        self.custom_model = self.config.custom_model
        # update the globals (for threading hacks)
        self._set_model(self.model)
        self._set_prompt_style(self.prompt_style)

    @property
    def api_key(self):
        # if this key is load from config, just skip the next steps 
        if self.is_load_from_config:
            return self._api_key
        
        if not self._api_key or self.model is None:
            return None
        elif self.model in self.OPENAI_MODELS:
            return os.getenv("OPENAI_API_KEY", None)
        elif "claude" in self.model:
            return os.getenv("ANTHROPIC_API_KEY", None)
        elif "gemini/gemini" in self.model:
            return os.getenv("GEMINI_API_KEY", None)
        elif "sonar" in self.model or "perplexity" in self.model:
            return os.getenv("PERPLEXITY_API_KEY", None)
        elif "vertex" in self.model:
            return self._api_key
        else:
            return None

    @api_key.setter
    def api_key(self, value):
        self._api_key = value
        _l.info(f"API key set to {self.model}")
        if self._api_key and self.model is not None:
            if self.model in self.OPENAI_MODELS:
                os.environ["OPENAI_API_KEY"] = self._api_key
            elif "claude" in self.model:
                os.environ["ANTHROPIC_API_KEY"] = self._api_key
            elif "gemini/gemini" in self.model:
                os.environ["GEMINI_API_KEY"] = self._api_key
            elif "sonar" in self.model or "perplexity" in self.model:
                os.environ["PERPLEXITY_API_KEY"] = self._api_key
            elif "vertex" in self.model:
                os.environ["VERTEX_API_KEY"] = self._api_key
            else:
                _l.error(f"API key not set for model {self.model}")

    @property
    def custom_model(self):
        return self._custom_model

    @custom_model.setter 
    def custom_model(self, value):
        custom_model = value
        if not custom_model.strip():
            self._custom_model = None
            _l.info(f"Custom model selection cleared, or not in use")
            return
        self._custom_model = "openai/" + custom_model.strip()
        _l.info(f"Custom model set to {self._custom_model}")

    @property
    def custom_endpoint(self):
        return self._custom_endpoint
    
    @custom_endpoint.setter
    def custom_endpoint(self, value):
        custom_endpoint = value
        if not custom_endpoint.strip():
            self._custom_endpoint = None
            _l.info(f"Custom endpoint disabled, defaulting to online API")
            return
        if not (custom_endpoint.lower().startswith("http://") or custom_endpoint.lower().startswith("https://")):
            self._custom_endpoint = None
            _l.error("Invalid endpoint format")
            return
        self._custom_endpoint = custom_endpoint.strip()
        _l.info(f"Custom endpoint set to {self._custom_endpoint}")

    # replacement strings for API calls
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        prompt_style: str = "few-shot",
        prompts: Optional[list] = None,
        fit_to_tokens: bool = False,
        chat_use_ctx: bool = True,
        chat_event_callbacks: Optional[dict] = None,
        custom_endpoint: Optional[str] = None,
        custom_model: Optional[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        
        self.config = DAILAConfig()

        self.is_load_from_config = False 
        
        # Check if the config file exists. Preferably load the config file 
        if self.config.save_location.exists():
            self.is_load_from_config = True 
            self.load_config()
        else: 
            # default values 
            self._api_key = None
            # default to openai api key if not provided
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
            self.model = model
            self.prompt_style = prompt_style
            self.fit_to_tokens = fit_to_tokens
            self.chat_use_ctx = chat_use_ctx
            self.chat_event_callbacks = chat_event_callbacks or {"send": None, "receive": None}
            self.custom_endpoint = custom_endpoint
            self.custom_model = custom_model

        self.fit_to_tokens = fit_to_tokens
        self.chat_use_ctx = chat_use_ctx
        self.chat_event_callbacks = chat_event_callbacks or {"send": None, "receive": None}

        # delay prompt import
        from .prompts import PROMPTS
        prompts = prompts + PROMPTS if prompts else PROMPTS
        self.prompts_by_name = {p.name: p for p in prompts}

        # update the globals (for threading hacks)
        global active_model, active_prompt_style
        active_model = self.model
        active_prompt_style = self.prompt_style

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

        if not self.api_key and not self.custom_endpoint:
            raise ValueError(f"Model API key is not set. Please set it before querying the model {self.model}")

        prompt_model = (model or self.model) if not self.custom_endpoint else self.custom_model
        response = completion(
            model=prompt_model,
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            timeout=60 if not self.custom_endpoint else 300,
            api_base=self.custom_endpoint if self.custom_endpoint else None,  # Use custom endpoint if set
            api_key=self.api_key if not self.custom_endpoint else "dummy" # In most of cases custom endpoint doesn't need the api_key
        )
        # get the answer
        try:
            answer = response.choices[0].message.content
            if self.custom_endpoint: print(answer)
        except (KeyError, IndexError) as e:
            answer = None

        if self.custom_endpoint:
            return answer, 0

        # get the estimated cost
        try:
            prompt_tokens = response.usage.prompt_tokens
            completion_tokens = response.usage.completion_tokens
        except (KeyError, IndexError) as e:
            prompt_tokens, completion_tokens = None, None
        cost = self.llm_cost(prompt_model, prompt_tokens, completion_tokens) \
            if prompt_tokens is not None and completion_tokens is not None else None

        return answer, cost

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

    @staticmethod
    def llm_cost(model_name: str, prompt_tokens: int, completion_tokens: int) -> float | None:
        # these are the $ per million tokens
        COST = {
            "gpt-4o": {"prompt_price": 2.5, "completion_price": 10},
            "gpt-4o-mini": {"prompt_price": 0.150, "completion_price": 0.600},
            "gpt-4-turbo": {"prompt_price": 10, "completion_price": 30},
            "claude-3.5-sonnet-20240620": {"prompt_price": 3, "completion_price": 15},
            "gemini/gemini-pro": {"prompt_price": 0.150, "completion_price": 0.600},
            "vertex_ai_beta/gemini-pro": {"prompt_price": 0.150, "completion_price": 0.600},
            # perplex is on legacy mode not available from 02/22/25:(
            "perplexity/llama-3.1-sonar-small-128k-online": {"prompt_price": 0.150, "completion_price": 0.600},
            "perplexity/llama-3.1-sonar-large-128k-online": {"prompt_price": 0.150, "completion_price": 0.600},
            "perplexity/llama-3.1-sonar-huge-128k-online": {"prompt_price": 0.150, "completion_price": 0.600},
            # introduced the new sonar-pro/sonar 
            "sonar": {"prompt_price": 0.150, "completion_price": 0.600},
            "sonar-pro": {"prompt_price": 0.150, "completion_price": 0.600},
        }
        if model_name not in COST:
            return None

        llm_price = COST[model_name]
        prompt_price = (prompt_tokens / 1000000) * llm_price["prompt_price"]
        completion_price = (completion_tokens / 1000000) * llm_price["completion_price"]

        return round(prompt_price + completion_price, 5)

    def _set_prompt_style(self, prompt_style):
        self.prompt_style = prompt_style
        global active_prompt_style
        active_prompt_style = prompt_style

    def _set_model(self, model):
        self.model = model
        global active_model
        active_model = model

    def get_model(self):
        # TODO: this hack needs to be refactored later
        global active_model
        return str(active_model)
    
    #
    # LLM Settings
    #

    # single function to ask for all the settings
    def ask_settings(self, *args, **kwargs):
        # attempts to ask for all the configurations by the user. 
        dialog = DAILAConfigDialog(self.config)
        new_config = dialog.config_dialog_exec()
        if new_config:
            # apply the new config
            self.is_load_from_config = True
            self.config = new_config
            self.config.save()
            self.load_config()
            self._dec_interface.info("DAILA Settings applied.")
        else:
            self._dec_interface.error("DAILA Settings not applied.")