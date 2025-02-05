from pathlib import Path
from typing import Optional
import os
import logging

import tiktoken

from libbs.decompilers import GHIDRA_DECOMPILER

from . import DEFAULT_MODEL, LLM_COST, OPENAI_MODELS
from ..ai_api import AIAPI
from dailalib.configuration import DAILAConfig

active_model = None
active_prompt_style = None

_l = logging.getLogger(__name__)


class LiteLLMAIAPI(AIAPI):
    prompts_by_name = []

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
        use_config: bool = True,
        **kwargs
    ):
        super().__init__(**kwargs)

        self._use_config = use_config
        # default values
        self._api_key = None
        self.model = model
        # default to openai api key if not provided
        if api_key or os.getenv("OPENAI_API_KEY"):
            self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        elif not self._use_config:
            self.api_key = None

        self.prompt_style = prompt_style
        self.fit_to_tokens = fit_to_tokens
        self.chat_use_ctx = chat_use_ctx
        self.chat_event_callbacks = chat_event_callbacks or {"send": None, "receive": None}
        self.custom_endpoint = custom_endpoint
        self.custom_model = custom_model
        self.config = DAILAConfig()
        if use_config:
            loaded = self.load_or_create_config()
            if loaded:
                _l.info("Loaded config file from %s", self.config.save_location)

        # delay prompt import
        from .prompts import PROMPTS
        prompts = prompts + PROMPTS if prompts else PROMPTS
        self.prompts_by_name = {p.name: p for p in prompts}

        # update the globals (for threading hacks)
        global active_model, active_prompt_style
        active_model = self.model
        active_prompt_style = self.prompt_style

    def load_or_create_config(self, new_config=None) -> bool:
        if new_config:
            self.config = new_config
            self.config.save()

        if self.config.save_location and not Path(self.config.save_location).exists():
            return False

        # load the config
        self.config.load()
        self.model = self.config.model
        self.api_key = self.config.api_key
        self.prompt_style = self.config.prompt_style
        if self.config.custom_endpoint:
            self.custom_endpoint = self.config.custom_endpoint
        if self.config.custom_model:
            self.custom_model = self.config.custom_model
        # update the globals (for threading hacks)
        self._set_model(self.model)
        self._set_prompt_style(self.prompt_style)
        return True

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

    @property
    def api_key(self):
        if not self._api_key or self.model is None:
            return None
        elif self.model in OPENAI_MODELS:
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
            if self.model in OPENAI_MODELS:
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
        custom_model = value.strip() if isinstance(value, str) else None
        if not custom_model:
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
        custom_endpoint = value.strip() if isinstance(value, str) else None
        if not custom_endpoint:
            self._custom_endpoint = None
            _l.info(f"Custom endpoint disabled, defaulting to online API")
            return
        if not (custom_endpoint.lower().startswith("http://") or custom_endpoint.lower().startswith("https://")):
            self._custom_endpoint = None
            _l.error("Invalid endpoint format")
            return
        self._custom_endpoint = custom_endpoint.strip()
        _l.info(f"Custom endpoint set to {self._custom_endpoint}")

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
        if model_name not in LLM_COST:
            return None

        llm_price = LLM_COST[model_name]
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
        # attempts to ask for all the configurations by the user
        is_ghidra = self._dec_interface.name == GHIDRA_DECOMPILER
        _l.info(f"Using {self._dec_interface.name} decompiler, starting with QT {self._dec_interface.qt_version}")
        new_config = self._dec_interface.gui_run_on_main_thread(
            self.open_config_dialog,
            self.config,
            make_app=is_ghidra,
            qt_version=self._dec_interface.qt_version
        )

        if new_config:
            self.load_or_create_config(new_config=new_config)
            self._dec_interface.info("DAILA Settings applied.")
        else:
            self._dec_interface.error("DAILA Settings not applied.")

    @staticmethod
    def open_config_dialog(config: DAILAConfig, make_app=False, qt_version: str = "PySide6") -> DAILAConfig:
        # delay import to configure the qt for the right platform
        from libbs.ui.version import set_ui_version
        set_ui_version(qt_version)
        from libbs.ui.qt_objects import QApplication
        from .config_dialog import DAILAConfigDialog

        if make_app:
            app = QApplication([])
            _l.info("Creating a new window for the DAILA settings")
            _dialog = DAILAConfigDialog(config)
            _l.info("Running the dialog")
            new_config = _dialog.config_dialog_exec()
            app.quit()
        else:
            dialog = DAILAConfigDialog(config)
            new_config = dialog.config_dialog_exec()

        return new_config
