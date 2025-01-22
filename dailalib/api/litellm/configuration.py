from libbs.configuration import BSConfig
from typing import Optional, Dict
from platformdirs import user_config_dir
import logging 
import os 

_l = logging.getLogger(__name__)

class DAILAConfig(BSConfig): 
    '''
    Configuration class for LLM API, model, prompt style, and probably other things in the future.
    '''
    __slots__ = (
        "save_location", 
        "_config_lock",
        "model",        # LLM Model selected by user, 
        "api_key",     # API keys for selected model,
        "prompt_style", # Prompt style selected by user,
        "custom_endpoint", # Custom OpenAI endpoint
        "custom_model"  # Custom OpenAI model
    )

    def __init__(self, save_location: Optional[str] = None):
        save_location = user_config_dir("daila")
        super().__init__(save_location)
        self.save_location = self.save_location / f"{self.__class__.__name__}.toml"
        self.model = "gpt-4o"
        self.api_key = "THISISAFAKEAPIKEY"
        self.prompt_style = "few-shot"
        self.custom_endpoint = ""
        self.custom_model = ""
