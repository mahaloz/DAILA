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
    "gemini/gemini-2.0-flash": 1_000_000,
    "vertex_ai_beta/gemini-2.0-flash": 1_000_000,
    # perplex is on legacy mode :(
    "perplexity/llama-3.1-sonar-small-128k-online": 127_072,
    "perplexity/llama-3.1-sonar-medium-128k-online": 127_072,
    "perplexity/llama-3.1-sonar-large-128k-online": 127_072,
    "sonar-pro": 127_072,
    "sonar": 127_072,
}

LLM_COST = {
    "gpt-4o": {"prompt_price": 2.5, "completion_price": 10},
    "gpt-4o-mini": {"prompt_price": 0.150, "completion_price": 0.600},
    "gpt-4-turbo": {"prompt_price": 10, "completion_price": 30},
    "claude-3.5-sonnet-20240620": {"prompt_price": 3, "completion_price": 15},
    "gemini/gemini-2.0-flash": {"prompt_price": 0.10, "completion_price": 0.4},
    "vertex_ai_beta/gemini-2.0-flash": {"prompt_price": 0.10, "completion_price": 0.4},
    # perplex is on legacy mode not available from 02/22/25:(
    "perplexity/llama-3.1-sonar-small-128k-online": {"prompt_price": 0.150, "completion_price": 0.600},
    "perplexity/llama-3.1-sonar-large-128k-online": {"prompt_price": 0.150, "completion_price": 0.600},
    "perplexity/llama-3.1-sonar-huge-128k-online": {"prompt_price": 0.150, "completion_price": 0.600},
    # introduced the new sonar-pro/sonar
    "sonar": {"prompt_price": 0.150, "completion_price": 0.600},
    "sonar-pro": {"prompt_price": 0.150, "completion_price": 0.600},
}

# delay import for const creation
from .litellm_api import LiteLLMAIAPI
from .prompt_type import PromptType, ALL_STYLES, DEFAULT_STYLE

