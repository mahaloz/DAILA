__version__ = "3.15.2"

import os
# stop LiteLLM from querying at all to the remote server
# https://github.com/BerriAI/litellm/blob/4d29c1fb6941e49191280c4fd63961dec1a1e7c5/litellm/__init__.py#L286C20-L286C48
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"

from .api import AIAPI, LiteLLMAIAPI

from dailalib.llm_chat import get_llm_chat_creator


def create_plugin(*args, **kwargs):
    from libbs.api import DecompilerInterface

    #
    # LLM API (through LiteLLM api)
    #

    litellm_api = LiteLLMAIAPI(delay_init=True)
    # create context menus for prompts
    gui_ctx_menu_actions = {
        f"DAILA/LLM/{prompt_name}": (prompt.desc, getattr(litellm_api, prompt_name))
        for prompt_name, prompt in litellm_api.prompts_by_name.items()
    }
    # create context menu for llm chat
    gui_ctx_menu_actions["DAILA/LLM/chat"] = ("Open LLM Chat...", get_llm_chat_creator(litellm_api))

    # create context menus for others
    gui_ctx_menu_actions["DAILA/LLM/Settings/update_api_key"] = ("Update API key...", litellm_api.ask_api_key)
    gui_ctx_menu_actions["DAILA/LLM/Settings/update_pmpt_style"] = ("Change prompt style...", litellm_api.ask_prompt_style)
    gui_ctx_menu_actions["DAILA/LLM/Settings/update_model"] = ("Change model...", litellm_api.ask_model)
    gui_ctx_menu_actions["DAILA/LLM/Settings/update_custom_url"] = ("Set Custom OpenAI Endpoint...", litellm_api.ask_custom_endpoint)
    gui_ctx_menu_actions["DAILA/LLM/Settings/update_custom_model"] = ("Set Custom OpenAI Model...", litellm_api.ask_custom_model)

    #
    # VarModel API (local variable renaming)
    #

    VARBERT_AVAILABLE = True
    try:
        import varbert
    except ImportError:
        VARBERT_AVAILABLE = False

    var_api = None
    if VARBERT_AVAILABLE:
        from varbert.api import VariableRenamingAPI
        var_api = VariableRenamingAPI(delay_init=True)

        # add single interface, which is to rename variables
        def make_callback(predict_for_all_variables):
            return lambda *args, **kwargs: var_api.query_model(**kwargs, remove_bad_names=not predict_for_all_variables)

        gui_ctx_menu_actions["DAILA/VarBERT/varbert_rename_vars"] = ("Suggest new variable names (source-like only)", make_callback(predict_for_all_variables=False))
        gui_ctx_menu_actions["DAILA/VarBERT/varbert_rename_vars_all"] = ("Suggest new variable names (for all variables)", make_callback(predict_for_all_variables=True))

    #
    # Decompiler Plugin Registration
    #

    force_decompiler = kwargs.pop("force_decompiler", None)
    deci = DecompilerInterface.discover(
        force_decompiler=force_decompiler,
        # decompiler-creation args
        plugin_name="DAILA",
        init_plugin=True,
        gui_ctx_menu_actions=gui_ctx_menu_actions,
        gui_init_args=args,
        gui_init_kwargs=kwargs
    )
    if not VARBERT_AVAILABLE:
        deci.info("VarBERT not installed, reinstall with `pip install dailalib[full]` to enable local models.")

    deci.info("DAILA backend loaded! Initializing context menus now...")

    litellm_api.init_decompiler_interface(decompiler_interface=deci)
    if var_api is not None:
        var_api.init_decompiler_interface(decompiler_interface=deci)

    return deci.gui_plugin
