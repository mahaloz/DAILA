__version__ = "3.4.1"

from .api import AIAPI, LiteLLMAIAPI
from libbs.api import DecompilerInterface


def create_plugin(*args, **kwargs):

    #
    # LLM API (through LiteLLM api)
    #

    litellm_api = LiteLLMAIAPI(delay_init=True)
    # create context menus for prompts
    gui_ctx_menu_actions = {
        f"DAILA/LLM/{prompt_name}": (prompt.desc, getattr(litellm_api, prompt_name))
        for prompt_name, prompt in litellm_api.prompts_by_name.items()
    }
    # create context menus for others
    gui_ctx_menu_actions["DAILA/LLM/update_api_key"] = ("Update API key...", litellm_api.ask_api_key)
    gui_ctx_menu_actions["DAILA/LLM/update_pmpt_style"] = ("Change prompt style...", litellm_api.ask_prompt_style)
    gui_ctx_menu_actions["DAILA/LLM/update_model"] = ("Change model...", litellm_api.ask_model)

    #
    # VarModel API (local variable renaming)
    #

    VARBERT_AVAILABLE = True
    try:
        from varbert.api import VariableRenamingAPI
    except ImportError:
        VARBERT_AVAILABLE = False

    var_api = None
    if VARBERT_AVAILABLE:
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
