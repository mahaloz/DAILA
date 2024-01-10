__version__ = "2.2.3"

from .api import AIAPI, OpenAIAPI
from libbs.api import DecompilerInterface


def create_plugin(*args, **kwargs):

    #
    # OpenAI API (ChatGPT)
    #

    openai_api = OpenAIAPI(delay_init=True)
    # create context menus for prompts
    gui_ctx_menu_actions = {
        f"DAILA/OpenAI/{prompt_name}": (prompt.desc, getattr(openai_api, prompt_name))
        for prompt_name, prompt in openai_api.prompts_by_name.items()
    }
    # create context menus for others
    gui_ctx_menu_actions["DAILA/OpenAI/update_api_key"] = ("Update API Key", openai_api.ask_api_key)

    #
    # VarModel API (local variable renaming)
    #

    from varbert.api import VariableRenamingAPI
    var_api = VariableRenamingAPI(delay_init=True)
    # add single interface, which is to rename variables
    gui_ctx_menu_actions["DAILA/VarBERT/varbert_rename_vars"] = ("Suggest new variable names", var_api.query_model)

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
        ui_init_args=args,
        ui_init_kwargs=kwargs
    )

    openai_api.init_decompiler_interface(decompiler_interface=deci)
    if var_api is not None:
        var_api.init_decompiler_interface(decompiler_interface=deci)

    return deci.gui_plugin
