__version__ = "2.0.0"

from .api import AIAPI, OpenAIAPI
from libbs.api import DecompilerInterface


def create_plugin(*args, **kwargs):

    ai_api = OpenAIAPI(delay_init=True)
    # create context menus for prompts
    gui_ctx_menu_actions = {
        f"DAILA/{prompt_name}": (prompt.desc, getattr(ai_api, prompt_name))
        for prompt_name, prompt in ai_api.prompts_by_name.items()
    }
    # create context menus for others
    gui_ctx_menu_actions["DAILA/Update API Key"] = ("Update API Key", ai_api.ask_api_key)

    # create decompiler interface
    force_decompiler = kwargs.pop("force_decompiler", None)
    deci = DecompilerInterface.discover_interface(
        force_decompiler=force_decompiler,
        # decompiler-creation args
        plugin_name="DAILA",
        init_plugin=True,
        gui_ctx_menu_actions=gui_ctx_menu_actions,
        ui_init_args=args,
        ui_init_kwargs=kwargs
    )
    ai_api.init_decompiler_interface(decompiler_interface=deci)

    return deci.gui_plugin
