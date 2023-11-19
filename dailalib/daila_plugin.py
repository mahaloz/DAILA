import sys
try:
    import idaapi
    has_ida = True
except:
    has_ida = False


def create_plugin(*args, **kwargs):
    from yodalib.api import DecompilerInterface
    from dailalib.api import OpenAIAPI

    ai_api = OpenAIAPI(delay_init=True)
    # create context menus
    gui_ctx_menu_actions = {
        f"DAILA/{prompt_name}": (prompt.desc, getattr(ai_api, prompt_name))
        for prompt_name, prompt in ai_api.prompts_by_name.items()
    }

    # create decompiler interface
    deci = DecompilerInterface.discover_interface(
        force_decompiler="ida",
        # decompiler-creation args
        plugin_name="daila_new",
        init_plugin=True,
        gui_ctx_menu_actions=gui_ctx_menu_actions,
        ui_init_args=args,
        ui_init_kwargs=kwargs
    )
    ai_api.init_decompiler_interface(decompiler_interface=deci)
    return deci.gui_plugin


def PLUGIN_ENTRY(*args, **kwargs):
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)


if __name__ == "__main__":
    if has_ida:
        # will be called in PLUGIN_ENTRY for IDA
        pass
    elif sys.version[0] == "2":
        # TODO: do Ghidra stuff here
        pass
    else:
        # we are in some other Py3 decompiler
        create_plugin()
