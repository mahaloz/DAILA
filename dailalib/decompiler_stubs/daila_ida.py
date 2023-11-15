def PLUGIN_ENTRY(*args, **kwargs):
    from yodalib.api import DecompilerInterface

    def _faux_func(*_args, **_kwargs):
        print("[+] IT ACTUALLY RAN!")

    deci = DecompilerInterface.discover_interface(
        force_decompiler="ida",
        plugin_name="daila_new",
        gui_ctx_menu_actions={"DAILA/tester": ("Run the tester", _faux_func)},
        ui_init_args=args, ui_init_kwargs=kwargs
    )
    return deci.gui_plugin
