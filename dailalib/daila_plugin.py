# Run the DAILA server and open the DAILA selector UI.
# @author mahaloz
# @category AI
# @menupath Tools.libbs.Run DAILA

library_command = "dailalib run-ghidra-server"

def create_plugin(*args, force_decompiler=None, **kwargs):
    from yodalib.api import DecompilerInterface
    from dailalib.api import OpenAIAPI

    ai_api = OpenAIAPI(delay_init=True)
    # create context menus for prompts
    gui_ctx_menu_actions = {
        f"DAILA/{prompt_name}": (prompt.desc, getattr(ai_api, prompt_name))
        for prompt_name, prompt in ai_api.prompts_by_name.items()
    }
    # create context menus for others
    gui_ctx_menu_actions["DAILA/Update API Key"] = ("Update API Key", ai_api.ask_api_key)

    # create decompiler interface
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

# =============================================================================
# LibBS generic plugin entry point
# =============================================================================

import sys
try:
    import idaapi
    has_ida = True
except ImportError:
    has_ida = False
try:
    import binaryninja
    has_binja = True
except ImportError:
    has_binja = False


def ghidra_plugin_main():
    """
    This is the entry point for Ghidra to load the plugin.
    """
    import subprocess
    from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer
    full_command = "python3 -m " + library_command

    GhidraBridgeServer.run_server(background=True)
    subprocess.Popen(full_command.split(" "))

def PLUGIN_ENTRY(*args, **kwargs):
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)

if has_binja:
    # Binja will not execute __main__, so we need to create the plugin manually
    create_plugin()
elif has_ida:
    # IDA will only use plugins created in PLUGIN_ENTRY, so we do nothing and rely on the func above
    pass
elif __name__ == "__main__":
    # Any other decompiler is assumed to execute __main__, as either Python 2 or 3
    if sys.version[0] == "2":
        # Python 2 indicated Ghidra, so we start the specialized Ghidra py2 plugin which spins up a
        # server in the Ghidra Python2 backend, then uses this file for Python3
        ghidra_plugin_main()
    else:
        create_plugin()

