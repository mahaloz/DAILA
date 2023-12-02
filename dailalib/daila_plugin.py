# Run the DAILA server and open the DAILA selector UI.
# @author mahaloz
# @category AI
# @menupath Tools.libbs.Run DAILA


# replace this with the command to run your plugin remotely
library_command = "dailalib run-ghidra-server"
# replace this imporate with an import of your plugin's create_plugin function
def create_plugin(*args, **kwargs):
    import ghidra_bridge
    from dailalib import create_plugin as _create_plugin
    return _create_plugin(*args, **kwargs)

# =============================================================================
# LibBS generic plugin loader (don't touch)
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
    process = subprocess.Popen(full_command.split(" "))
    if process.poll() is not None:
        raise RuntimeError("Failed to run the Python3 backed. It's likely Python3 is not in your Path inside Ghidra.")

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
