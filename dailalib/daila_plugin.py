# Run the DAILA server and open the DAILA selector UI.
# @author mahaloz
# @category AI
# @menupath Tools.DAILA.Start DAILA Backend


python_library_command = "dailalib -s ghidra"
shell_library_command = "daila -s ghidra"
def create_plugin(*args, **kwargs):
    from dailalib import create_plugin as _create_plugin
    return _create_plugin(*args, **kwargs)

# =============================================================================
# LibBS generic plugin loader (don't touch)
# =============================================================================

import sys
# Python 2 has special requirements for Ghidra, which forces us to use a different entry point
# and scope for defining plugin entry points
if sys.version[0] == "2":
    # Do Ghidra Py2 entry point
    import subprocess
    from libbs_vendored.ghidra_bridge_server import GhidraBridgeServer
    from distutils.spawn import find_executable
    cmd = shell_library_command.split(" ")
    if not find_executable(cmd[0]):
        # fallback to doing python style module call 
        python_end = ["-m"] + python_library_command.split(" ")
        python_exec = "python" if find_executable("python") else "python3"
        cmd = [python_exec] + python_end
    
    GhidraBridgeServer.run_server(background=True)
    print("[+] Starting the backend now...")
    try:
        process = subprocess.Popen(cmd)
    except Exception as e:
        print("[!] Failed to run the backend command", cmd, "because", e)

    if process.poll() is not None:
        raise RuntimeError(
            "Failed to run the Python3 backed. It's likely Python3 is not in your Path inside Ghidra.")
else:
    # Try plugin discovery for other decompilers
    try:
        import idaapi
        has_ida = True
    except ImportError:
        has_ida = False
    try:
        import angrmanagement
        has_angr = True
    except ImportError:
        has_angr = False

    if not has_ida and not has_angr:
        create_plugin()
    elif has_angr:
        from angrmanagement.plugins import BasePlugin
        class AngrBSPluginThunk(BasePlugin):
            def __init__(self, workspace):
                super().__init__(workspace)
                globals()["workspace"] = workspace
                self.plugin = create_plugin()

            def teardown(self):
                pass


def PLUGIN_ENTRY(*args, **kwargs):
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)
