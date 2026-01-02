# Run the DAILA server and open the DAILA selector UI.
# @author mahaloz
# @category AI
# @menupath Tools.DAILA.Start DAILA Backend
# @runtime PyGhidra


def create_plugin(*args, **kwargs):
    from dailalib import create_plugin as _create_plugin
    return _create_plugin(*args, **kwargs)

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
try:
    import ghidra
    has_ghidra = True
except ImportError:
    has_ghidra = False
try:
    import binaryninja
    has_binja = True
except ImportError:
    has_binja = False


if has_ghidra or has_binja:
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
elif has_ida:
    # IDA will call create_plugin automatically
    pass


def PLUGIN_ENTRY(*args, **kwargs):
    """
    This is the entry point for IDA to load the plugin.
    """
    return create_plugin(*args, **kwargs)
