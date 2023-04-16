import textwrap
from pathlib import Path

import pkg_resources
from binsync.installer import Installer


class DAILAInstaller(Installer):
    def __init__(self):
        super().__init__(targets=("ida", "ghidra", "binja"))
        self.plugins_path = Path(
            pkg_resources.resource_filename("dailalib", f"plugins")
        )

    def display_prologue(self):
        print(textwrap.dedent("""
         ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄            ▄▄▄▄▄▄▄▄▄▄▄ 
        ▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌
        ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ ▐░▌          ▐░█▀▀▀▀▀▀▀█░▌
        ▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌          ▐░▌       ▐░▌
        ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░▌          ▐░█▄▄▄▄▄▄▄█░▌
        ▐░▌       ▐░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌          ▐░░░░░░░░░░░▌
        ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░▌          ▐░█▀▀▀▀▀▀▀█░▌
        ▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌     ▐░▌          ▐░▌       ▐░▌
        ▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌ ▄▄▄▄█░█▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌
        ▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
         ▀▀▀▀▀▀▀▀▀▀   ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀ 
                                                                 
        Now installing DAILA...
        Please input your decompiler install paths as prompted. Enter nothing to either use
        the default install path if one exist, or to skip.
        """))

    def install_ida(self, path=None):
        ida_plugin_path = super().install_ida(path=path)
        if ida_plugin_path is None:
            return

        src_ida_py = self.plugins_path.joinpath("daila_ida.py").absolute()
        dst_ida_py = ida_plugin_path.joinpath("daila_ida.py").absolute()
        self.link_or_copy(src_ida_py, dst_ida_py)
        return dst_ida_py

    def install_ghidra(self, path=None):
        ghidra_path = self.ask_path("Ghidra Scripts Path:") if path is None else path
        if not ghidra_path:
            return None

        ghidra_path: Path = ghidra_path.expanduser().absolute()
        if not ghidra_path.exists():
            return None

        src_ghidra_py = self.plugins_path.joinpath("daila_ghidra.py").absolute()
        dst_path = ghidra_path.expanduser().absolute()
        if not dst_path.exists():
            return None

        dst_ghidra_py = dst_path.joinpath(src_ghidra_py.name)
        self.link_or_copy(src_ghidra_py, dst_ghidra_py)
        return dst_ghidra_py

    def install_binja(self, path=None):
        binja_plugin_path = super().install_binja(path=path)
        if binja_plugin_path is None:
            return None

        src_path = self.plugins_path.joinpath("daila_binja.py")
        dst_path = binja_plugin_path.joinpath("daila_binja.py")
        self.link_or_copy(src_path, dst_path)
        return dst_path
