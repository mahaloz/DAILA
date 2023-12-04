import textwrap
from pathlib import Path
import importlib.resources

from libbs.plugin_installer import PluginInstaller


class DAILAInstaller(PluginInstaller):
    def __init__(self):
        super().__init__(targets=("ida", "ghidra", "binja"))
        self.pkg_path = Path(str(importlib.resources.files("dailalib"))).absolute()

    def _copy_plugin_to_path(self, path):
        src = self.pkg_path / "daila_plugin.py"
        dst = Path(path) / "daila_plugin.py"
        self.link_or_copy(src, dst, symlink=True)

    def display_prologue(self):
        print(textwrap.dedent("""
        Now installing...
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
        
        The Decompiler AI Language Assistant                                                         
        """))

    def install_ida(self, path=None, interactive=True):
        path = path or super().install_ida(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_ghidra(self, path=None, interactive=True):
        path = path or super().install_ghidra(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_binja(self, path=None, interactive=True):
        path = path or super().install_binja(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_angr(self, path=None, interactive=True):
        path = path or super().install_angr(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path
