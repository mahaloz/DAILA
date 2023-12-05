import textwrap
from pathlib import Path
import importlib.resources

from libbs.plugin_installer import PluginInstaller

from dailalib import VARMODEL_AVAILABLE


class DAILAInstaller(PluginInstaller):
    def __init__(self):
        super().__init__(targets=("ida", "ghidra", "binja", "angr"))
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

    def display_epilogue(self):
        super().display_epilogue()
        if VARMODEL_AVAILABLE:
            self.info("We will now download local moodle for each decompiler you've installed. Ctrl+C to cancel.")
            from varmodel import install_model as install_varmodel_model
            for target in self._successful_installs:
                install_varmodel_model(target, opt_level="O0")

            self.info("Installs completed!")