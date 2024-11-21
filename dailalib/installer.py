import textwrap
from pathlib import Path

from libbs.plugin_installer import LibBSPluginInstaller

VARBERT_AVAILABLE = True
try:
    import varbert
except ImportError:
    VARBERT_AVAILABLE = False


class DAILAInstaller(LibBSPluginInstaller):
    def __init__(self):
        super().__init__()
        self.pkg_path = self.find_pkg_files("dailalib")

    def _copy_plugin_to_path(self, path):
        src = self.pkg_path / "daila_plugin.py"
        dst = Path(path) / "daila_plugin.py"
        self.link_or_copy(src, dst, symlink=True)

    def display_prologue(self):
        print(textwrap.dedent("""
        Now installing...
        
        ██████   █████  ██ ██       █████      
        ██   ██ ██   ██ ██ ██      ██   ██     
        ██   ██ ███████ ██ ██      ███████     
        ██   ██ ██   ██ ██ ██      ██   ██     
        ██████  ██   ██ ██ ███████ ██   ██
        
        The Decompiler AI Language Assistant                                                         
        """))

    def install_ida(self, path=None, interactive=True):
        path = super().install_ida(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_ghidra(self, path=None, interactive=True):
        path = super().install_ghidra(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_binja(self, path=None, interactive=True):
        path = super().install_binja(path=path, interactive=interactive)
        if not path:
            return

        self._copy_plugin_to_path(path)
        return path

    def install_angr(self, path=None, interactive=True):
        path = super().install_angr(path=path, interactive=interactive)
        if not path:
            return

        path = path / "DAILA"
        path.mkdir(parents=True, exist_ok=True)
        src = self.pkg_path / "plugin.toml"
        dst = Path(path) / "plugin.toml"
        self.link_or_copy(src, dst, symlink=True)
        self._copy_plugin_to_path(path)
        return path

    def display_epilogue(self):
        super().display_epilogue()
        print("")
        if VARBERT_AVAILABLE:
            self.install_local_models()
        else:
            self.warn("VarBERT not installed, reinstall with `pip install dailalib[full]` to enable local models if you would like them.")

    def install_local_models(self):
        self.info("We will now download local models for each decompiler you've installed. Ctrl+C to cancel.")
        self.install_varmodel_models()

    def install_varmodel_models(self):
        self.info("Installing VarBERT models...")
        from varbert import install_model as install_varbert_model
        for target in self._successful_installs:
            install_varbert_model(target, opt_level="O0")
