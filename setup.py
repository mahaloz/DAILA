# pylint: disable=missing-class-docstring
import os
import shutil
from pathlib import Path
from distutils.command.build import build as st_build

from setuptools import setup
from setuptools.command.develop import develop as st_develop


def _copy_plugins():
    local_plugins = Path("plugins").absolute()
    daila_loc = Path("dailalib").absolute()
    pip_e_plugins = daila_loc.joinpath("plugins").absolute()

    # clean the install location of symlink or folder
    shutil.rmtree(pip_e_plugins, ignore_errors=True)
    try:
        os.unlink(pip_e_plugins)
    except:
        pass

    # first attempt a symlink, if it works, exit early
    try:
        os.symlink(local_plugins, pip_e_plugins, target_is_directory=True)
        return
    except:
        pass

    # copy if symlinking is not available on target system
    try:
        shutil.copytree("plugins", "dailalib/plugins")
    except:
        pass

class build(st_build):
    def run(self, *args):
        self.execute(_copy_plugins, (), msg="Copying plugins...")
        super().run(*args)

class develop(st_develop):
    def run(self, *args):
        self.execute(_copy_plugins, (), msg="Linking or copying local plugins folder...")
        super().run(*args)


cmdclass = {
    "build": build,
    "develop": develop,
}

setup(cmdclass=cmdclass)
