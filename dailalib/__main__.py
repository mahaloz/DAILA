import argparse
import importlib.resources
from pathlib import Path

import dailalib
from .installer import DAILAInstaller



class COMMANDS:
    INSTALL = "install"
    RUN_GHIDRA_SERVER = "run-ghidra-server"
    ALL_COMMANDS = [INSTALL, RUN_GHIDRA_SERVER]


def main():
    parser = argparse.ArgumentParser(
        description="""
            The DAILA CLI is used to install the DAILA core to supported decompilers as plugins and run the
            headless DAILA server for use with Ghidra. 
            """,
        epilog="""
            Examples:
            dailalib install
            """
    )
    parser.add_argument(
        "command", choices=COMMANDS.ALL_COMMANDS, help="""
        The command to run. 
        """
    )
    parser.add_argument(
        "--version", action="version", version=f"DAILA {dailalib.__version__}"
    )
    args = parser.parse_args()

    if args.command == COMMANDS.INSTALL:
        DAILAInstaller().install()
    elif args.command == COMMANDS.RUN_GHIDRA_SERVER:
        from dailalib.daila_plugin import create_plugin
        create_plugin(force_decompiler="ghidra")


if __name__ == "__main__":
    main()
