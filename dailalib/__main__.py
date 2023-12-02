import argparse

import dailalib
from .installer import DAILAInstaller


def main():
    parser = argparse.ArgumentParser(
        description="""
            The DAILA CLI is used to install, run, and host the DAILA plugin.
            """,
        epilog="""
            Examples:
            daila install
            """
    )
    parser.add_argument(
        "-i", "--install", action="store_true", help="Install DAILA into your decompiler"
    )
    parser.add_argument(
        "-s", "--server", help="Run a a headless server for DAILA", choices=["ghidra"]
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"DAILA {dailalib.__version__}"
    )
    args = parser.parse_args()

    if args.install:
        DAILAInstaller().install()
    elif args.server:
        if args.server != "ghidra":
            raise NotImplementedError("Only Ghidra is supported for now")

        from dailalib.daila_plugin import create_plugin
        create_plugin(force_decompiler="ghidra")


if __name__ == "__main__":
    main()
