import argparse

from .installer import DAILAInstaller
import dailalib


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
        "-i", "--install", action="store_true", help="Install DAILA into your decompilers"
    )
    parser.add_argument(
        "--single-decompiler-install", nargs=2, metavar=('decompiler', 'path'), help="Install DAILA into a single decompiler. Decompiler must be one of: ida, ghidra, binja, angr."
    )
    parser.add_argument(
        "-s", "--server", help="Run a a headless server for DAILA", choices=["ghidra"]
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"{dailalib.__version__}"
    )
    args = parser.parse_args()

    if args.single_decompiler_install:
        decompiler, path = args.single_decompiler_install
        DAILAInstaller().install(interactive=False, paths_by_target={decompiler: path})
    elif args.install:
        DAILAInstaller().install()
    elif args.server:
        if args.server != "ghidra":
            raise NotImplementedError("Only Ghidra is supported for now")

        from dailalib import create_plugin
        create_plugin(force_decompiler="ghidra")


if __name__ == "__main__":
    main()
