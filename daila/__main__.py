import argparse

from .installer import DAILAInstaller
from .controller_server import DAILAServer


def main():
    parser = argparse.ArgumentParser(
        description="""
            The DAILA Command Line Util. 
            """,
        epilog="""
            Examples:
            daila --install
            """
    )
    parser.add_argument(
        "--install", action="store_true", help="""
        Install the DAILA core to supported decompilers as plugins. This option will start an interactive
        prompt asking for install paths for all supported decompilers. Each install path is optional and 
        will be skipped if not path is provided during install. 
        """
    )
    parser.add_argument(
        "-server", action="store_true", help="""
        Starts the DAILA Server for use with Ghidra
        """
    )
    args = parser.parse_args()

    if args.install:
        DAILAInstaller().install()

    if args.server:
        DAILAServer().start_xmlrpc_server()


if __name__ == "__main__":
    main()
