from typing import Dict, Optional

from yodalib.api import DecompilerInterface


class AIAPI:
    def __init__(
        self,
        decompiler_interface=None,
        decompiler_name=None,
        use_decompiler=True,
        min_func_size=0x10
    ):
        self._dec_interface = DecompilerInterface.discover_interface(force_decompiler=decompiler_name) \
            if use_decompiler and decompiler_interface is None else decompiler_interface
        self._dec_name = decompiler_name if decompiler_interface is None else decompiler_interface.name
        if self._dec_interface is None and not self._dec_name:
            raise ValueError("You must either provide a decompiler name or a decompiler interface.")

        self._min_func_size = min_func_size

