from typing import Dict, Optional
from functools import wraps
import threading

from libbs.api import DecompilerInterface


class AIAPI:
    def __init__(
        self,
        decompiler_interface: Optional[DecompilerInterface] = None,
        decompiler_name: Optional[str] = None,
        use_decompiler: bool = True,
        delay_init: bool = False,
        # size in bytes
        min_func_size: int = 0x10,
        max_func_size: int = 0xffff,
        model=None,
    ):
        # useful for initing after the creation of a decompiler interface
        self._dec_interface: Optional[DecompilerInterface] = None
        self._dec_name = None
        self._delay_init = delay_init
        if not self._delay_init:
            self.init_decompiler_interface(decompiler_interface, decompiler_name, use_decompiler)

        self._min_func_size = min_func_size
        self._max_func_size = max_func_size
        self.model = model or self.__class__.__name__

    def init_decompiler_interface(
        self,
        decompiler_interface: Optional[DecompilerInterface] = None,
        decompiler_name: Optional[str] = None,
        use_decompiler: bool = True
    ):
        self._dec_interface: DecompilerInterface = DecompilerInterface.discover(force_decompiler=decompiler_name) \
            if use_decompiler and decompiler_interface is None else decompiler_interface
        self._dec_name = decompiler_name if decompiler_interface is None else decompiler_interface.name
        if self._dec_interface is None and not self._dec_name:
            raise ValueError("You must either provide a decompiler name or a decompiler interface.")

    def info(self, msg):
        if self._dec_interface is not None:
            self._dec_interface.info(msg)

    def debug(self, msg):
        if self._dec_interface is not None:
            self._dec_interface.debug(msg)

    def warning(self, msg):
        if self._dec_interface is not None:
            self._dec_interface.warning(msg)

    def error(self, msg):
        if self._dec_interface is not None:
            self._dec_interface.error(msg)

    @property
    def has_decompiler_gui(self):
        return self._dec_interface is not None and not self._dec_interface.headless

    @staticmethod
    def requires_function(f):
        """
        A wrapper function to make sure an API call has decompilation text to operate on and possibly a Function
        object. There are really two modes any API call operates in:
        1. Without Decompiler Backend: requires provided dec text
        2. With Decompiler Backend:
               2a. With UI: Function will be collected from the UI if not provided
               2b. Without UI: requires a FunctionA

        The Function collected from the UI is the one the use is currently looking at.
        """
        @wraps(f)
        def _requires_function(*args, ai_api: "AIAPI" = None, **kwargs):
            function = kwargs.pop("function", None)
            dec_text = kwargs.pop("dec_text", None)
            use_dec = kwargs.pop("use_dec", True)
            has_self = kwargs.pop("has_self", True)
            # make the self object the new AI API, should only be used inside an AIAPI class
            if not ai_api and has_self:
                ai_api = args[0]

            if not dec_text and not use_dec:
                raise ValueError("You must provide decompile text if you are not using a dec backend")

            # two mode constructions: with decompiler and without
            # with decompiler backend
            if use_dec:
                if not ai_api.has_decompiler_gui and function is None:
                    raise ValueError("You must provide a Function when using this with a decompiler")

                # we must have a UI if we have no func
                if function is None:
                    function = ai_api._dec_interface.art_lifter.lower(
                        ai_api._dec_interface.functions[ai_api._dec_interface.active_context().addr]
                    )

                # get new text with the function that is present
                if dec_text is None:
                    dec_text = ai_api._dec_interface.decompile(function.addr)

            return f(*args, function=function, dec_text=dec_text, use_dec=use_dec, **kwargs)

        return _requires_function

