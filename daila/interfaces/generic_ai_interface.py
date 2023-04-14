from typing import Dict, Optional

from binsync.api import load_decompiler_controller, BSController


class GenericAIInterface:
    def __init__(self, decompiler_controller: Optional[BSController] = None):
        self.decompiler_controller = decompiler_controller or load_decompiler_controller()

    #
    # decompiler interface
    #

    def _cmt_func(self, func_addr: int, comment: str, **kwargs):
        return False

    def _decompile(self, func_addr: int, **kwargs):
        return self.decompiler_controller.decompile(func_addr)

    def _current_function_addr(self, **kwargs):
        return None

    def _register_menu_item(self, name, action_string, callback_func):
        return False

    def _rename_variables_by_name(self, func_addr: int, names: Dict[str, str]):
        return False

    def ask_api_key(self):
        pass
