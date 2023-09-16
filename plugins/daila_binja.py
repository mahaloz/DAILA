from functools import wraps

import binaryninja
from binaryninja import PluginCommand
from binaryninja import lineardisassembly
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType, InstructionTextTokenType
from PySide6.QtWidgets import QProgressDialog


from dailalib.interfaces.openai_interface import OpenAIInterface, addr_ctx_when_none


def with_loading_popup(func):
    @wraps(func)
    def _with_loading_popup(*args, **kwargs):
        prg = QProgressDialog("Querying AI...", "Stop", 0, 1, None)
        prg.show()

        try:
            out = func(*args, **kwargs)
        except Exception as e:
            print(e)
            out = None

        prg.setValue(1)
        prg.close()
        return out

    return _with_loading_popup


class BinjaOpenAIInterface(OpenAIInterface):
    def __init__(self, bv=None, plugin=None):
        self.bv = bv
        self.plugin = plugin
        super().__init__()

    def _current_function_addr(self, **kwargs):
        addr = kwargs.get("address", None)
        if addr is None:
            return None

        return addr

    def _decompile(self, func_addr: int, **kwargs):
        bv = self.bv
        if bv is None:
            print("[DAILA] Warning: was unable to collect the current BinaryView. Please report this issue.")
            return

        func = DAILAPlugin.get_func(bv, func_addr)
        if func is None:
            return None

        settings = DisassemblySettings()
        settings.set_option(DisassemblyOption.ShowVariableTypesWhenAssigned)
        settings.set_option(DisassemblyOption.GroupLinearDisassemblyFunctions)
        settings.set_option(DisassemblyOption.WaitForIL)

        decomp = ""
        obj = lineardisassembly.LinearViewObject.single_function_language_representation(func, settings)
        cursor = obj.cursor
        while True:
            for line in cursor.lines:
                if line.type in [
                    LinearDisassemblyLineType.FunctionHeaderStartLineType,
                    LinearDisassemblyLineType.FunctionHeaderEndLineType,
                    LinearDisassemblyLineType.AnalysisWarningLineType,
                ]:
                    continue
                for i in line.contents.tokens:
                    if i.type == InstructionTextTokenType.TagToken:
                        continue

                    decomp += str(i)
                decomp += "\n"

            if not cursor.next():
                break

        return decomp

    def _cmt_func(self, func_addr: int, comment: str, **kwargs):
        bv = self.bv
        if bv is None:
            return None

        func = DAILAPlugin.get_func(bv, func_addr)
        if func is None:
            return None

        func.comment = comment

    def _register_menu_item(self, name, action_string, callback_func):
        PluginCommand.register_for_address(
            f"DAILA: {action_string}",
            action_string,
            callback_func,
            is_valid=self.plugin.is_func
        )

    def ask_api_key(self, *args, **kwargs):
        resp = binaryninja.get_text_line_input("Enter you OpenAI API Key: ", "DAILA: Update API Key")
        if not resp:
            return

        self.api_key = resp.decode()

    @with_loading_popup
    @addr_ctx_when_none
    def find_source_of_function(self, *args, **kwargs) -> str:
        bv, address = args[0:2]
        self.bv = bv
        return super().find_source_of_function(func_addr=address, bv=bv, edit_dec=True)

    @with_loading_popup
    @addr_ctx_when_none
    def summarize_function(self, *args, **kwargs) -> str:
        bv, address = args[0:2]
        self.bv = bv
        return super().summarize_function(func_addr=address, bv=bv, edit_dec=True)

    @with_loading_popup
    @addr_ctx_when_none
    def find_vulnerability_in_function(self, *args, **kwargs) -> str:
        bv, address = args[0:2]
        self.bv = bv
        return super().find_vulnerability_in_function(func_addr=address, bv=bv, edit_dec=True)

    @with_loading_popup
    @addr_ctx_when_none
    def answer_questions(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs):
        bv, address = args[0:2]
        self.bv = bv
        return super().answer_questions(func_addr=address, bv=bv, edit_dec=True)

    @with_loading_popup
    @addr_ctx_when_none
    def rename_functions_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs):
        bv, address = args[0:2]
        self.bv = bv
        return super().rename_functions_in_function(func_addr=address, bv=bv, edit_dec=True)

    @with_loading_popup
    @addr_ctx_when_none
    def rename_variables_in_function(self, *args, func_addr=None, decompilation=None, edit_dec=False, **kwargs):
        bv, address = args[0:2]
        self.bv = bv
        return super().rename_variables_in_function(func_addr=address, bv=bv, edit_dec=True)





class DAILAPlugin:
    def __init__(self):
        self.controller = BinjaOpenAIInterface(plugin=self)

    @staticmethod
    def get_func(bv, address):
        funcs = bv.get_functions_containing(address)
        try:
            func = funcs[0]
        except IndexError:
            return None

        return func

    @staticmethod
    def is_func(bv, address):
        func = DAILAPlugin.get_func(bv, address)
        return func is not None


plugin = DAILAPlugin()
