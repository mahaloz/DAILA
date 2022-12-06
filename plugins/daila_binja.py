from binaryninja import PluginCommand
from binaryninja import lineardisassembly
from binaryninja.function import DisassemblySettings
from binaryninja.enums import DisassemblyOption, LinearDisassemblyLineType, InstructionTextTokenType
from PySide6.QtWidgets import QProgressDialog


from daila.controller import DAILAController


class BinjaDAILAController(DAILAController):
    def __init__(self, bv=None):
        super().__init__()
        self.bv = None

    def _current_function_addr(self, **kwargs):
        addr = kwargs.get("address", None)
        if addr is None:
            return None

        return addr

    def _decompile(self, func_addr: int, **kwargs):
        bv = kwargs.get("bv", None)
        if bv is None:
            return None

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
        bv = kwargs.get("bv", None)
        if bv is None:
            return None

        func = DAILAPlugin.get_func(bv, func_addr)
        if func is None:
            return None

        func.comment = comment


class DAILAPlugin:
    def __init__(self):
        self.controller = BinjaDAILAController()

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

    def identify_function(self, bv, address):
        print("[+] Identifying Function Now. Please Wait...")
        prg = QProgressDialog("Querying AI...", "Stop", 0, 1, None)
        prg.show()
        self.controller.id_current_function(address=address, bv=bv)
        prg.setValue(1)
        prg.close()


plugin = DAILAPlugin()
PluginCommand.register_for_address(
    "DAILA: Identify Function",
    "Identifies the current function you are in and sets response in comment",
    plugin.identify_function,
    is_valid=plugin.is_func
)
