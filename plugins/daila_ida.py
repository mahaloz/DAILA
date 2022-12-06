import threading
import functools
from typing import Optional

import idaapi
import ida_hexrays
import idc
from PyQt5.QtWidgets import QProgressDialog

from daila.controller import DAILAController

controller: Optional["IDADAILAController"] = None


#
# IDA Threading
#


def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)


def execute_sync(func, sync_type):
    """
    Synchronize with the disassembler for safe database access.
    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> object:
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = func(*args, **kwargs)
            return 1

        if is_mainthread():
            thunk()
        else:
            idaapi.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]
    return wrapper


def execute_read(func):
    return execute_sync(func, idaapi.MFF_READ)


def execute_write(func):
    return execute_sync(func, idaapi.MFF_WRITE)


def execute_ui(func):
    return execute_sync(func, idaapi.MFF_FAST)

#
# IDA PLUGIN
#


def PLUGIN_ENTRY(*args, **kwargs):
    return DAILAPlugin(*args, **kwargs)


class DAILAPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Start the DAILA Interface"
    help = "DAILA Help"
    wanted_name = "Identify the current function you are looking at!"

    id_action_name = "daila:identify_function"
    id_menu_path = "Edit/DAILA/Explain function"

    def __init__(self, *args, **kwargs):
        print("[DAILA] loaded!")


    def init(self):
        """
        This init is highly inspired by the code here:
        https://github.com/JusticeRage/Gepetto
        """
        global controller
        controller = IDADAILAController()

        # Check for whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Function explaining action
        explain_action = idaapi.action_desc_t(
            self.id_action_name,
            'ID Function',
            IdentifyAction(),
            "Ctrl+Alt+Shift+I",
            'Use ChatGPT to identify the currently selected function',
            199
        )
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.id_menu_path, self.id_action_name, idaapi.SETMENU_APP)
        
        self.menu = ContextMenuHooks()
        self.menu.hook()
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        pass

    def term(self):
        pass 


class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, DAILAPlugin.id_action_name, "DAILA/")


class IdentifyAction(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        dec_view = ida_hexrays.get_widget_vdui(ctx.widget)

        prg = QProgressDialog("Querying AI...", "Stop", 0, 1, None)
        prg.show()
        controller.id_current_function()
        prg.setValue(1)
        prg.close()

        dec_view.refresh_view(False)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    
class IDADAILAController(DAILAController):
    def _decompile(self, func_addr: int, **kwargs):
        try:
            cfunc = ida_hexrays.decompile(func_addr)
        except Exception as e:
            return None

        return str(cfunc)

    def _current_function_addr(self, **kwargs):
        curr_ea = idaapi.get_screen_ea()
        if curr_ea is None:
            return None

        func = idaapi.get_func(curr_ea)
        if func is None:
            return None

        return func.start_ea
    
    def _cmt_func(self, func_addr: int, comment: str, **kwargs):
        idc.set_func_cmt(func_addr, comment, 0)
        return True

    @execute_write
    def id_current_function(self):
        return super().id_current_function()

