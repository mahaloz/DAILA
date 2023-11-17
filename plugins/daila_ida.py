import threading
import functools
from typing import Optional, Dict

import idaapi
import ida_hexrays
import idc
from PyQt5.QtWidgets import QProgressDialog

from dailalib.ai_api.openai_api import OpenAIAPI

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

    id_action_name = "dailalib:identify_function"
    id_menu_path = "Edit/DAILA/Explain function"

    def __init__(self, *args, **kwargs):
        print("[DAILA] loaded!")
        self.controller = IDADAILAController()


    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        self.controller.hook_menu()
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        pass

    def term(self):
        pass


class ContextMenuHooks(idaapi.UI_Hooks):
    def __init__(self, *args, menu_strs=None, **kwargs):
        idaapi.UI_Hooks.__init__(self)
        self.menu_strs = menu_strs or []

    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            for menu_str in self.menu_strs:
                #idaapi.attach_action_to_popup(form, popup, DAILAPlugin.id_action_name, "DAILA/")
                idaapi.attach_action_to_popup(form, popup, menu_str, "DAILA/")


class GenericAction(idaapi.action_handler_t):
    def __init__(self, action_target, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_target = action_target
        self.action_function = action_function

    def activate(self, ctx):
        if ctx is None or ctx.action != self.action_target:
            return

        dec_view = ida_hexrays.get_widget_vdui(ctx.widget)
        # show a thing while we query
        prg = QProgressDialog("Querying AI...", "Stop", 0, 1, None)
        prg.show()

        self.action_function()

        # close the panel we showed while running
        prg.setValue(1)
        prg.close()

        dec_view.refresh_view(False)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class IDADAILAController(OpenAIAPI):
    def __init__(self):
        self.menu_actions = []
        super().__init__(self)
        self.menu = None

    def _decompile(self, func_addr: int, **kwargs):
        try:
            cfunc = ida_hexrays.decompile(func_addr)
        except Exception:
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

    def _rename_variables_by_name(self, func_addr: int, names: Dict[str, str]):
        dec = idaapi.decompile(func_addr)
        if dec is None:
            return False

        lvars = {
            lvar.name: lvar for lvar in dec.get_lvars() if lvar.name
        }
        update = False
        for name, lvar in lvars.items():
            new_name = names.get(name, None)
            if new_name is None:
                continue

            lvar.name = new_name
            update |= True

        if update:
            dec.refresh_func_ctext()

        return update

    def _register_menu_item(self, name, action_string, callback_func):
        # Function explaining action
        explain_action = idaapi.action_desc_t(
            name,
            action_string,
            GenericAction(name, callback_func),
            "",
            action_string,
            199
        )
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(f"Edit/DAILA/{name}", name, idaapi.SETMENU_APP)
        self.menu_actions.append(name)

    def hook_menu(self):
        self.menu = ContextMenuHooks(menu_strs=self.menu_actions)
        self.menu.hook()

    def ask_api_key(self, *args, **kwargs):
        resp = idaapi.ask_str(self.api_key if isinstance(self.api_key, str) else "", 0, "Enter you OpenAI API Key: ")
        if resp is None:
            return

        self.api_key = resp

    @execute_write
    def identify_current_function(self):
        return super().identify_current_function()

    @execute_write
    def explain_current_function(self, **kwargs):
        return super().explain_current_function(**kwargs)
