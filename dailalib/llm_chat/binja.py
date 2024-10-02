from binaryninjaui import (
    UIContext,
    DockHandler,
    DockContextHandler,
    UIAction,
    UIActionHandler,
    Menu,
)

import traceback
import sys
import logging

from PySide6.QtWidgets import (
    QDockWidget,
    QWidget,
    QApplication,
    QMenu,
    QMainWindow,
    QMenuBar, QVBoxLayout,
)
from PySide6.QtCore import Qt
from binaryninjaui import DockContextHandler
import binaryninja

from .llm_chat_ui import LLMChatClient
from ..api import AIAPI

_l = logging.getLogger(__name__)

# this code is based on:
# https://github.com/binsync/binsync/blob/fa754795b7d55e4b5de4e12ea7d4b5f9706c23af/plugins/binja_binsync/binja_binsync.py

def find_main_window():
    main_window = None
    for x in QApplication.allWidgets():
        if not isinstance(x, QDockWidget):
            continue
        main_window = x.parent()
        if isinstance(main_window, (QMainWindow, QWidget)):
            break
        else:
            main_window = None

    if main_window is None:
        # oops cannot find the main window
        raise Exception("Main window is not found.")
    return main_window


dockwidgets = [ ]


# shamelessly copied from https://github.com/Vector35/debugger
def create_widget(widget_class, name, parent, data, *args):
    # It is imperative this function return *some* value because Shiboken will try to deref what we return
    # If we return nothing (or throw) there will be a null pointer deref (and we won't even get to see why)
    # So in the event of an error or a nothing, return an empty widget that at least stops the crash
    try:
        # binsync specific code
        if not isinstance(data, binaryninja.BinaryView):
            raise Exception('expected an binary view')
        new_bv = args[0]
        # uses only a bv_controller
        widget = widget_class(new_bv, parent=parent, name=name, data=data)
        if not widget:
            raise Exception('expected widget, got None')

        global dockwidgets

        found = False
        for (bv, widgets) in dockwidgets:
            if bv == data:
                widgets[name] = widget
                found = True

        if not found:
            dockwidgets.append((data, {
                name: widget
            }))

        widget.destroyed.connect(lambda destroyed: destroy_widget(destroyed, widget, data, name))

        return widget
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return QWidget(parent)


def destroy_widget(destroyed, old, data, name):
    # Gotta be careful to delete the correct widget here
    for (bv, widgets) in dockwidgets:
        if bv == data:
            for (name, widget) in widgets.items():
                if widget == old:
                    # If there are no other references to it, this will be the only one and the call
                    # will delete it and invoke __del__.
                    widgets.pop(name)
                    return


class BinjaWidgetBase:
    def __init__(self):
        self._main_window = None
        self._menu_bar = None
        self._tool_menu = None

    @property
    def main_window(self):
        if self._main_window is None:
            self._main_window = find_main_window()
        return self._main_window

    @property
    def menu_bar(self):
        if self._menu_bar is None:
            self._menu_bar = next(
                iter(x for x in self._main_window.children() if isinstance(x, QMenuBar))
            )
        return self._menu_bar

    @property
    def tool_menu(self):
        if self._tool_menu is None:
            self._tool_menu = next(
                iter(
                    x
                    for x in self._menu_bar.children()
                    if isinstance(x, QMenu) and x.title() == u"Tools"
                )
            )
        return self._tool_menu

    def add_tool_menu_action(self, name, func):
        self.tool_menu.addAction(name, func)


class BinjaDockWidget(QWidget, DockContextHandler):
    def __init__(self, name, parent=None):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)

        self.base = BinjaWidgetBase()

        self.show()

    def toggle(self):
        if self.isVisible():
            self.hide()
        else:
            self.show()


class BinjaWidget(QWidget):
    def __init__(self, tabname):
        super(BinjaWidget, self).__init__()


class LLMChatClientDockWidget(BinjaDockWidget):
    def __init__(self, ai_api, parent=None, name=None, data=None):
        super().__init__(name, parent=parent)
        self.data = data
        self._widget = None
        self.ai_api = ai_api

        self._widget = LLMChatClient(self.ai_api)
        layout = QVBoxLayout()
        layout.addWidget(self._widget)
        self.setLayout(layout)


def add_llm_chat_to_ui(*args, ai_api: AIAPI = None, **kwargs):
    # control panel (per BV)
    dock_handler = DockHandler.getActiveDockHandler()
    dock_handler.addDockWidget(
        "LLM Chat",
        lambda n, p, d: create_widget(LLMChatClientDockWidget, n, p, d, ai_api._dec_interface.bv),
        Qt.RightDockWidgetArea,
        Qt.Vertical,
        True
    )