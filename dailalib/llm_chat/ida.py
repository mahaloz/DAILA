import logging

from PyQt5 import sip
from PyQt5.QtWidgets import QWidget, QVBoxLayout

import idaapi

from libbs.ui.version import set_ui_version
set_ui_version("PyQt5")

from dailalib.llm_chat.llm_chat_ui import LLMChatClient

_l = logging.getLogger(__name__)

# disable the annoying "Running Python script" wait box that freezes IDA at times
idaapi.set_script_timeout(0)


class LLMChatWrapper(object):
    NAME = "LLM Chat"

    def __init__(self, ai_api, context=None):
        # create a dockable view
        self.twidget = idaapi.create_empty_widget(LLMChatWrapper.NAME)
        self.widget = sip.wrapinstance(int(self.twidget), QWidget)
        self.widget.name = LLMChatWrapper.NAME
        self.width_hint = 250

        self._ai_api = ai_api
        self._context = context
        self._w = None

        self._init_widgets()

    def _init_widgets(self):
        self._w = LLMChatClient(self._ai_api, context=self._context)
        layout = QVBoxLayout()
        layout.addWidget(self._w)
        layout.setContentsMargins(2,2,2,2)
        self.widget.setLayout(layout)


def add_llm_chat_to_ui(*args, ai_api=None, context=None, **kwargs):
    """
    Open the control panel view and attach it to IDA View-A or Pseudocode-A.
    """
    wrapper = LLMChatWrapper(ai_api, context=context)
    if not wrapper.twidget:
        _l.info("Unable to find a widget to attach to. You are likely running headlessly")
        return None

    flags = idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST
    idaapi.display_widget(wrapper.twidget, flags)
    wrapper.widget.visible = True
    target = "Pseudocode-A"
    dwidget = idaapi.find_widget(target)

    if not dwidget:
        target = "IDA View-A"

    idaapi.set_dock_pos(LLMChatWrapper.NAME, target, idaapi.DP_RIGHT)
