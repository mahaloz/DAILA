import logging

from libbs.api import DecompilerInterface
from libbs.decompilers import IDA_DECOMPILER, ANGR_DECOMPILER, BINJA_DECOMPILER, GHIDRA_DECOMPILER

from ..api import AIAPI

_l = logging.getLogger(__name__)


def get_llm_chat_creator(ai_api: AIAPI) -> callable:
    # determine the current decompiler
    current_decompiler = DecompilerInterface.find_current_decompiler()
    add_llm_chat_to_ui = lambda *args, **kwargs: None
    if current_decompiler == IDA_DECOMPILER:
        from dailalib.llm_chat.ida import add_llm_chat_to_ui
    elif current_decompiler == BINJA_DECOMPILER:
        from dailalib.llm_chat.binja import add_llm_chat_to_ui
    else:
        _l.warning(f"LLM Chat not supported for decompiler %s", current_decompiler)

    def llm_chat_creator_wrapper(*args, **kwargs):
        ai_api.info(f"Opening LLM Chat with model {ai_api.model}...")
        return add_llm_chat_to_ui(ai_api=ai_api, *args, **kwargs)

    return llm_chat_creator_wrapper
