from pathlib import Path
from .prompt_type import PromptType, DEFAULT_STYLE, ALL_STYLES
from .prompt import Prompt
from .prompts import SUMMARIZE_FUNCTION, IDENTIFY_SOURCE, RENAME_FUNCTION, RENAME_VARIABLES

FILE_DIR = Path(__file__).absolute().parent

PROMPTS = [
    Prompt(
        "summarize",
        SUMMARIZE_FUNCTION,
        desc="Summarize the function",
        response_key="summary",
        gui_result_callback=Prompt.comment_function
    ),
    Prompt(
        "identify_source",
        IDENTIFY_SOURCE,
        desc="Identify the source of the function",
        response_key="link",
        gui_result_callback=Prompt.comment_function
    ),
    Prompt(
        "rename_variables",
        RENAME_VARIABLES,
        desc="Suggest variable names",
        gui_result_callback=Prompt.rename_variables
    ),
    Prompt(
        "rename_function",
        RENAME_FUNCTION,
        desc="Suggest a function name",
        gui_result_callback=Prompt.rename_function
    ),
]
