from pathlib import Path
from .prompt_type import PromptType, DEFAULT_STYLE, ALL_STYLES
from .prompt import Prompt

FILE_DIR = Path(__file__).absolute().parent


def load_prompts():
    template_texts = {}
    for prompt_path in FILE_DIR.glob("*.j2"):
        with open(prompt_path, "r") as f:
            template_texts[prompt_path.stem] = f.read()

    return [
        Prompt(
            "summarize",
            template_texts["summarize"],
            desc="Summarize the function",
            response_key="summary",
            gui_result_callback=Prompt.comment_function
        ),
        Prompt(
            "identify_source",
            template_texts["identify_source"],
            desc="Identify the source of the function",
            response_key="link",
            gui_result_callback=Prompt.comment_function
        ),
        Prompt(
            "rename_variables",
            template_texts["rename_variables"],
            desc="Suggest variable names",
            gui_result_callback=Prompt.rename_variables
        ),
        Prompt(
            "rename_function",
            template_texts["rename_function"],
            desc="Suggest a function name",
            gui_result_callback=Prompt.rename_function
        ),
    ]


PROMPTS = load_prompts()
