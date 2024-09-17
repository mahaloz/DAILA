from .prompt_type import PromptType, DEFAULT_STYLE, ALL_STYLES
from .prompt import Prompt


class PromptNames:
    RENAME_FUNC = "RENAME_FUNCTION"
    RENAME_VARS = "RENAME_VARIABLES"
    SUMMARIZE_FUNC = "SUMMARIZE_FUNCTION"
    ID_SRC = "IDENTIFY_SOURCE"
    FIND_VULN = "FIND_VULN"
    MAN_PAGE = "MAN_PAGE"


def get_prompt_template(prompt_name, prompt_style):
    if prompt_style in [PromptType.FEW_SHOT, PromptType.ZERO_SHOT]:
        from .few_shot_prompts import (
            RENAME_FUNCTION, RENAME_VARIABLES, SUMMARIZE_FUNCTION, IDENTIFY_SOURCE, FIND_VULN, MAN_PAGE
        )
        d = {
            PromptNames.RENAME_FUNC: RENAME_FUNCTION,
            PromptNames.RENAME_VARS: RENAME_VARIABLES,
            PromptNames.SUMMARIZE_FUNC: SUMMARIZE_FUNCTION,
            PromptNames.ID_SRC: IDENTIFY_SOURCE,
            PromptNames.FIND_VULN: FIND_VULN,
            PromptNames.MAN_PAGE: MAN_PAGE,
        }
    elif prompt_style == PromptType.COT:
        from .cot_prompts import (
            RENAME_FUNCTION, RENAME_VARIABLES, SUMMARIZE_FUNCTION, IDENTIFY_SOURCE, FIND_VULN, MAN_PAGE
        )
        d = {
            PromptNames.RENAME_FUNC: RENAME_FUNCTION,
            PromptNames.RENAME_VARS: RENAME_VARIABLES,
            PromptNames.SUMMARIZE_FUNC: SUMMARIZE_FUNCTION,
            PromptNames.ID_SRC: IDENTIFY_SOURCE,
            PromptNames.FIND_VULN: FIND_VULN,
            PromptNames.MAN_PAGE: MAN_PAGE,
        }
    else:
        raise ValueError("Invalid prompt style")

    return d.get(prompt_name, None)


PROMPTS = [
    Prompt(
        "summarize",
        PromptNames.SUMMARIZE_FUNC,
        desc="Summarize this function",
        response_key="summary",
        gui_result_callback=Prompt.comment_function
    ),
    Prompt(
        "identify_source",
        PromptNames.ID_SRC,
        desc="Identify the source of this function",
        response_key="link",
        gui_result_callback=Prompt.comment_function
    ),
    Prompt(
        "rename_variables",
        PromptNames.RENAME_VARS,
        desc="Suggest variable names",
        gui_result_callback=Prompt.rename_variables
    ),
    Prompt(
        "rename_function",
        PromptNames.RENAME_FUNC,
        desc="Suggest a function name",
        gui_result_callback=Prompt.rename_function
    ),
    Prompt(
        "find_vulnerabilities",
        PromptNames.FIND_VULN,
        desc="Find vulnerabilities in this function",
        gui_result_callback=Prompt.comment_vulnerability
    ),
    Prompt(
        "man_page",
        PromptNames.MAN_PAGE,
        desc="Summarize library call man page",
        gui_result_callback=Prompt.comment_man_page
    ),
]
