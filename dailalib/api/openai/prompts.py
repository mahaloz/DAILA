import typing

from libbs.artifacts import Comment

from .prompt import Prompt

if typing.TYPE_CHECKING:
    from dailalib.api import AIAPI


def rename_function(result, function, ai_api: "AIAPI"):
    new_name = list(result.values())[0]
    function.name = new_name
    ai_api._dec_interface.functions[function.addr] = function


def rename_variables(result, function, ai_api: "AIAPI"):
    ai_api._dec_interface.rename_local_variables_by_names(function, result)


def comment_function(result, function, ai_api: "AIAPI"):
    ai_api._dec_interface.comments[function.addr] = Comment(function.addr, comment=result, func_addr=function.addr)


PROMPTS = [
    Prompt(
        "summarize",
        f'''
        You are C expert that summarizes code. When given code, you summarize at a high level what the function does 
        and you identify if known algorithms are used in the function. As an example:
        """
        int sub_404000(int a0, char** a1) 
        {{
            int v1; // rax 
            v1 = sub_404100(a0[1]) % 2 == 0 
            return v1;
        }}
        """

        You responded with:
        This function takes two arguments and implements the is_even check on second argument

        Here is another example:
        {Prompt.DECOMP_TEXT}

        You responded with:
        ''',
        desc="Summarize the function",
        gui_result_callback=comment_function
    ),
    Prompt(
        "identify_source",
        f'''
        You are a C expert that identifies the original source given decompilation. Upon discovering the source,
        you give a link to the code. You only respond with a json. As an example:
        """
        void __fastcall __noreturn usage(int status)
        {{
            v2 = program_name;
            if ( status )
            {{
                v3 = dcgettext(0LL, "Try '%s --help' for more information.\n", 5);
                _fprintf_chk(stderr, 1LL, v3, v2);
            }}
            // ...
        }}
        """

        You responded with:
        {{"link": "https://www.gnu.org/software/coreutils/"}}

        When you don't know, you respond with {{}}.

        Here is another example:
        {Prompt.DECOMP_TEXT}

        You responded with:
        ''',
        desc="Identify the original source",
        json_response=True,
        gui_result_callback=comment_function
    ),
    Prompt(
        "rename_variables",
        f'''
        You are C expert that renames variables in code. When given code, you rename variables according to the
        meaning of the function or its use. You only respond with a json. As an example:

        int sub_404000(int a0, char** a1) 
        {{
            int v1; // rax 
            v1 = sub_404100(a0[1]) % 2 == 0 
            return v1;
        }}

        You responded with:
        {{"a0: argc", "a1: argv",  "v1": "is_even"}}

        Here is another example:
        {Prompt.DECOMP_TEXT}

        You responded with:
        ''',
        desc="Suggest variable names",
        json_response=True,
        gui_result_callback=rename_variables,
    ),
    Prompt(
        "rename_function",
        f'''
        You are C expert that renames functions. When given a function, you rename it according to the
        meaning of the function or its use. You only respond with a json. As an example:

        int sub_404000(int a0, char** a1) 
        {{
            int is_even; // rax 
            is_even = sub_404100(a0[1]) % 2 == 0 
            return is_even;
        }}

        You responded with:
        {{"sub_404000": "number_is_even"}}

        Here is another example:
        {Prompt.DECOMP_TEXT}

        You responded with:
        ''',
        desc="Suggest a function name",
        json_response=True,
        gui_result_callback=rename_function
    ),
]
PROMPTS_BY_NAME = {p.name: p for p in PROMPTS}
