#
# Common prompt types for Chain of Thought (COT) tasks.
# These are usually implemented as a single prompt with 3-expert chain of thought.
#

COT_PREAMBLE = """
# TASK
Identify and behave as three different experts that are appropriate to answering this question.

"""

COT_MIDAMBLE = """
All experts will write down their assessment of the function and their reasoning, then share it with the group.
Then, all experts will move on to the next stage, and so on.
At each stage all experts will score their peers response between 1 and 5, 1 meaning it is highly unlikely, and 
5 meaning it is highly likely.
If any expert is judged to be wrong at any point then they leave.
After all experts have provided their analysis, you then analyze all 3 analyses and provide either the consensus
solution or your best guess solution.

"""

COT_POSTAMBLE = """

When the three experts all agree, give us the final name of the function as a JSON.
The three experts must provide a conclusion after two stages, regardless of whether they achieve agreement.

If you proposal is accepted, you will be rewarded with a flag.
No yapping! 
You MUST eventually finish with a valid JSON as shown in the example shown below! 
"""

#
# Prompts
#

RENAME_FUNCTION = f"""
{COT_PREAMBLE}
All experts will be asked to rename a function in a decompiled C code.
{COT_MIDAMBLE}
The question is how to rename the function given all the information we got.
Note that the function name must be descriptive of the function's purpose and include known algorithms if known.
{COT_POSTAMBLE}
""" + """
# Example
Here is an example. Given the following code:
```
int sub_404000(int a0, char** a1)
{
    int is_even; // rax

    is_even = sub_404100(a0[1]) % 2 == 0
    return is_even;
}
```

You respond with:
## Reasoning
### Expert 1: C Programming Expert
#### Assessment
The function sub_404000 takes an integer and an array of strings as inputs.
It calls another function, sub_404100, passing the second element of the array.
The return value of sub_404100 is then checked for evenness by taking the modulus with 2.
This suggests that sub_404000 checks if the value obtained is even.

#### Proposed Rename
sub_404000: check_is_even
sub_404100: get_integer_value

#### Reasoning
The function seems to be performing a check for evenness, hence check_is_even.
Since sub_404100 retrieves a value used for checking evenness, get_integer_value is a descriptive name.

### Expert 2: Reverse Engineering Expert
#### Assessment
The function sub_404000 is performing a comparison operation to determine if a value is even.
sub_404100 is a retrieval function that operates on the second argument, possibly transforming or extracting an integer from the string array.

#### Proposed Rename
sub_404000: is_value_even
sub_404100: extract_number_from_string

#### Reasoning
is_value_even directly states the purpose of checking for evenness.
extract_number_from_string describes the possible action of sub_404100 more explicitly.

### Expert 3: Cybersecurity Analyst
#### Assessment
The function sub_404000 appears to validate evenness, possibly related to input sanitization or checking.
sub_404100 processes a string input to produce an integer, which may relate to a value extraction or parsing routine.

#### Proposed Rename
sub_404000: validate_even_value
sub_404100: parse_integer

#### Reasoning
validate_even_value reflects the validation aspect of checking evenness.
parse_integer suggests a parsing operation, likely suitable for a function handling string to integer conversion.

## Answer
{
    "sub_404000": "is_value_even",
    "sub_404100": "get_integer_value"
}

Notice the format of the answer at the end. You must provide a JSON object with the function names and their 
proposed new names.

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

# TODO: finish me
RENAME_VARIABLES = """
# Task
You are decompiled C expert that renames variables in code. When given code, you rename variables according to the
meaning of the function or its use.

You eventually respond with a valid json. As an example:
## Answer 
{
  "v1": "i",
  "v2": "ptr"
}

{% if few_shot %}
# Example
Here is an example. Given the following code:
```
int sub_404000(int a0, char** a1)
{
    int v1; // rax

    v1 = sub_404100(a0[1]) % 2 == 0
    return v1;
}
```

You responded with:
## Answer
{
    "a0": "argc",
    "a1": "argv",
    "v1": "is_even"
}
{% endif %}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

# TODO: finish me
SUMMARIZE_FUNCTION = """
# Task
You are decompiled C expert that summarizes code. When given code, you summarize at a high level what the function does
and you identify if known algorithms are used in the function.

You eventually respond with a valid json. As an example:
## Answer 
{
    "summary": "This function computes the fibonacci sequence. It takes an integer as an argument and returns the fibonacci number at that index.",
    "algorithms": ["fibonacci"]
}

{% if few_shot %}
# Example
Here is an example. Given the following code:
```
int sub_404000(int a0, char** a1)
{
    int v1; // rax
    v1 = sub_404100(a0[1]) % 2 == 0
    return v1;
}
```

You responded with:
## Answer
{
    "summary": "This function takes two arguments and implements the is_even check on second argument",
    "algorithms": ["is_even"]
}
{% endif %}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

# TODO: finish me
IDENTIFY_SOURCE = """
# Task
You are a decompiled C expert that identifies the original source given decompilation. Upon discovering the source,
you give a link to the code.

You eventually respond with a valid json. As an example:
## Answer 
{
  "link": "https://github.com/torvalds/linux"
  "version": "5.10"
}

{% if few_shot %}
# Example
Here is an example. Given the following code:
```
void __fastcall __noreturn usage(int status)
{
    v2 = program_name;
    if ( status )
    {
        v3 = dcgettext(0LL, "Try '%s --help' for more information.\n", 5);
        _fprintf_chk(stderr, 1LL, v3, v2);
    }
    // ...
}
```

You would respond with:
## Answer
{
    "link": "https://www.gnu.org/software/coreutils/"
    "version": ""
}
{% endif %}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""
