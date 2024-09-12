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

RENAME_VARIABLES = f"""
{COT_PREAMBLE}
All experts will be asked to rename the variables in some decompiled C code.
{COT_MIDAMBLE}
The question is how to rename the variables given all the information we got.
Note that the variable name must be descriptive of the variables's purpose and include known algorithms if known.
Use how the variable is used in the function to determine the new name.
{COT_POSTAMBLE}
""" + """
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
## Reasoning
### Expert 1: C Programming Expert

#### Assessment
The function appears to be using the first element of the a0 parameter (likely a pointer or array) to call another 
function sub_404100. It then checks if the result is even by taking modulo 2. The purpose of a0 seems similar to 
the argc parameter in a typical main function, representing the count of elements (arguments). a1 is accessed like an 
array of strings, typical for command line arguments (argv). v1 checks the result of a function call against an even 
condition, making it an "is even" type check.

#### Renaming
a0 -> argc (argument count)
a1 -> argv (argument values)
v1 -> is_even (checks if the result is even)

#### Reasoning
Based on the common C patterns and usage of argc/argv in argument parsing, the names align with conventional usage.


### Expert 2: Reverse Engineering Expert
#### Assessment
From reverse engineering perspectives, the use of a0 and a1 in the function closely mimics command-line argument 
handling, typically seen in programs parsing inputs. The function sub_404100's output is then tested for evenness, 
suggesting a validation or filtering step on input data.

#### Renaming
a0 -> argc
a1 -> argv
v1 -> is_even

#### Reasoning
The pattern fits well-known command-line input processing. The use of modulo operation suggests a straightforward 
validation function.


### Expert 3: Cybersecurity Analyst
#### Assessment
This function checks if a value derived from a set of arguments is even. This check is common in validation routines, 
especially where inputs might affect program flow or data integrity.

#### Renaming:
a0 -> argc (argument count, a potential source of external input)
a1 -> argv (argument values, standard for parsing command line arguments)
v1 -> is_even (indicative of a validation flag)

#### Reasoning
The context aligns with common input validation scenarios in programs handling external inputs, ensuring values conform 
to expected formats (in this case, even numbers).

## Answer
{
    "a0": "argc",
    "a1": "argv",
    "v1": "is_even"
}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

SUMMARIZE_FUNCTION = f"""
{COT_PREAMBLE}
All experts will be asked to summarizes the code. When given code, they summarize at a high level what the function does
and identify if known algorithms are used in the function.
{COT_MIDAMBLE}
The question is how to summarize the function given all the information we got.
Note that the summary must be descriptive of the function's purpose and include known algorithms if known.
{COT_POSTAMBLE}
""" + """
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
## Reasoning
### Expert 1: C Programming Expert
This function, named `sub_404000`, accepts two parameters: an integer `a0` and an array of strings `a1` (char**). 
The function seems to call another function `sub_404100` with the value at `a0[1]`. The return value of this call is 
then checked to see if it's even (`% 2 == 0`). The result of this evaluation (true or false) is assigned to `v1` and 
returned.

### Expert 2: Reverse Engineering Expert
On a high level, the function `sub_404000` performs an operation using another function, `sub_404100`. It evaluates 
whether the result of the `sub_404100` function, called with the second element of an integer array, is even. This 
functionality can be identified as an "even-check" operation. From the look of it, this might correspond to checking 
for a specific condition or behavior related to even numbers.

### Expert 3: Cybersecurity Analyst
The function `sub_404000` appears to be analyzing the nature of the provided input array. By using the result of 
`sub_404100` and evaluating if it is even, it is likely implementing some control mechanism or check that might be 
important in securing an environment, ensuring certain conditions hold before proceeding.

## Answer
{
    "summary": "This function takes two arguments and implements the is_even check on second argument",
    "algorithms": ["is_even"]
}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

IDENTIFY_SOURCE = f"""
{COT_PREAMBLE}
All experts will be asked to identify the original source of the code given a decompilation.
Upon discovering the source, you give a link to the code.
{COT_MIDAMBLE}
Note that the source must be a well-known library or program.
If you do not know the source, of if you are not very confident, please do not guess. 
Provide an empy JSON.
{COT_POSTAMBLE}
""" + """
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
## Reasoning
### Expert 1: C Programming Expert
Given the use of `dcgettext` and `_fprintf_chk`, the function is most likely part of a widely-used GNU program. 
Considering the prevalence and usage context, this function potentially belongs to the GNU Core Utilities package.

### Expert 2: Reverse Engineering Expert
Given further consideration of function names and the general pattern of program design, the program aligns closely 
with GNU Core Utilities, specifically in functionalities related to user guidance and error display.

### Expert 3: Cybersecurity Analyst
Reevaluating the function in the context of command-line tools, the best match is indeed a core utility such as those 
found in the GNU Core Utilities package.

## Answer
{
    "link": "https://www.gnu.org/software/coreutils/"
    "version": ""
}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""
