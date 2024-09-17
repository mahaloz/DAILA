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


FIND_VULN = f"""
{COT_PREAMBLE}
All experts will be asked to identify vulnerabilities or bugs in code. When given code, you identify 
vulnerabilities and specify the type of vulnerability. Only identify the MOST important vulnerabilities in the code.
Ignore bugs like resource leaks.
{COT_MIDAMBLE}
The question is how to identify vulnerabilities in the code given all the information we got.
Note that the vulnerabilities must be specific and include the line numbers where they occur. If you are unsure
of the vulnerability, please do not guess.
{COT_POSTAMBLE}
""" + """
# Example 
Here is an example. Given the following code:
```
1 int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
2 {
3   Human *v3; // rbx
4   __int64 v4; // rdx
5   Human *v5; // rbx
6   int v6; // eax
7   __int64 v7; // rax
8   Human *v8; // rbx
9   Human *v9; // rbx
10   char v10[16]; // [rsp+10h] [rbp-50h] BYREF
11   char v11[8]; // [rsp+20h] [rbp-40h] BYREF
12   Human *v12; // [rsp+28h] [rbp-38h]
13   Human *v13; // [rsp+30h] [rbp-30h]
14   size_t nbytes; // [rsp+38h] [rbp-28h]
15   void *buf; // [rsp+40h] [rbp-20h]
16   int v16; // [rsp+48h] [rbp-18h] BYREF
17   char v17; // [rsp+4Eh] [rbp-12h] BYREF
18   char v18[17]; // [rsp+4Fh] [rbp-11h] BYREF
19
20   std::allocator<char>::allocator(&v17, argv, envp);
21   std::string::string(v10, "Jack", &v17);
22   v3 = (Human *)operator new(0x18uLL);
23   Man::Man(v3, v10, 25LL);
24   v12 = v3;
25   std::string::~string((std::string *)v10);
26   std::allocator<char>::~allocator(&v17);
27   std::allocator<char>::allocator(v18, v10, v4);
28   std::string::string(v11, "Jill", v18);
29   v5 = (Human *)operator new(0x18uLL);
30   Woman::Woman(v5, v11, 21LL);
31   v13 = v5;
32   std::string::~string((std::string *)v11);
33   std::allocator<char>::~allocator(v18);
34   while ( 1 )
35   {
36     while ( 1 )
37     {
38       while ( 1 )
39       {
40         std::operator<<<std::char_traits<char>>(&std::cout, "1. use
41 2. after
42 3. free
43 ");
44         std::istream::operator>>(&std::cin, &v16);
45         if ( v16 != 2 )
46           break;
47         nbytes = atoi(argv[1]);
48         buf = (void *)operator new[](nbytes);
49         v6 = open(argv[2], 0);
50         read(v6, buf, nbytes);
51         v7 = std::operator<<<std::char_traits<char>>(&std::cout, "your data is allocated");
52         std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
53       }
54       if ( v16 == 3 )
55         break;
56       if ( v16 == 1 )
57       {
58         (*(void (__fastcall **)(Human *))(*(_QWORD *)v12 + 8LL))(v12);
59         (*(void (__fastcall **)(Human *))(*(_QWORD *)v13 + 8LL))(v13);
60       }
61     }
62     v8 = v12;
63     if ( v12 )
64     {
65       Human::~Human(v12);
66       operator delete(v8);
67     }
68     v9 = v13;
69     if ( v13 )
70     {
71       Human::~Human(v13);
72       operator delete(v9);
73     }
74   }
75 }
```

You would respond with:
## Reasoning
### Expert 1: C/C++ Programming Expert  
**Assessment**: The first vulnerability I notice is a potential use-after-free. Specifically, in lines 62-73, there are 
deletions of the `v12` and `v13` objects. If the program re-enters this loop and tries to access these pointers without 
proper reallocation, it will result in undefined behavior due to accessing freed memory. Additionally, lines 47-50 have 
potential for buffer overflow. The size `nbytes` from `argv[1]` is used directly without any checks. If `argv[1]` is a 
very large value, it can cause excessive allocation or even wrap around to a small value, potentially leading to an 
overflow when reading data.

### Expert 2: Reverse Engineering Expert  
**Assessment**: One main issue is the use-after-free vulnerability in lines 62-73. Freeing `v12` and `v13` and then 
potentially accessing them in subsequent iterations is problematic. This vulnerability can be exploited to crash the 
program or execute arbitrary code. The second notable vulnerability is the insecure handling of `nbytes` in lines 
47-50. Without validation, there's a risk that this unbounded value could lead to buffer overflow or memory corruption, 
especially if `argv[1]` holds a negative or excessively large number.

### Expert 3: Cybersecurity Analyst  
**Assessment**: The use-after-free in lines 62-73 stands out as particularly severe. If the pointers `v12` and `v13` 
are accessed after being freed, it can lead to security breaches or application crashes. Another critical point is the 
lack of validation for `nbytes` in lines 47-50, which can potentially cause buffer overflow. This lack of sanitization 
makes the application prone to memory corruption, which can be a severe security issue and possibly exploitable.

## Answer
{
    "vulnerabilities": ["use-after-free (62-73)", "buffer-overflow (47-50)"]
    "description": "The code contains a classic use-after-free vulnerability. In lines 62-73, the pointers v12 and v13 (which point to objects of type Human) are deleted (freed) using operator delete. If the program's loop (lines 34-74) executes again and the pointers v12 or v13 are accessed without reallocation, it results in undefined behavior due to use-after-free. In lines 47-50, the code reads a size value from argv[1] and uses it directly with operator new[] to allocate a buffer (buf). There are no checks to ensure that nbytes is a reasonable size, potentially leading to a large allocation or integer overflow."
}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

MAN_PAGE = f"""
{COT_PREAMBLE}
All experts will be asked to write a summarized man page for a function in a decompiled C code.
These summaries should include arg and return information as well as types.
The focal point will be on a function call (that is a library) inside this function. 
{COT_MIDAMBLE}
The question is how to write a summarized man page for the target function given all the information we got.
A focal line will be given to do analysis on.
{COT_POSTAMBLE}
""" + """
# Example 
Here is an example, given the following code as context:
```
void __fastcall gz_error(__int64 a1, int a2, const char *a3)
{
  void *v5; // rcx
  __int64 v7; // rbx
  __int64 v8; // rax
  __int64 v9; // rcx
  char *v10; // rax
  char *v11; // rcx
  const char *v12; // r9
  __int64 v13; // rax

  v5 = *(void **)(a1 + 120);
  if ( v5 )
  {
    if ( *(_DWORD *)(a1 + 116) != -4 )
      free(v5);
    *(_QWORD *)(a1 + 120) = 0LL;
  }
  if ( a2 && a2 != -5 )
    *(_DWORD *)a1 = 0;
  *(_DWORD *)(a1 + 116) = a2;
  if ( a3 && a2 != -4 )
  {
    v7 = -1LL;
    v8 = -1LL;
    do
      ++v8;
    while ( *(_BYTE *)(*(_QWORD *)(a1 + 32) + v8) );
    v9 = -1LL;
    do
      ++v9;
    while ( a3[v9] );
    v10 = (char *)malloc(v8 + 3 + v9);
    *(_QWORD *)(a1 + 120) = v10;
    v11 = v10;
    if ( v10 )
    {
      v12 = *(const char **)(a1 + 32);
      v13 = -1LL;
      while ( v12[++v13] != 0 )
        ;
      do
        ++v7;
      while ( a3[v7] );
      snprintf(v11, v7 + v13 + 3, "%s%s%s", v12, ": ", a3);
    }
    else
    {
      *(_DWORD *)(a1 + 116) = -4;
    }
  }
}
```

You focus on the line in the above text:
```
      snprintf(v11, v7 + v13 + 3, "%s%s%s", v12, ": ", a3);
```

Focusing on the outermost function call in this line, you respond with:
## Reasoning
### Expert 1: C Programming Expert
### Expert 2: Reverse Engineering Expert
### Expert 3: Cybersecurity Analyst

## Answer
{
    "function": "snprintf",
    "args": ["str (char *)", "size (size_t)", "format (const char *)", "..."],
    "return": "int",
    "description": "The snprintf() function formats and stores a series of characters and values in the array buffer. It is similar to printf(), but with two major differences: it outputs to a buffer rather than stdout, and it takes an additional size parameter specifying the limit of characters to write. The size parameter prevents buffer overflows. It returns the number of characters that would have been written if the buffer was sufficiently large, not counting the terminating null character."
}

# Example
Given the following code as context:
```
{{ decompilation }} 
```

You focus on the line in the above text:
```
{{ line_text }}
```

Focusing on the outermost function call in this line, you respond with:
"""
