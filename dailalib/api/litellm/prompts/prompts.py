RENAME_FUNCTION = """
# Task
You are decompiled C expert that renames functions. When given a function, you rename it according to the
meaning of the function or its use. You specify which function you are renaming by its name.

You only respond with a valid json. As an example:
{
    "sub_404000": "fibonacci",
}

{% if few_shot %}
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
{
    "sub_404000": "is_even",
    "sub_404100": "get_value",
}
{% endif %}

# Example
Given the following code:
```
{{ decompilation }}
```

You respond with:
"""

RENAME_VARIABLES = """
# Task
You are decompiled C expert that renames variables in code. When given code, you rename variables according to the
meaning of the function or its use.

You only respond with a valid json. As an example:
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

SUMMARIZE_FUNCTION = """
# Task
You are decompiled C expert that summarizes code. When given code, you summarize at a high level what the function does
and you identify if known algorithms are used in the function.

You always respond with a valid json:
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

IDENTIFY_SOURCE = """
# Task
You are a decompiled C expert that identifies the original source given decompilation. Upon discovering the source,
you give a link to the code.

You only respond with a valid json. As an example:
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