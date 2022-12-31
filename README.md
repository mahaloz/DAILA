# DAILA 
Decompiler Artificial Intelligence Language Assistant - Built on OpenAI.
Utilize OpenAI to improve your decompilation experience in most modern decompilers.

![](./assets/ida_daila.png)

## Installation
Clone down this repo and pip install and use the daila installer:
```bash
pip3 install -e . && daila --install 
```

Depending on your decompiler, this will attempt to copy the script files into your decompiler and install
the DAILA core to your current Python. If you are using Binja or IDA, make sure your Python is the same 
as the one you are using in your decompiler. 

If you are using Ghidra, you may be required to enable the `$USER_HOME/ghidra_scripts` as a valid 
scripts path. 

If your decompiler does not have access to the `OPENAI_API_KEY`, then you must use the decompiler option from
DAILA to set the API key. A popup will appear for you to enter your key. 

### Manual Install
If the above fails, you will need to manually install.
To manually install, first `pip3 install -e .` on the repo, then copy the python file for your decompiler in your 
decompilers plugins/scripts folder. 

### Ghidra Gotchas
You must have `python3` in your path for the Ghidra version to work. We quite literally call it from inside Python 2.

## Usage
In your decompiler you can access the DAILA options in one of two ways:
1. If you are not in Ghidra, you can right-click a function and go to `Plugins` or directly use the `DAILA ...` menu.
2. If you are in Ghidra, use `Tools->DAILA` then use the operation selector

All operations that DAILA can perform can be found from the DAILA context menu, which in some decompilers may just be 
the menu described above.

![](./assets/ida_show_menu_daila.png)

Comments will appear in the function header with the response or an error message.

## Supported Decompilers
- IDA
![](./assets/ida_daila.png)

- Binja
![](./assets/binja_daila.png)

- Ghidra
![](./assets/ghidra_daila.png)

## Features
### Function Identification
We use ChatGPT to attempt to:
1. Identify which open-source project this decompilation could be a result of 
2. Find a link to that said source if it exists 

### Function Summarization
Summarizes in human-readable text what this function does

### Vulnerability Detection
Attempts to find and describe the vulnerability in the function 