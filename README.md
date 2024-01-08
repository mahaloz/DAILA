# DAILA 
The Decompiler Artificial Intelligence Language Assistant (DAILA) is a unified interface for AI systems to be used in decompilers.
Using DAILA, you can utilize various AI systems, like local and remote LLMs, all in the same scripting and GUI interfaces.
DAILA was featured in the keynote talk at [HITCON CTM 2023](https://hitcon.org/2023/CMT/en/). 

![](./assets/ida_daila.png)

DAILA provides a lifted interface, relying on the BinSync library [LibBS](https://github.com/binsync/libbs) to abstract away the decompiler.
**All decompilers supported in LibBS are supported in DAILA, which currently includes IDA, Ghidra, Binja, and angr-management.**
Currently, there are two AI systems supported in DAILA: [OpenAI](https://openai.com/) and [VarBERT](https://github.com/binsync/varbert_api), 
the latter of which is a local model for renaming variables in decompilation published in S&P 2024. 
If you are looking for a demo of DAILA, please see the [Demo](#demo) section.

## Installation
Install our library backend through pip and our decompiler plugin through our installer:
```bash
pip3 install dailalib && daila --install 
```

This will also download the VarBERT models for you through the [VarBERT API](https://github.com/binsync/varbert_api).
If you happen to be installing DAILA on a machine that won't have internet access, like a secure network, you can use our Docker image in the [Docker Container](#docker-container) section.

### Ghidra Extra Steps
You need to do a few extra steps to get Ghidra working.
Next, enable the DAILA plugin:
1. Start Ghidra and open a binary
2. Goto the `Windows > Script Manager` menu
3. Search for `daila` and enable the script

You must have `python3` in your path for the Ghidra version to work. We quite literally call it from inside Python 2.
You may also need to enable the `$USER_HOME/ghidra_scripts` as a valid scripts path in Ghidra.

### Manual Install (if above fails)
If the above fails, you will need to manually install.
To manually install, first `pip3 install dailalib` on the repo, then copy the [daila_plugin.py](./dailalib/daila_plugin.py) file to your decompiler's plugin directory.


## Usage
DAILA is designed to be used in two ways:
1. As a decompiler plugin with a GUI
2. As a scripting library in your decompiler

### Decompiler GUI
With the exception of Ghidra (see below), when you start your decompiler you will have a new context menu 
which you can access when you right-click anywhere in a function:

<img src="./assets/ida_daila.png" style="width: 50%;" alt="DAILA context menu"/>

If you are using Ghidra, go to `Tools->DAILA->Start DAILA Backend` to start the backend server.
After you've done this, you can use the context menu as shown above.

### Scripting
You can use DAILA in your own scripts by importing the `dailalib` package.
Here is an example using the OpenAI API:
```python
from dailalib import OpenAIAPI
from libbs.api import DecompilerInterface

deci = DecompilerInterface.discover()
ai_api = OpenAIAPI(decompiler_interface=deci)
for function in deci.functions:
    summary = ai_api.summarize_function(function)
```

### Docker Container
If you are attempting to install DAILA for a one-shot install that will not use the internet after install, like on a secure network, you can use our Docker container.
You should either build the container yourself, save the image to a tarball, and then load it on the target machine, or you can use our pre-built image.
You can build the container yourself by running `docker build -t daila .` in the root of this repo.
You can also download our pre-built image by running `docker pull binsync/daila:latest` (the image is for x86_64 Linux).
The container contains DAILA and a copy of Ghidra.

Now you need to foward X11 to the container so that you can see the GUI.
To do this, you need to run the container with the following flags:
```bash
docker run -it --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix binsync/daila:latest
```

In the container, you can launch ghidra from `/tools/ghidra_10.4_PUBLIC/ghidraRun`.
Now follow the [Ghidra Extra Steps](#ghidra-extra-steps) to enable the DAILA plugin and you're good to go!

## Supported AI Backends
### OpenAI (ChatGPT)
DAILA supports the OpenAI API. To use the OpenAI API, you must have an OpenAI API key.
If your decompiler does not have access to the `OPENAI_API_KEY` environment variable, then you must use the decompiler option from
DAILA to set the API key.

Currently, DAILA supports the following prompts:
- Summarize a function
- Rename variables
- Rename function
- Identify the source of a function

### VarBERT
VarBERT is a local BERT model from the S&P 2024 paper [""Len or index or count, anything but v1": Predicting Variable Names in Decompilation Output with Transfer Learning"]().
VarBERT is for renaming variables (both stack, register, and arguments) in decompilation.
To understand how to use VarBERT as a library, please see the [VarBERT API](https://github.com/binsync/varbert_api) documentation.
Using it in DAILA is a simple as using the GUI context-menu when clicking on a function. 

## Demo
You can find a demo of VarBERT running inside DAILA below:

[![VarBERT Demo](https://img.youtube.com/vi/nUazQm8sFL8/0.jpg)](https://youtu.be/nUazQm8sFL8 "DAILA v2.1.4: Renaming variables with local VarBERT model")


## Supported Decompilers
- IDA
![](./assets/ida_daila.png)

- Binja
![](./assets/binja_daila.png)

- Ghidra
![](./assets/ghidra_daila.png)

- angr management
![](./assets/am_daila.png)