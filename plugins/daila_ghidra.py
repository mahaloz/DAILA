# Activates DAILA Identification on the current function you are viewing
#@category AI
#@menupath Tools.DAILA: Identify Function
#@keybinding ctrl alt shift i

import xmlrpclib
from time import sleep
import subprocess

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

fpapi = FlatProgramAPI(getState().getCurrentProgram())
fdapi = FlatDecompilerAPI(fpapi)


def current_func():
    func = fpapi.getFunctionContaining(currentAddress)
    return func if func else None


def decompile_curr_func():
    func = current_func()
    if func is None:
        return None

    decomp = fdapi.decompile(func)
    if not decomp:
        return None

    return str(decomp)


def set_func_comment(comment):
    func = current_func()
    if func is None:
        return False

    func.setComment(comment)
    return True


def request_identification():
    server = xmlrpclib.ServerProxy('http://localhost:44414')
    try:
        server.ping()
    except BaseException as e:
        print("[!] Encountered an error when creating the py3 server", e)
        return None

    decomp = decompile_curr_func()
    if decomp is None:
        return None

    resp = server.identify_function(decomp)
    if not resp:
        return None

    set_func_comment(resp)
    server.shutdown()


def start_server():
    return subprocess.Popen(["python3", "-m", "daila", "-server"])


def identify_function():
    server_proc = start_server()
    sleep(1)
    try:
        request_identification()
    except Exception as e:
        print("Exception occurred", e)
    server_proc.kill()


if __name__ == "__main__":
    print("[+] Starting identification of function " + str(current_func()))
    identify_function()
    print("[+] Finished")
