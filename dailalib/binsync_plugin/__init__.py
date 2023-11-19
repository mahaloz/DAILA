from pathlib import Path
import argparse
import subprocess
import sys

from dailalib.binsync_plugin.ai_bs_user import AIBSUser
from dailalib.binsync_plugin.openai_bs_user import OpenAIBSUser
from dailalib.binsync_plugin.varmodel_bs_user import VARModelBSUser


def add_ai_user_to_project(
    openai_api_key: str, binary_path: Path, bs_proj_path: Path, username: str = AIBSUser.DEFAULT_USERNAME,
    base_on=None, headless=False, copy_proj=False, decompiler_backend=None, model=None, controller=None, progress_callback=None,
    range_str="", arch=None
):
    if headless:
        _headlessly_add_ai_user(openai_api_key, binary_path, bs_proj_path, username=username, decompiler_backend=decompiler_backend, base_on=base_on, model=model, arch=arch)
    else:
        if model is None or model.startswith("gpt"):
            ai_user = OpenAIBSUser(
                openai_api_key=openai_api_key, binary_path=binary_path, bs_proj_path=bs_proj_path, model=model,
                username=username, copy_project=copy_proj, decompiler_backend=decompiler_backend, base_on=base_on,
                controller=controller, progress_callback=progress_callback, range_str=range_str, arch=arch
            )
        elif model == "VARModel":
            ai_user = VARModelBSUser(
                openai_api_key=openai_api_key, binary_path=binary_path, bs_proj_path=bs_proj_path, model=model,
                username=username, copy_project=copy_proj, decompiler_backend=decompiler_backend, base_on=base_on,
                controller=controller, progress_callback=progress_callback, range_str=range_str, arch=arch
            )
        else:
            raise ValueError(f"Model: {model} is not supported. Please use a supported model.")

        ai_user.add_ai_user_to_project()


def _headlessly_add_ai_user(
    openai_api_key: str, binary_path: Path, bs_proj_path: Path, username: str = AIBSUser.DEFAULT_USERNAME,
    decompiler_backend=None, base_on=None, model=None, arch=None
):
    script_path = Path(__file__).absolute()
    python_path = sys.executable
    optional_args = []
    if decompiler_backend:
        optional_args += ["--dec", decompiler_backend]
    if base_on:
        optional_args += ["--base-on", base_on]
    if model:
        optional_args += ["--model", model]
    if arch:
        optional_args += ["--arch", arch]

    subpproc = subprocess.Popen([
        python_path,
        str(script_path),
        openai_api_key,
        str(binary_path),
        "--username",
        username,
        "--proj-path",
        str(bs_proj_path),
    ] + optional_args)
    return subpproc


def _headless_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("openai_api_key", type=str)
    parser.add_argument("binary_path", type=Path)
    parser.add_argument("--proj-path", type=Path)
    parser.add_argument("--username", type=str)
    parser.add_argument("--dec", type=str)
    parser.add_argument("--base-on", type=str)
    parser.add_argument("--model", type=str)
    parser.add_argument("--arch", type=str)

    args = parser.parse_args()
    if args.username is None:
        args.username = AIBSUser.DEFAULT_USERNAME

    add_ai_user_to_project(
        args.openai_api_key, args.binary_path, args.proj_path, username=args.username, headless=False,
        copy_proj=True, decompiler_backend=args.dec if args.dec else None, base_on=args.base_on,
        model=args.model if args.model else None, arch=args.arch if args.arch else None
    )


if __name__ == "__main__":
    _headless_main()
