import sys
import subprocess

import unittest
import dailalib


class TestCommandline(unittest.TestCase):
    def test_cli(self):
        # run the CLI version check
        output = subprocess.run(["daila", "--version"], capture_output=True)
        version = output.stdout.decode().strip()
        assert version == dailalib.__version__

    def test_resources_exist(self):
        from dailalib.api.litellm.prompts import PROMPTS
        assert len(PROMPTS) > 0


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
