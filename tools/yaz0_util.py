import os
import subprocess

_tool_name = 'wszst' if os.name != 'nt' else 'wszst.exe'

def compress(data: bytes) -> bytes:
    return subprocess.run([_tool_name, "comp", "-", "-d-", "-C10"], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True).stdout

def decompress(data: bytes) -> bytes:
    return subprocess.run([_tool_name, "de", "-", "-d-"], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True).stdout
