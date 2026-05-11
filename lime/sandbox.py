import subprocess

def sandbox(cmd):
    return subprocess.run(cmd)