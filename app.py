import subprocess, sys

apps = {
    "enc": "encserver.py",
    "backend": "backend.py"
}

def main():
    args = sys.argv
    if (len(args) < 2): return
    launch = args[1]
    if (launch in apps):
        subprocess.call(["py", apps[launch]])

main()
