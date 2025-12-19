import subprocess, sys, os

apps = {
    "enc": ("encserver.py", "encserver"),
    "backend": ("webserver.py", "backend")
}

def main():
    args = sys.argv
    if (len(args) < 2): return
    launch = args[1]
    if (launch in apps):
        os.chdir(apps[launch][1])
        subprocess.call(["py", apps[launch][0]])
    if (not launch):
        print("You need to specify an application to run!")

main()
