import sys
from .core import install, audit

def main():
    args = sys.argv[1:]

    if not args:
        print("lime <pkg> | lime -S <pkg> | lime audit <pkg>")
        return

    if args[0] == "-S":
        install(args[1])
        return

    if args[0] == "audit":
        audit(args[1])
        return

    install(args[0])


if __name__ == "__main__":
    main()