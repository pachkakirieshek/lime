import sys
from .core import install, audit
from .locale import t


def main():
    args = sys.argv[1:]

    if not args:
        print(t("usage"))
        return

    if args[0] == "-S" and len(args) > 1:
        install(args[1])
        return

    if args[0] == "audit" and len(args) > 1:
        audit(args[1])
        return

    install(args[0])


if __name__ == "__main__":
    main()
