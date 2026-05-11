import json

def report(pkg, level, risk, reasons, diff):
    return json.dumps({
        "pkg": pkg,
        "risk": risk,
        "level": level,
        "reasons": reasons,
        "diff": diff
    }, indent=2)