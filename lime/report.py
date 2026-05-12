import json


def report(pkg: str, level: str, risk: int, reasons: list, explanations: list, diff: list) -> str:
    data = {
        "pkg": pkg,
        "risk_score": risk,
        "level": level,
        "reasons": reasons,
        "explanations": explanations,
        "diff_warnings": diff,
    }
    return json.dumps(data, ensure_ascii=False, indent=2)
