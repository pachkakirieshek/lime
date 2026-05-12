from .locale import t


def confirm(level: str, reasons: list) -> bool:
    prompt = t("confirm_prompt", level=level, reasons=", ".join(reasons))
    ans = input(prompt)
    return ans.strip().lower() == "y"
