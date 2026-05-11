class Rule:
    def check(self, text):
        return []


class SSHRule(Rule):
    def check(self, text):
        return ["ssh access"] if "~/.ssh" in text else []


PLUGINS = [SSHRule()]


def run(text):
    out = []

    for p in PLUGINS:
        out += p.check(text)

    return out