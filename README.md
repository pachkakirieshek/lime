# lime
Lime is a security-focused wrapper over AUR helpers (paru, yay) that analyzes PKGBUILDs before installation and assigns a risk level.

It is designed to prevent unsafe package execution and highlight potentially dangerous build scripts.

---

## Features

    PKGBUILD analysis (heuristic + AST-like parsing)
    Risk scoring system (LOW / MEDIUM / HIGH / KETER)
    Detection of dangerous patterns (e.g. curl | sh, rm -rf)
    AUR helper integration (paru, yay)
    Package diff tracking (update tampering detection)
    Plugin-based rule system
    Sandbox execution support (optional)


---

## Installation (AUR)
```
yay -S lime
```
or
```
paru -S lime
```
## Install package (safe wrapper over AUR)
```
lime neovim
```
or
```
lime -S neovim
```
## Audit package only (no install)
```
lime audit neovim
```
## Risk Levels
LOW - Safe

MEDIUM - Suspicious behavior detected

HIGH - Dangerous operations detected

KETER - Highly destructive / system-critical risk

## How it works

Lime analyzes PKGBUILDs using:

```
Pattern-based security heuristics
Lightweight AST extraction
Dependency graph inspection
Plugin-based rule system
Diff-based update attack detection
```

Then it decides whether installation should be allowed or confirmed manually.

 ## Example output
```
{
  "pkg": "neovim",
  "risk": 60,
  "level": "MEDIUM",
  "reasons": ["curl usage", "sudo usage"],
  "diff": []
}
```
Architecture
```lime
 ├── analyzer (risk engine)
 ├── ast_parser (structure analysis)
 ├── graph (dependency analysis)
 ├── plugins (rules system)
 ├── diff (update attack detection)
 ├── sandbox (execution isolation)
 └── cli (user interface)
```
# Disclaimer
## Lime does NOT guarantee full security.

It is a heuristic-based tool and should be used as an additional safety layer, not a replacement for system trust verification.
