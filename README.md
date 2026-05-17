##🍋 Lime


**Lime** is a security-focused wrapper over Arch Linux AUR helpers (`paru`, `yay`). It intercepts the installation process, performs deep static analysis and heuristic auditing of `PKGBUILD` files before compilation, assigns a granular risk score, and prevents unsafe code execution in your system.

> 🛡️ **Stop blindly trusting the AUR.** Lime automates build script auditing, highlighting backdoors, obfuscated code, and destructive operations before they ever touch your system.

---

##  Key Features & Advantages

*  **Anti-TOCTOU (Time-of-Check to Time-of-Use) Protection:** Lime mitigates race condition attacks by fetching and validating the `PKGBUILD` SHA-256 hash twice—once during analysis and *strictly right before* handing execution over to the package manager. Attackers cannot swap the payload while you are reading the report.

*  **Unicode Homoglyph Mitigation:** Built-in string sanitization maps identical-looking non-ASCII characters (e.g., Cyrillic `с` instead of Latin `c`) and strips hidden `zero-width` spaces or soft hyphens. This prevents bad actors from evading regex pattern detection.

* **Deep Multi-Tier Dependency Parsing:** Unlike basic tools that only scan standard `depends=()`, Lime extracts, flattens, and analyzes all dependency types: `depends`, `makedepends`, `checkdepends`, and `optdepends` to catch hidden network tools (`curl`, `wget`) sneaked into check or build stages.

*  **Plugin-Based Extensibility:** The auditing engine is completely decoupled and class-based. Security rules (e.g., cron persistence, unauthorized SSH key access, raw base64 injection, suspicious network requests) can be added or adjusted seamlessly without altering the core logic.

*  **Diff-Based Tampering Detection:** Caches previous analysis metadata. When a package updates, Lime automatically tracks and prints a precise diff of structural changes to detect malicious update tampering.

*  **Zero External Dependencies:** Built entirely using the

* **Python Standard Library** (`stdlib-only`). It introduces zero supply-chain risk, compiles cleanly into a standalone binary (`lime-bin`), and runs lightning-fast.

*  **Native Multi-Language Support:** Full English and Russian localization natively supported and configured on the fly via environment variables.

---

## 📦 Installation

The package is available in the **AUR**. You can install it using your preferred AUR helper:

yay -S lime-bin
# or
paru -S lime-bin
💻 UsageLime serves as a drop-in secure replacement for your standard installation commands.Install a package (Safe Wrapper Mode)Bashlime package-name
# or using standard flags
lime -S package-name

## Audit only (No installation)
If you want to quickly inspect a package structure and risk score without triggering compilation or pacman audit package-name
List cached profiles
View all audited and cached packages with their respective risk levels list
Check cached packages for updates Verify if any of your previously analyzed packages have changed in the AUR remote repository update
📊 Risk Scoring & Shifting PoliciesLime scores triggers dynamically and aggregates them into four discrete danger.

Tier Description System Policy

🟢 LOW: Clean package. Standard build routines detected.Continues to installation automatically.

🟡 MEDIUM: Suspicious utilities or unusual structures found (e.g., untypical curl, sudo usage).Prints warnings, requires general confirmation.

🔴 HIGH: Dangerous persistence mechanisms or critical file modifications (e.g., cron, config overwrites).Halts execution, prompts explicit warning.

💀 KETER: Maximum destructive threat level (e.g., ~/.ssh access, suspicious rm -rf combinations).

Strictly blocks execution; requires explicit bypass.

## 🛠️ Project Architecture Plaintext
📂 lime/
core.py         # Main entrypoint (install, audit, list, update commands + TOCTOU validation)
analyzer.py     # Static heuristic and risk scoring engine
plugins.py      # Decoupled class-based security rules (SSH, Cron, Base64 detection)
homoglyph.py    # String sanitization mapping and Unicode defense
graph.py        # Complete dependency tree extraction and validation
diff.py         # Incremental shift and update mutation analysis
sandbox.py      # Subprocess handling with execution timeouts
locale.py       # Localization system (RU / EN toggle via LIME_LANG)
output.py       # Beautiful, dependency-free ANSI colored terminal UI output
 
## 🌐 Localization

The CLI interface adapts automatically to your environment locale. You can override the language at any time using the LIME_LANG environment variable:Bashexport LIME_LANG=en  # Enforce English interface
export LIME_LANG=ru  # Enforce Russian interface

## 🤝 Contributing 

Pull requests are highly appreciated! To add a new security heuristic, simply inherit from the base Rule class inside plugins.py:Pythonclass MyCustomSecurityRule(Rule):
    def check(self, text: str) -> list[Finding]:
        # Implement your PKGBUILD string parsing logic here
        ...
## ⚠️ Disclaimer 
Lime does NOT guarantee absolute safety against 0-day obfuscation vectors. It serves as an automated heuristic static layer of defense. It should complement, not completely replace, manual code verification and system trust evaluations.
