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































































































































































































































































































































## For Redditors

Congratulations, you found the hidden boss room. Since some of you spent your weekend conducting a literal linguistic PhD analysis on my em-dashes and emojis, here is your official breakdown:

1. **Yes, the README was heavily blasted with LLM marketing hype.** Why? Because I didn't want to waste 3 hours manually formatting tables and tree diagrams. I used an AI assistant as an advanced IDE to skip the boring routine. If this triggers your weird anti-AI crusader trauma, please go touch some grass or find a job.
2. **Yes, I read your "expert" analysis of the code.** While 99% of you were crying about emojis and completely ignored the massive **Disclaimer** at the bottom, a few of you actually pointed out real architectural flaws. 
3. **So, I fixed it.** Lime has now evolved past the hobby-MVP stage:
   * The "fake sandbox" is now backed by actual kernel-level **Bubblewrap (`bwrap`)** isolation.
   * The "regex AST" is strictly documented for what it is, and we added a **ShellObfuscationRule** specifically to detect and instantly flag that sneaky `$foo$bar$baz$qux` dynamic code generation trick you tried to flex with.
   * The TOCTOU window is dead. Lime now clones the verified PKGBUILD to a secure `/tmp/` directory and forces `makepkg` to compile directly from there. No more double-hashing, no more race conditions.

Thanks for the free security audit and the temporary shadowban, you absolute nerds. Your paranoid tech-detective routine actually made this tool ten times better. 

And no, I am still not deleting Hatsune Miku from the git history. but 
Somewhere, a student who wrote those long dashes in an online exam shot himself, as did a grandmother who loved writing emojis

You guys love to scream 'AI slop! Ctrl+C Ctrl+V without understanding!' like you're some kind of cyber-monks living in a digital monastery. But let’s be real for a second and look at the absolute peak hypocrisy here:

Clicking 'Next -> Next -> I Agree' on a 100-page corporate Terms of Service and data-mining privacy policy without reading a single word? 'Well, that's different, everyone does it!'

Blindsidedly hitting 'Enter' when your AUR helper asks if you want to inspect a sketchy PKGBUILD, completely trusting a random maintainer named xX_LinuxLover_Xx? 'Well, the community probably checked it (maybe)...'

A guy uses an AI assistant for code? 'HE'S A WITCH! BURN HIM AT THE STAKE! HE'S USING COPIED CODE!'

If you are so pure and terrified of automation, why stop at AI? Uninstall your modern IDEs. Disable syntax highlighting, code completion, and linters. Go back to writing your code in raw ed or on paper punch cards. Why use Google to find an answer in 3 seconds when you could travel to a library and read an encyclopedia?

You're micro-analyzing my em-dashes and emojis like you're writing a PhD thesis on 'AI-induced punctuation decay,' while 99% of you haven't even read the giant  Disclaimer at the bottom of the README. It literally says Lime is a lightweight heuristic filter, not an enterprise silver bullet.

But sure, go on, celebrate your 'victory' over the AI bot while blindly updating your system with uninspected code. Stay safe, clean your READMEs, and please, go touch some grass or find a job.

