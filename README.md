# 🛡️ ShieldGuard

**ShieldGuard** is a lightweight, modern Windows desktop security utility built with Python & CustomTkinter to detect and remove stealth crypto-miners, Task Manager evasion watchdogs, malicious persistence entries, unauthorized Windows Defender exclusions, and suspicious files.

---

## ✨ Key Features

- **Stealth Process & Crypto-Miner Hunter (CPU/GPU):** Detects known miners (`xmrig`, `lolminer`, `gminer`, `t-rex`, `rigel`, etc.), `conhost --headless` watchdogs, mining pool connections, and NVIDIA GPU compute usage via `nvidia-smi` (without triggering Task Manager evasion).
- **Persistence Scanner:** Audits Scheduled Tasks, Registry `Run` / `RunOnce` / `Winlogon\Shell`, Startup folders, Windows Services/Drivers (e.g., `WinRing0_1_2_0`), and WMI Event Subscriptions.
- **Windows Defender Exclusions Auditor:** Verifies Real-Time Protection status and detects/removes unauthorized `ExclusionPath`, `ExclusionProcess`, and `ExclusionExtension` entries.
- **File / Folder Scanner + Windows Defender + VirusTotal:** Combines static heuristics, on-demand Windows Defender (`MpCmdRun.exe`) scanning, and optional VirusTotal API v3 SHA-256 lookups.
- **Built-in Knowledge Base + Online / AI File Lookup:** Explains what detected files do using an offline pattern database, DuckDuckGo/Wikipedia web search, Google Search, and optional Gemini AI analysis.
- **Safe Quarantine Vault & Batch Remediation:** Multi-select checkboxes for batch cleanup, XOR-neutralized quarantine (`.sgq`) with 1-click Restore or Permanent Delete, and shareable `.txt` / `.json` scan logs.
- **Multi-Language UI:** Supports **English, Tiếng Việt, 中文 (简体), Español, and Deutsch** with instant live switching.
- **Built-in Auto-Update Checker:** Checks GitHub Releases directly from the app and supports upgrades via **WinGet**.

---

## 📦 Installation

### Option 1: Install via WinGet (Windows Package Manager)
```powershell
winget install M4rcus-theIvel.ShieldGuard
```

To check and install updates via WinGet:
```powershell
winget upgrade M4rcus-theIvel.ShieldGuard
```

### Option 2: Download Standalone `.exe`
Download the latest `ShieldGuard.exe` from the [GitHub Releases](https://github.com/M4rcus-theIvel/ShieldGuard/releases) page and run it as Administrator.

### Option 3: Run from Source
```powershell
git clone https://github.com/M4rcus-theIvel/ShieldGuard.git
cd ShieldGuard
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python main.py
```

---

## 🔨 Build Standalone `.exe` Locally
Run `build_exe.bat` (uses PyInstaller with `--uac-admin` manifest) to compile `dist\ShieldGuard.exe`.

---

## 🔄 Checking for Updates
- **Inside the App:** Click **🔄 Check Updates** in the left sidebar. ShieldGuard queries the GitHub Releases API, compares versions, and lets you download the new release or trigger `winget upgrade`.
- **Via WinGet CLI:** Run `winget upgrade M4rcus-theIvel.ShieldGuard` in PowerShell or Windows Terminal.

---

## 📄 License
Licensed under the [MIT License](LICENSE).
