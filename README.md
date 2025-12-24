# APT Cyber Killchain Simulator 🚀

[![Red Team](https://img.shields.io/badge/Red_Team-APT_Attacks-ff4444?style=for-the-badge&logo=octicons)](https://github.com/username/APT28-Cyber-Killchain-Simulator/blob/main/apt-simulator.sh)
[![Blue Team](https://img.shields.io/badge/Blue_Team-Defense-4488ff?style=for-the-badge&logo=shield)](https://github.com/username/APT28-Cyber-Killchain-Simulator/blob/main/apt-simulator.sh)
[![MIT License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge&logo=mit)](LICENSE)
[![Gum Powered](https://img.shields.io/badge/Powered_by-gum-FFEB3B?style=for-the-badge&logo=go&logoColor=black)](https://github.com/charmbracelet/gum)\
**Interactive Red Team & Blue Team training platform** simulating real-world **APT group operations** with terminal-based adventures. Choose your role, select your APT adversary, and execute complete killchains or defensive operations.


## 🎮 Architecture

```
TUI Menu (dialog) → Select Script → Execute (gum-based) → Return to Menu
```

**Launcher**: Professional ncurses TUI using `dialog` (standard Linux/macOS)
**Scripts**: Interactive adventures using `gum` (Charmbracelet)

## ✨ Features

| Component | Technology | Description |
|-----------|-----------|-------------|
| **Launcher** | `dialog` (ncurses) | Professional TUI menu system |
| **Red Team Scripts** | `gum` + bash | 14-phase interactive killchains |
| **Blue Team Scripts** | `gum` + bash | 10-phase defense assessments |
| **MITRE Coverage** | Manual mapping | 32+ ATT&CK techniques |
| **Expandable** | File-based detection | Drop scripts → Auto-appears |

## 🚀 Quick Start

```bash
# 1. Install dependencies
sudo apt install dialog        # TUI menu (Linux)
brew install dialog            # TUI menu (macOS)
brew install gum               # Script framework

# 2. Run launcher
chmod +x apt-simulator.sh
./apt-simulator.sh
```

## 📱 User Experience

```
┌─────────────────────────────────────────────┐
│            [ MAIN MENU ]                    │
│                                             │
│   1  🔴 Red Team                            │
│   2  🛡️  Blue Team                          │
│   3  ❌ Exit                                │
│                                             │
└─────────────────────────────────────────────┘
         ↓ Select "Red Team"
┌─────────────────────────────────────────────┐
│         [ SELECT APT GROUP ]                │
│                                             │
│   1  🇷🇺 APT28 (Fancy Bear)                 │
│   2  🇷🇺 APT29 (Cozy Bear)                  │
│   3  🇰🇵 Lazarus Group                      │
│   ...                                       │
└─────────────────────────────────────────────┘
         ↓ Select "APT28"
         ↓ Launches apt28-killchain.sh
┌─────────────────────────────────────────────┐
│  🎯 PHASE 1: RECONNAISSANCE (TA0043)       │
│  Target Organization? [input box]          │
│  → DNC Servers selected                    │
│  ✅ OSINT complete                         │
└─────────────────────────────────────────────┘
```

## 🗂️ Repository Structure

```
apt-simulator.sh                    # 🎮 TUI Launcher (dialog)
├── red-team/                      # 🔴 Attack Simulators (gum)
│   ├── apt28-killchain.sh         # ✅ APT28 (Fancy Bear) - LIVE
│   ├── apt29-killchain.sh         # ⏳ Coming Soon
│   └── lazarus-killchain.sh       # ⏳ Coming Soon
├── blue-team/                     # 🛡️ Defense Simulators (gum)
│   ├── blueteam-apt28-defense.sh  # ✅ APT28 Defense - LIVE
│   ├── blueteam-apt29-defense.sh  # ⏳ Coming Soon
│   └── blueteam-lazarus-defense.sh# ⏳ Coming Soon
├── README.md                      # 📖 This file
└── LICENSE                        # 📄 MIT License
```

## 🎓 Training Scenarios

### ✅ **Currently Available**

| APT Group | Red Team Script | Blue Team Script | Status |
|-----------|----------------|------------------|--------|
| **APT28** (Fancy Bear) | `apt28-killchain.sh` | `blueteam-apt28-defense.sh` | **LIVE** |
| **APT29** (Cozy Bear) | `apt29-killchain.sh` | `blueteam-apt29-defense.sh` | **LIVE** |

**APT28 Red Team**: 14 phases (Recon → Exfiltration → Impact)  
**APT28 Blue Team**: 10 phases (Inventory → Hunt → Validation)

### ⏳ **Planned Implementations**

| APT Group | Attribution | Notable Operations |
|-----------|-------------|-------------------|
| Lazarus Group | 🇰🇵 North Korea | WannaCry, Sony Hack |
| APT41 (Winnti) | 🇨🇳 China | Double Dragon |
| Sandworm | 🇷🇺 GRU | NotPetya, Ukraine Grid |
| APT32 (Ocean Lotus) | 🇻🇳 Vietnam | Southeast Asia |
| Equation Group | 🇺🇸 NSA | FoxAcid Exploits |
| Turla | 🇷🇺 FSB | Venomous Bear |

## 📊 Sample Outputs

### TUI Menu Navigation
```
[dialog ncurses interface - keyboard navigation]
↑/↓ arrows to select
Enter to launch
ESC to go back
```

### Red Team Script Execution (APT28)
```
🇷🇺 APT28 FANCY BEAR SIMULATOR
PHASE 1: RECONNAISSANCE (TA0043)
[gum choose] Select target: US State Department
[gum spin] OSINT collection...
✅ Emails harvested: 1,247 targets

🎖️ MISSION COMPLETE
Stealth Score: 87/100 ✅ EXCELLENT
Compromised: 12 hosts | Exfiltrated: 2.4GB
```

### Blue Team Script Execution (APT28)
```
🛡️ APT28 DEFENSE OPERATIONS
PHASE 1: ASSET INVENTORY
[gum input] Domain Controller: DC01.corp.local
[gum spin] Scanning network...
✅ Total endpoints: 347

🛡️ SECURITY GRADE: A - Excellent
Score: 92/100 | Threat Level: LOW
Controls: 28 deployed | Detection Rate: 89%
```

## 🛠️ Adding New APT Groups

**Super easy!** The TUI menu auto-detects scripts:

```bash
# 1. Create new scripts (copy existing templates)
cp red-team/apt28-killchain.sh red-team/apt41-killchain.sh
cp blue-team/blueteam-apt28-defense.sh blue-team/blueteam-apt41-defense.sh

# 2. Customize for APT41 TTPs
nano red-team/apt41-killchain.sh

# 3. Restart launcher - APT41 auto-appears in menu!
./apt-simulator.sh
```

**No code changes needed!** Menu reads folder contents automatically.

## 🎯 MITRE ATT&CK Coverage (APT28)

| Tactic | Red Team Implementation | Blue Team Detection |
|--------|------------------------|-------------------|
| **Reconnaissance** | TA0043 - OSINT, Active Scanning | Sigma Rules, Threat Intel |
| **Initial Access** | T1566.001 - Spear-phishing | Email Sandbox, DMARC |
| **Execution** | T1059.001 - PowerShell | Script Block Logging |
| **Persistence** | T1547.001 - Registry Run Keys | Sysmon EID 13 |
| **Privilege Escalation** | T1068 - Exploit for Privilege | Credential Guard |
| **Defense Evasion** | T1055 - Process Injection | Behavioral EDR |
| **Credential Access** | T1003.001 - LSASS Memory | LSA Protection |
| **Lateral Movement** | T1021.002 - SMB/Windows Shares | Network Segmentation |
| **Collection** | T1114 - Email Collection | DLP Controls |
| **Exfiltration** | T1041 - C2 Channel | NetFlow Analysis |

## 👥 Perfect For

- **Red Team Operators** - Realistic TTP execution with stealth scoring
- **Blue Team Analysts** - Detection rule validation and IR practice  
- **Purple Team Exercises** - Collaborative attacker/defender training
- **SOC Training** - Incident response workflow development
- **EDR Testing** - Platform capability assessment against APT TTPs
- **Certification Prep** - OSCP, GCIH, GCFA, CySA+ practical scenarios
- **CTF/Lab Environments** - TryHackMe, Hack The Box companion tool

## 🔧 Technical Details

### TUI Launcher (`apt-simulator.sh`)
- **Framework**: `dialog` (ncurses-based)
- **Navigation**: Keyboard-driven menus (↑/↓/Enter/ESC)
- **Script Detection**: Auto-discovers `red-team/*.sh` and `blue-team/*.sh`
- **Exit Handling**: Clean return to shell prompt
- **Dependencies**: Standard on most Linux/macOS systems

### Interactive Scripts (Red/Blue Team)
- **Framework**: `gum` (Charmbracelet terminal toolkit)
- **Components**: `gum choose`, `gum input`, `gum spin`, `gum style`, `gum format`
- **Output**: Logs, reports, session data to `/tmp/apt-*`
- **Metrics**: Stealth scores (Red), Security grades (Blue)

## 📈 Metrics & Reporting

**Red Team Outputs**:
- Stealth Score (0-100)
- Compromised assets inventory
- Exfiltration volume (GB)
- MITRE ATT&CK technique coverage
- After Action Report (AAR)

**Blue Team Outputs**:
- Security Grade (A-F, 0-100)
- Deployed controls list
- Detection rule coverage
- Gap analysis recommendations
- Assessment report

## 🤝 Contributing

1. **Add New APTs**: Create `red-team/aptXX-killchain.sh` + matching Blue Team script
2. **Enhance TTPs**: Add new MITRE techniques to existing simulators
3. **Detection Rules**: Expand Sigma/YARA coverage in Blue Team scripts
4. **Submit PR**: Include demo video/screenshots

```bash
# Example: Adding APT29
git checkout -b feature/apt29
cp red-team/apt28-killchain.sh red-team/apt29-killchain.sh
# Customize for Cozy Bear TTPs (supply chain, cloud attacks)
git add . && git commit -m "Add APT29 Cozy Bear simulator"
git push && Open PR ✨
```


***

## 🆕 What's New in v1.0

✨ **Professional TUI launcher** using ncurses `dialog`
✨ **Auto-discovery** of APT scripts - no hardcoding needed  
✨ **Clean separation** - Menu (TUI) vs Scripts (gum adventures)
✨ **Keyboard navigation** - Arrow keys, Enter, ESC  
✨ **Production ready** - Error handling, script validation  

***

**Built by cybersecurity practitioners for training the next generation of defenders & operators**

⭐ **Star if useful!** 🚀 **Fork & contribute new APTs!** 🛡️ **Train your SOC today!**

***

## Quick Commands

```bash
# Install everything
sudo apt install dialog && brew install gum

# Launch simulator
./apt-simulator.sh

# Add new APT
cp red-team/apt28-killchain.sh red-team/mynew-apt.sh

# Test script directly
bash red-team/apt28-killchain.sh
```

**Ready for production cybersecurity training environments!** 🎓
