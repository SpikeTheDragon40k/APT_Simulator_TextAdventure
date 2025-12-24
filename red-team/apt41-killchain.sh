#!/bin/bash
# ============================================================================
# APT41 (WINNTI / DOUBLE DRAGON) - RED TEAM KILLCHAIN SIMULATOR
# ============================================================================
# Simulates Chinese dual-purpose APT: State-sponsored espionage + Financial crime
# MSS (Ministry of State Security) - People's Republic of China
# MITRE ATT&CK Group: G0096
# ============================================================================

set -euo pipefail
trap cleanup INT TERM

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
VERSION="1.0"
LOG_FILE="/tmp/apt41-mission-$(date +%Y%m%d-%H%M%S).log"
MISSION_START=$(date +%s)

# Mission state tracking
declare -a COMPROMISED_HOSTS=()
declare -a HARVESTED_CREDS=()
declare -a STOLEN_DATA=()
declare -A MITRE_TECHNIQUES=()
STEALTH_SCORE=100
DETECTION_EVENTS=0
FINANCIAL_GAIN=0
INTELLECTUAL_PROPERTY_SIZE=0

# APT41 characteristics (dual operational model)
C2_DOMAIN="update-$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1).com"
C2_IP="103.$(( RANDOM % 255 )).$(( RANDOM % 255 )).$(( RANDOM % 255 ))"
OPERATIONAL_MODE=""

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
check_dependencies() {
    if ! command -v gum &> /dev/null; then
        echo "❌ ERROR: gum required"
        echo "Install: brew install gum"
        exit 1
    fi
}

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

cleanup() {
    echo
    gum style --foreground 11 "🚨 Operation terminated"
    generate_report
    exit 130
}

update_stealth() {
    local penalty=$1
    ((STEALTH_SCORE -= penalty)) || true
    ((DETECTION_EVENTS++)) || true
    if [ $STEALTH_SCORE -lt 30 ]; then
        gum style --foreground 196 "⚠️  WARNING: High detection probability!"
    fi
}

track_mitre() {
    local tactic=$1
    local technique=$2
    MITRE_TECHNIQUES["$tactic"]="$technique"
    log_action "MITRE: [$tactic] $technique"
}

phase_banner() {
    local phase_num=$1
    local phase_name=$2
    clear
    gum style \
        --foreground 208 --border-foreground 208 --border double \
        --width 90 --align center --padding "1 2" \
        "PHASE $phase_num: $phase_name"
    echo
}

# ============================================================================
# PHASE 0: MISSION BRIEFING
# ============================================================================
mission_briefing() {
    clear
    gum style \
        --foreground 208 --background 0 --border-foreground 208 --border double \
        --width 90 --align center --padding "3 4" --bold \
        "🇨🇳 APT41 DOUBLE DRAGON" \
        "MSS Ministry of State Security - People's Republic of China" \
        "" \
        "Dual-Purpose Cyber Operations Simulator v${VERSION}"
    
    echo
    
    gum format -- "# Mission Parameters"
    gum format -- "**Threat Actor**: APT41 (Winnti, Double Dragon, Wicked Panda, Barium)"
    gum format -- "**Attribution**: MSS Contractor - Chengdu 404, Axiom"
    gum format -- "**MITRE Group**: G0096"
    gum format -- "**Unique Trait**: Dual operations - State espionage + Financial cybercrime"
    gum format -- "**Notable Campaigns**: Healthcare breach (2019), Gaming industry supply chain, Telecoms"
    
    echo
    
    OPERATIONAL_MODE=$(gum choose --header "Select operational mode:" \
        "🕵️  STATE-SPONSORED ESPIONAGE (MSS tasking)" \
        "💰 FINANCIAL CYBERCRIME (Personal profit)" \
        "🎯 DUAL OPERATION (Espionage + Crime combined)")
    
    log_action "=== APT41 MISSION START: $OPERATIONAL_MODE ==="
    
    case $OPERATIONAL_MODE in
        *"STATE-SPONSORED"*)
            gum style --foreground 208 "📋 Mission authorized by MSS"
            gum style --foreground 208 "🎯 Target: Critical infrastructure, IP theft, strategic intelligence"
            ;;
        *"FINANCIAL"*)
            gum style --foreground 208 "💰 Freelance operation for personal enrichment"
            gum style --foreground 208 "🎯 Target: Gaming companies, payment systems, cryptocurrency"
            ;;
        *"DUAL"*)
            gum style --foreground 208 "🔀 Hybrid operation: State intelligence + Financial gain"
            gum style --foreground 208 "🎯 Multi-objective mission (MSS + profit)"
            ;;
    esac
    
    echo
    if ! gum confirm "Proceed with APT41 operation?"; then
        echo "Operation cancelled"
        exit 0
    fi
}

# ============================================================================
# PHASE 1: RECONNAISSANCE - Target Selection
# ============================================================================
phase_reconnaissance() {
    phase_banner 1 "RECONNAISSANCE - TARGET INTELLIGENCE (TA0043)"
    
    gum format -- "## Strategic Target Selection"
    
    case $OPERATIONAL_MODE in
        *"STATE-SPONSORED"*)
            TARGET_ORG=$(gum choose --header "Select espionage target:" \
                "Healthcare Industry (Patient data, Research)" \
                "Telecommunications (5G infrastructure)" \
                "Defense Contractors" \
                "Higher Education (Research IP)" \
                "Biotechnology Firms")
            ;;
        *"FINANCIAL"*)
            TARGET_ORG=$(gum choose --header "Select financial target:" \
                "Online Gaming Companies (Virtual currency)" \
                "Cryptocurrency Exchanges" \
                "Payment Processors" \
                "Software License Resellers" \
                "E-commerce Platforms")
            ;;
        *"DUAL"*)
            TARGET_ORG=$(gum choose --header "Select dual-purpose target:" \
                "Pharmaceutical Company (IP + Financial)" \
                "Technology Firm (Trade secrets + Source code)" \
                "Financial Institution (Intelligence + Fraud)" \
                "Gaming Platform (User data + Virtual goods)")
            ;;
    esac
    
    log_action "TARGET: $TARGET_ORG ($OPERATIONAL_MODE)"
    track_mitre "Reconnaissance" "T1589.002 - Email Addresses"
    
    echo
    gum spin --spinner dot --title "OSINT collection on $TARGET_ORG..." -- sleep 3
    
    # Employee intelligence
    gum format -- "### Employee & Social Engineering Intelligence"
    if gum confirm "Harvest employee data (LinkedIn, social media)?"; then
        track_mitre "Reconnaissance" "T1593.002 - Search Engines"
        gum spin --spinner dot --title "Scraping social media profiles..." -- sleep 2
        
        EMPLOYEES=$((100 + RANDOM % 300))
        HIGH_VALUE_TARGETS=$((EMPLOYEES / 15))
        
        gum style --foreground 46 "✅ Employee profiles: $EMPLOYEES"
        gum style --foreground 46 "✅ High-value targets: $HIGH_VALUE_TARGETS (IT admins, DevOps, Finance)"
        gum style --foreground 46 "✅ Email patterns: firstname.lastname@domain.com"
    fi
    
    echo
    gum format -- "### Technical Reconnaissance"
    track_mitre "Reconnaissance" "T1595.002 - Vulnerability Scanning"
    
    gum spin --spinner pulse --title "Scanning external attack surface..." -- sleep 3
    
    EXPOSED_ASSETS=$((10 + RANDOM % 40))
    gum style --foreground 46 "✅ Internet-facing assets: $EXPOSED_ASSETS"
    gum style --foreground 46 "✅ Web applications: $((EXPOSED_ASSETS / 2))"
    gum style --foreground 46 "✅ VPN gateways: $(( 1 + RANDOM % 3 ))"
    gum style --foreground 46 "✅ Unpatched CVEs detected: $(( RANDOM % 5 + 1 ))"
    
    # Certificate transparency logs (APT41 technique)
    echo
    if gum confirm "Mine certificate transparency logs for subdomains?"; then
        track_mitre "Reconnaissance" "T1596.003 - Digital Certificates"
        gum spin --spinner dot --title "Querying crt.sh certificate logs..." -- sleep 2
        
        SUBDOMAINS=$((50 + RANDOM % 100))
        gum style --foreground 46 "✅ Subdomains discovered: $SUBDOMAINS"
        gum style --foreground 46 "✅ Hidden services: vpn.internal, dev.staging, admin.corp"
    fi
    
    log_action "RECON: $TARGET_ORG scanned, $HIGH_VALUE_TARGETS HVTs identified"
    
    gum confirm "Proceed to resource development?" || exit 0
}

# ============================================================================
# PHASE 2: RESOURCE DEVELOPMENT - Malware Arsenal
# ============================================================================
phase_resource_development() {
    phase_banner 2 "RESOURCE DEVELOPMENT - WINNTI MALWARE SUITE (TA0042)"
    
    gum format -- "## APT41 Custom Malware Development"
    
    # Select primary malware family
    MALWARE_FAMILY=$(gum choose --header "Select Winnti malware variant:" \
        "Winnti (Rootkit + Backdoor)" \
        "KEYPLUG (Modular backdoor)" \
        "DEADEYE (Dropper)" \
        "MESSAGETAP (Telecom SMS interception)" \
        "HOMEUNIX (Linux backdoor)" \
        "HIGHNOON (RAT)" \
        "DUSTPAN (Data exfil tool)")
    
    track_mitre "Resource Development" "T1587.001 - Malware"
    gum spin --spinner pulse --title "Compiling $MALWARE_FAMILY..." -- sleep 3
    
    gum style --foreground 46 "✅ Malware compiled: $MALWARE_FAMILY"
    gum style --foreground 46 "✅ Code obfuscation: VMProtect + custom packer"
    gum style --foreground 46 "✅ Anti-analysis: Multi-stage unpacking"
    gum style --foreground 46 "✅ Rootkit component: Kernel-mode driver"
    
    # Code signing certificates (APT41 specialty)
    echo
    gum format -- "## Code Signing Certificate"
    
    if gum confirm "Acquire stolen/forged code signing certificate?"; then
        track_mitre "Resource Development" "T1588.003 - Code Signing Certificates"
        
        CERT_SOURCE=$(gum choose \
            "Stolen from software vendor" \
            "Purchased from underground market" \
            "Forged certificate (self-signed)")
        
        gum spin --spinner pulse --title "Obtaining code signing certificate via $CERT_SOURCE..." -- sleep 2
        
        CERT_ISSUER="VeriSign Class 3 Code Signing 2010 CA"
        CERT_SUBJECT="Legitimate Software Company Ltd."
        
        gum style --foreground 46 "✅ Certificate acquired"
        gum style --foreground 46 "   Issuer: $CERT_ISSUER"
        gum style --foreground 46 "   Subject: $CERT_SUBJECT"
        gum style --foreground 46 "✅ Malware signed with valid certificate"
        update_stealth -15  # Very stealthy
    fi
    
    # C2 Infrastructure
    echo
    gum format -- "## Command & Control Infrastructure"
    track_mitre "Resource Development" "T1583.001 - Domains"
    
    gum spin --spinner pulse --title "Provisioning C2 infrastructure..." -- sleep 2
    
    gum style --foreground 46 "✅ C2 Domain: $C2_DOMAIN (typosquatted)"
    gum style --foreground 46 "✅ C2 IP: $C2_IP (Compromised server in Asia)"
    gum style --foreground 46 "✅ Backup C2: DGA algorithm (domain generation)"
    gum style --foreground 46 "✅ Protocol: HTTPS with custom SSL pinning"
    
    # Supply chain preparation (APT41 tactic)
    echo
    gum format -- "## Supply Chain Compromise Preparation"
    
    if gum confirm "Target software supply chain (trojanize updates)?"; then
        track_mitre "Resource Development" "T1587.002 - Code Signing Certificates"
        
        SUPPLY_CHAIN_TARGET=$(gum choose \
            "CCleaner-style update mechanism" \
            "Gaming platform patch system" \
            "Open-source library dependency" \
            "Software vendor build server")
        
        gum spin --spinner pulse --title "Infiltrating $SUPPLY_CHAIN_TARGET..." -- sleep 3
        
        gum style --foreground 46 "✅ Supply chain target: $SUPPLY_CHAIN_TARGET"
        gum style --foreground 46 "✅ Backdoored installer prepared"
        gum style --foreground 46 "✅ Distribution channel compromised"
        
        log_action "SUPPLY CHAIN: $SUPPLY_CHAIN_TARGET prepared for trojanization"
    fi
    
    log_action "WEAPONIZATION: $MALWARE_FAMILY ready, code-signed"
    
    gum confirm "Proceed to initial access?" || exit 0
}

# ============================================================================
# PHASE 3: INITIAL ACCESS
# ============================================================================
phase_initial_access() {
    phase_banner 3 "INITIAL ACCESS - MULTI-VECTOR COMPROMISE (TA0001)"
    
    gum format -- "## Initial Compromise Vector Selection"
    
    ACCESS_METHOD=$(gum choose --header "Select delivery method:" \
        "Spear-phishing with DEADEYE dropper" \
        "Supply chain attack (trojanized software)" \
        "Watering hole (compromised industry site)" \
        "SQL injection on web application" \
        "Citrix/VPN vulnerability exploitation" \
        "Stolen credentials (credential stuffing)")
    
    echo
    case $ACCESS_METHOD in
        *"Spear-phishing"*)
            track_mitre "Initial Access" "T1566.001 - Spearphishing Attachment"
            
            PHISH_TARGET=$(gum input --placeholder "Target employee email" \
                --value "it.admin@$(echo $TARGET_ORG | tr ' ' '-' | tr '[:upper:]' '[:lower:]').com")
            
            gum spin --spinner pulse --title "Crafting targeted spear-phishing campaign..." -- sleep 2
            
            gum style --foreground 46 "📧 Phishing email crafted:"
            gum style --foreground 11 "   Subject: IT Security Update Required - Action Needed"
            gum style --foreground 11 "   Attachment: SecurityPatch_2024.exe (DEADEYE dropper)"
            gum style --foreground 11 "   Target: $PHISH_TARGET"
            gum style --foreground 11 "   Social engineering: Appears from IT department"
            
            echo
            gum spin --spinner pulse --title "Sending phishing email..." -- sleep 2
            
            if (( RANDOM % 100 < 70 )); then
                gum style --foreground 46 --bold "✅ ATTACHMENT EXECUTED"
                gum style --foreground 46 "✅ DEADEYE dropper executed"
                gum style --foreground 46 "✅ $MALWARE_FAMILY payload deployed"
            else
                gum style --foreground 196 "❌ Email flagged by security awareness training"
                update_stealth 15
                gum confirm "Retry with different vector?" && phase_initial_access
                return
            fi
            ;;
            
        *"Supply chain"*)
            track_mitre "Initial Access" "T1195.002 - Compromise Software Supply Chain"
            
            gum spin --spinner pulse --title "Deploying trojanized software update..." -- sleep 3
            
            gum style --foreground 46 --bold "✅ SUPPLY CHAIN COMPROMISE SUCCESSFUL"
            gum style --foreground 46 "✅ Trojanized update distributed"
            gum style --foreground 46 "✅ Code signed with stolen certificate (trusted)"
            
            INFECTED_COUNT=$((50 + RANDOM % 200))
            gum style --foreground 46 "✅ Installations: $INFECTED_COUNT organizations"
            gum style --foreground 46 "✅ Target org: $TARGET_ORG (confirmed install)"
            
            update_stealth -10  # Very stealthy
            ;;
            
        *"Watering hole"*)
            track_mitre "Initial Access" "T1189 - Drive-by Compromise"
            
            WATERING_HOLE=$(gum input --placeholder "Industry website to compromise" \
                --value "healthcare-tech-forum.com")
            
            gum spin --spinner pulse --title "Compromising $WATERING_HOLE..." -- sleep 3
            gum style --foreground 46 "✅ Watering hole compromised"
            gum style --foreground 46 "✅ Exploit kit deployed (Internet Explorer 0-day)"
            
            gum spin --spinner dot --title "Waiting for $TARGET_ORG visitors..." -- sleep 3
            gum style --foreground 46 --bold "✅ TARGET INFECTED VIA DRIVE-BY"
            ;;
            
        *"SQL injection"*)
            track_mitre "Initial Access" "T1190 - Exploit Public-Facing Application"
            
            gum spin --spinner pulse --title "Testing SQL injection vectors..." -- sleep 2
            gum style --foreground 46 "✅ Vulnerable endpoint: /api/users?id=1"
            
            gum spin --spinner pulse --title "Exploiting SQL injection..." -- sleep 3
            
            gum style --foreground 46 --bold "✅ SQL INJECTION SUCCESSFUL"
            gum style --foreground 46 "✅ Database access: Customer records"
            gum style --foreground 46 "✅ Web shell uploaded: /uploads/update.aspx"
            ;;
            
        *"Citrix"* | *"VPN"*)
            track_mitre "Initial Access" "T1133 - External Remote Services"
            
            CVE=$(gum choose "CVE-2019-19781 (Citrix ADC)" "Pulse Secure VPN" "Fortinet VPN")
            
            gum spin --spinner pulse --title "Exploiting $CVE..." -- sleep 3
            
            gum style --foreground 46 --bold "✅ VPN GATEWAY COMPROMISED"
            gum style --foreground 46 "✅ Internal network access obtained"
            gum style --foreground 46 "✅ VPN user credentials harvested"
            ;;
            
        *"Stolen credentials"*)
            track_mitre "Initial Access" "T1078 - Valid Accounts"
            
            gum spin --spinner pulse --title "Testing stolen credentials from breach databases..." -- sleep 2
            
            gum style --foreground 46 "✅ Valid credentials found:"
            gum style --foreground 46 "   Username: jdoe@$TARGET_ORG"
            gum style --foreground 46 "   Password: Summer2023! (password reuse)"
            
            gum spin --spinner pulse --title "Authenticating to VPN..." -- sleep 2
            gum style --foreground 46 --bold "✅ VPN ACCESS GRANTED"
            ;;
    esac
    
    VICTIM_HOST="$(echo $TARGET_ORG | tr ' ' '-' | tr '[:upper:]' '[:lower:]')-pc-$(printf '%04d' $((RANDOM % 9999)))"
    VICTIM_IP="10.$(( RANDOM % 255 )).$(( RANDOM % 255 )).$(( RANDOM % 254 + 1 ))"
    COMPROMISED_HOSTS+=("$VICTIM_HOST|$VICTIM_IP|Windows 10")
    
    log_action "INITIAL ACCESS: $VICTIM_HOST via $ACCESS_METHOD"
    
    gum confirm "Proceed to execution?" || exit 0
}

# ============================================================================
# PHASE 4: EXECUTION
# ============================================================================
phase_execution() {
    phase_banner 4 "EXECUTION - MALWARE DEPLOYMENT (TA0002)"
    
    gum format -- "## Payload Execution & C2 Establishment"
    track_mitre "Execution" "T1059.001 - PowerShell"
    
    gum spin --spinner pulse --title "Executing $MALWARE_FAMILY payload..." -- sleep 3
    
    case $MALWARE_FAMILY in
        *"Winnti"*)
            gum style --foreground 46 --bold "🦠 WINNTI ROOTKIT DEPLOYING"
            gum style --foreground 46 "✅ Kernel-mode driver installed"
            gum style --foreground 46 "✅ User-mode component: DLL injection"
            gum style --foreground 46 "✅ Rootkit active: Process/file hiding enabled"
            ;;
        *"KEYPLUG"*)
            gum style --foreground 46 --bold "🔌 KEYPLUG BACKDOOR ACTIVE"
            gum style --foreground 46 "✅ Modular architecture loaded"
            gum style --foreground 46 "✅ Plugins: Screenshot, keylogger, file manager"
            gum style --foreground 46 "✅ C2 protocol: Custom over HTTPS"
            ;;
        *"MESSAGETAP"*)
            gum style --foreground 46 --bold "📱 MESSAGETAP SMS INTERCEPTOR"
            gum style --foreground 46 "✅ Telecom database hooks installed"
            gum style --foreground 46 "✅ SMS interception: Active"
            gum style --foreground 46 "✅ Target numbers: Imported from list"
            ;;
        *)
            gum style --foreground 46 "✅ Backdoor deployed: $MALWARE_FAMILY"
            gum style --foreground 46 "✅ C2 callback: $C2_DOMAIN"
            ;;
    esac
    
    echo
    gum style --foreground 46 "✅ C2 connection established"
    gum style --foreground 46 "✅ Beacon interval: 300 seconds (5 minutes)"
    gum style --foreground 46 "✅ Encryption: AES-256 + RSA-2048"
    
    # Fileless execution option
    echo
    if gum confirm "Use fileless execution (PowerShell reflective loading)?"; then
        track_mitre "Execution" "T1620 - Reflective Code Loading"
        gum spin --spinner pulse --title "Reflective DLL injection into memory..." -- sleep 2
        gum style --foreground 46 "✅ Fileless execution (no disk artifacts)"
        gum style --foreground 46 "✅ Injected into: explorer.exe"
        update_stealth -10
    fi
    
    log_action "EXECUTION: $MALWARE_FAMILY deployed on $VICTIM_HOST"
    
    gum confirm "Proceed to persistence?" || exit 0
}

# ============================================================================
# PHASE 5: PERSISTENCE - Winnti Rootkit
# ============================================================================
phase_persistence() {
    phase_banner 5 "PERSISTENCE - LONG-TERM ACCESS (TA0003)"
    
    gum format -- "## Establishing Multiple Persistence Mechanisms"
    
    PERSIST_COUNT=0
    
    # Winnti rootkit driver
    if gum confirm "Install Winnti kernel-mode rootkit driver?"; then
        track_mitre "Persistence" "T1543.003 - Windows Service"
        gum spin --spinner pulse --title "Loading kernel driver via exploited vulnerable driver..." -- sleep 3
        
        gum style --foreground 46 --bold "✅ ROOTKIT DRIVER INSTALLED"
        gum style --foreground 46 "   Driver: WinntiBios64.sys (disguised as BIOS driver)"
        gum style --foreground 46 "   Technique: BYOVD (Bring Your Own Vulnerable Driver)"
        gum style --foreground 46 "   Capabilities: Process hiding, file hiding, network hiding"
        ((PERSIST_COUNT++))
        update_stealth -15  # Very stealthy
    fi
    
    echo
    # DLL side-loading
    if gum confirm "Deploy DLL side-loading persistence?"; then
        track_mitre "Persistence" "T1574.002 - DLL Side-Loading"
        
        LEGITIMATE_APP=$(gum choose \
            "VMware Tools (vmtoolsd.exe)" \
            "Microsoft Defender (MpCmdRun.exe)" \
            "Google Update (GoogleUpdate.exe)")
        
        gum spin --spinner pulse --title "Placing malicious DLL alongside $LEGITIMATE_APP..." -- sleep 2
        
        gum style --foreground 46 "✅ DLL side-loading configured"
        gum style --foreground 46 "   Legitimate app: $LEGITIMATE_APP"
        gum style --foreground 46 "   Malicious DLL: version.dll (loaded first)"
        gum style --foreground 46 "✅ Executed on every reboot"
        ((PERSIST_COUNT++))
    fi
    
    echo
    # Registry run keys (backup)
    if gum confirm "Add registry run key (backup persistence)?"; then
        track_mitre "Persistence" "T1547.001 - Registry Run Keys"
        gum spin --spinner pulse --title "Modifying HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run..." -- sleep 2
        gum style --foreground 46 "✅ Registry key: WindowsUpdateAgent"
        gum style --foreground 46 "   Value: C:\\Windows\\System32\\update.exe"
        ((PERSIST_COUNT++))
    fi
    
    echo
    # Scheduled task
    if gum confirm "Create scheduled task (stealthy)?"; then
        track_mitre "Persistence" "T1053.005 - Scheduled Task"
        TASK_NAME="MicrosoftEdgeUpdateTask$(printf '%02d' $((RANDOM % 99)))"
        gum spin --spinner pulse --title "schtasks /create /tn $TASK_NAME /tr update.exe..." -- sleep 2
        gum style --foreground 46 "✅ Task: $TASK_NAME (runs every 6 hours)"
        gum style --foreground 46 "✅ Hidden from Task Scheduler UI"
        ((PERSIST_COUNT++))
    fi
    
    echo
    # Bootkit (advanced)
    if gum confirm "Install UEFI/BIOS bootkit (firmware persistence)?"; then
        track_mitre "Persistence" "T1542.001 - System Firmware"
        gum spin --spinner pulse --title "Flashing malicious UEFI module..." -- sleep 4
        
        gum style --foreground 46 --bold "✅ UEFI BOOTKIT INSTALLED"
        gum style --foreground 46 "⚠️  Survives OS reinstallation"
        gum style --foreground 46 "⚠️  Survives disk formatting"
        gum style --foreground 46 "⚠️  Extremely difficult to detect"
        ((PERSIST_COUNT++))
        update_stealth -20  # Ultimate stealth
    fi
    
    echo
    gum style --foreground 46 --bold "🔒 $PERSIST_COUNT persistence mechanisms deployed"
    log_action "PERSISTENCE: $PERSIST_COUNT mechanisms (rootkit, DLL side-loading, etc)"
    
    gum confirm "Proceed to privilege escalation?" || exit 0
}

# ============================================================================
# PHASE 6: PRIVILEGE ESCALATION
# ============================================================================
phase_privilege_escalation() {
    phase_banner 6 "PRIVILEGE ESCALATION (TA0004)"
    
    gum format -- "## Escalating to SYSTEM/Administrator"
    
    CURRENT_PRIV="Standard User"
    gum style --foreground 11 "Current: $CURRENT_PRIV"
    
    echo
    ESCALATION_METHOD=$(gum choose --header "Privilege escalation technique:" \
        "Exploit vulnerable signed driver (BYOVD)" \
        "Token impersonation (Juicy Potato)" \
        "Exploit CVE-2021-1732 (Win32k)" \
        "UAC bypass (DLL hijacking)" \
        "PrintNightmare (CVE-2021-34527)")
    
    track_mitre "Privilege Escalation" "T1068 - Exploitation for Privilege Escalation"
    
    gum spin --spinner pulse --title "Executing $ESCALATION_METHOD..." -- sleep 3
    
    if (( RANDOM % 100 < 90 )); then
        gum style --foreground 46 --bold "✅ PRIVILEGE ESCALATION SUCCESSFUL"
        gum style --foreground 46 "✅ Running as: NT AUTHORITY\\SYSTEM"
        gum style --foreground 46 "✅ SeDebugPrivilege: Enabled"
        log_action "PRIVILEGE ESCALATION: Success via $ESCALATION_METHOD"
    else
        gum style --foreground 196 "❌ Escalation failed"
        update_stealth 10
    fi
    
    gum confirm "Proceed to defense evasion?" || exit 0
}

# ============================================================================
# PHASE 7: DEFENSE EVASION - Rootkit Techniques
# ============================================================================
phase_defense_evasion() {
    phase_banner 7 "DEFENSE EVASION - WINNTI ROOTKIT STEALTH (TA0005)"
    
    gum format -- "## Advanced Evasion Techniques"
    
    # Rootkit capabilities
    if [[ "$MALWARE_FAMILY" == *"Winnti"* ]]; then
        gum format -- "### Winnti Rootkit Evasion"
        
        gum style --foreground 46 "✅ Process hiding: Winnti process invisible"
        gum style --foreground 46 "✅ File hiding: All malware files hidden"
        gum style --foreground 46 "✅ Registry hiding: Persistence keys invisible"
        gum style --foreground 46 "✅ Network hiding: C2 connections hidden from netstat"
        
        track_mitre "Defense Evasion" "T1014 - Rootkit"
    fi
    
    echo
    # Code signing bypass
    if gum confirm "Use stolen code signing certificate (bypass AV)?"; then
        track_mitre "Defense Evasion" "T1553.002 - Code Signing"
        gum spin --spinner pulse --title "Signing malware with valid certificate..." -- sleep 2
        gum style --foreground 46 "✅ Code signed with trusted certificate"
        gum style --foreground 46 "✅ Windows Defender: Whitelisted"
        gum style --foreground 46 "✅ Antivirus: Trusted process"
        update_stealth -15
    fi
    
    echo
    # Timestomping
    if gum confirm "Timestomp files (hide implant creation time)?"; then
        track_mitre "Defense Evasion" "T1070.006 - Timestomp"
        gum spin --spinner pulse --title "Modifying file timestamps..." -- sleep 2
        gum style --foreground 46 "✅ File timestamps: Backdated to 2019"
        gum style --foreground 46 "✅ Appears as old system file"
    fi
    
    echo
    # Process injection
    if gum confirm "Inject into legitimate process (hide malicious code)?"; then
        track_mitre "Defense Evasion" "T1055 - Process Injection"
        
        TARGET_PROCESS=$(gum choose "svchost.exe" "explorer.exe" "lsass.exe")
        gum spin --spinner pulse --title "Injecting into $TARGET_PROCESS..." -- sleep 2
        gum style --foreground 46 "✅ Code running in $TARGET_PROCESS context"
        gum style --foreground 46 "✅ Appears as legitimate process activity"
    fi
    
    echo
    # Log clearing
    if gum confirm "Clear Windows Event Logs?"; then
        track_mitre "Defense Evasion" "T1070.001 - Clear Windows Event Logs"
        gum spin --spinner pulse --title "wevtutil cl Security..." -- sleep 2
        gum style --foreground 46 "✅ Security logs cleared"
        gum style --foreground 46 "✅ System logs cleared"
        update_stealth 10  # Noisy action
    fi
    
    echo
    gum style --foreground 11 "Current stealth score: $STEALTH_SCORE/100"
    
    gum confirm "Proceed to credential access?" || exit 0
}

# ============================================================================
# PHASE 8: CREDENTIAL ACCESS
# ============================================================================
phase_credential_access() {
    phase_banner 8 "CREDENTIAL ACCESS - HARVESTING (TA0006)"
    
    gum format -- "## Comprehensive Credential Theft"
    
    # LSASS dumping
    if gum confirm "Dump LSASS process memory (Mimikatz)?"; then
        track_mitre "Credential Access" "T1003.001 - LSASS Memory"
        
        gum spin --spinner pulse --title "Dumping LSASS.exe with rootkit protection..." -- sleep 3
        
        # Generate credentials
        DOMAIN="$(echo $TARGET_ORG | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]')"
        for i in $(seq 1 $(( 5 + RANDOM % 8 ))); do
            CRED="$DOMAIN\\user$i:Pass$(openssl rand -hex 4)"
            HARVESTED_CREDS+=("$CRED")
        done
        
        gum style --foreground 46 "✅ Credentials extracted: ${#HARVESTED_CREDS[@]}"
        
        # Domain admin
        if (( RANDOM % 100 < 55 )); then
            ADMIN_CRED="$DOMAIN\\administrator:$(openssl rand -base64 12)"
            HARVESTED_CREDS+=("$ADMIN_CRED")
            gum style --foreground 46 --bold "🎯 DOMAIN ADMIN CREDENTIAL CAPTURED!"
        fi
    fi
    
    echo
    # SAM database
    if gum confirm "Dump SAM database (local accounts)?"; then
        track_mitre "Credential Access" "T1003.002 - Security Account Manager"
        gum spin --spinner pulse --title "reg save HKLM\\SAM sam.save..." -- sleep 2
        
        LOCAL_ACCOUNTS=$(( 5 + RANDOM % 10 ))
        gum style --foreground 46 "✅ SAM database dumped"
        gum style --foreground 46 "✅ Local accounts: $LOCAL_ACCOUNTS"
        gum style --foreground 46 "✅ NTLM hashes extracted"
    fi
    
    echo
    # Browser credential theft
    if gum confirm "Steal browser saved passwords?"; then
        track_mitre "Credential Access" "T1555.003 - Credentials from Web Browsers"
        gum spin --spinner pulse --title "Extracting Chrome/Firefox credentials..." -- sleep 2
        
        BROWSER_CREDS=$(( 10 + RANDOM % 30 ))
        for i in $(seq 1 3); do
            SITE="banking-site-$i.com:user$i@email.com:$(openssl rand -hex 6)"
            HARVESTED_CREDS+=("$SITE")
        done
        
        gum style --foreground 46 "✅ Browser credentials: $BROWSER_CREDS"
        gum style --foreground 46 "✅ Includes: Banking, email, corporate portals"
    fi
    
    echo
    # Keylogging
    if gum confirm "Deploy keylogger for ongoing credential capture?"; then
        track_mitre "Credential Access" "T1056.001 - Keylogging"
        gum spin --spinner pulse --title "Installing kernel-mode keylogger..." -- sleep 2
        gum style --foreground 46 "✅ Keylogger active (rootkit-protected)"
        gum style --foreground 46 "✅ Logs encrypted and exfiltrated hourly"
    fi
    
    echo
    gum style --foreground 46 --bold "🔑 Total credentials: ${#HARVESTED_CREDS[@]}"
    log_action "CREDENTIAL ACCESS: ${#HARVESTED_CREDS[@]} credentials harvested"
    
    gum confirm "Continue to discovery?" || exit 0
}

# ============================================================================
# PHASE 9: DISCOVERY - Network & AD Enumeration
# ============================================================================
phase_discovery() {
    phase_banner 9 "DISCOVERY - ENVIRONMENT MAPPING (TA0007)"
    
    gum format -- "## Network & Active Directory Reconnaissance"
    
    # Network discovery
    track_mitre "Discovery" "T1018 - Remote System Discovery"
    gum spin --spinner dot --title "Scanning internal network..." -- sleep 3
    
    DISCOVERED_HOSTS=$((50 + RANDOM % 200))
    gum style --foreground 46 "✅ Active hosts: $DISCOVERED_HOSTS"
    
    # Active Directory enumeration
    echo
    track_mitre "Discovery" "T1087.002 - Domain Account"
    gum spin --spinner dot --title "Enumerating Active Directory..." -- sleep 2
    
    AD_USERS=$((500 + RANDOM % 1500))
    GROUPS=$((50 + RANDOM % 150))
    
    gum style --foreground 46 "✅ Domain: $DOMAIN.local"
    gum style --foreground 46 "✅ Domain users: $AD_USERS"
    gum style --foreground 46 "✅ Security groups: $GROUPS"
    gum style --foreground 46 "✅ Domain admins: $((5 + RANDOM % 15))"
    
    # High-value targets
    echo
    gum format -- "### Critical Systems Identification"
    
    case $OPERATIONAL_MODE in
        *"STATE-SPONSORED"*)
            HVT_1=$(gum input --placeholder "Domain Controller" --value "DC01.$DOMAIN.local")
            HVT_2=$(gum input --placeholder "Research Database" --value "RESEARCH-DB-01")
            HVT_3=$(gum input --placeholder "Email Server" --value "EXCH01.$DOMAIN.local")
            ;;
        *"FINANCIAL"*)
            HVT_1=$(gum input --placeholder "Payment Server" --value "PAY-SRV-01")
            HVT_2=$(gum input --placeholder "Game Server" --value "GAME-PROD-01")
            HVT_3=$(gum input --placeholder "License Server" --value "LICENSE-01")
            ;;
        *"DUAL"*)
            HVT_1=$(gum input --placeholder "Domain Controller" --value "DC01.$DOMAIN.local")
            HVT_2=$(gum input --placeholder "Financial Database" --value "FINANCE-DB-01")
            HVT_3=$(gum input --placeholder "Research Server" --value "R&D-SRV-01")
            ;;
    esac
    
    COMPROMISED_HOSTS+=("$HVT_1|10.0.1.10|Windows Server 2019")
    COMPROMISED_HOSTS+=("$HVT_2|10.0.1.50|SQL Server 2019")
    COMPROMISED_HOSTS+=("$HVT_3|10.0.1.20|Windows Server 2016")
    
    gum style --foreground 46 "🎯 Critical systems identified: 3"
    
    log_action "DISCOVERY: $DISCOVERED_HOSTS hosts, $AD_USERS users, 3 HVTs"
    
    gum confirm "Proceed to lateral movement?" || exit 0
}

# ============================================================================
# PHASE 10: LATERAL MOVEMENT
# ============================================================================
phase_lateral_movement() {
    phase_banner 10 "LATERAL MOVEMENT - DOMAIN COMPROMISE (TA0008)"
    
    gum format -- "## Network Propagation & Privilege Expansion"
    
    # Target selection
    if [ ${#COMPROMISED_HOSTS[@]} -gt 1 ]; then
        TARGET_HOST="${COMPROMISED_HOSTS[-1]%%|*}"
    else
        TARGET_HOST="SRV-$(printf '%04d' $((RANDOM % 9999)))"
    fi
    
    echo
    LATERAL_METHOD=$(gum choose --header "Lateral movement technique:" \
        "Pass-the-Hash (Stolen credentials)" \
        "WMI (Windows Management Instrumentation)" \
        "PsExec (Remote service creation)" \
        "RDP (Remote Desktop - stolen creds)" \
        "SMB (Admin share access)" \
        "DCOM (Distributed COM exploitation)")
    
    case $LATERAL_METHOD in
        *"Pass-the-Hash"*)
            track_mitre "Lateral Movement" "T1550.002 - Pass the Hash"
            gum spin --spinner pulse --title "Authenticating with NTLM hash..." -- sleep 2
            ;;
        *"WMI"*)
            track_mitre "Lateral Movement" "T1047 - Windows Management Instrumentation"
            gum spin --spinner pulse --title "wmic /node:$TARGET_HOST process call create..." -- sleep 2
            ;;
        *"PsExec"*)
            track_mitre "Lateral Movement" "T1021.002 - SMB/Windows Admin Shares"
            gum spin --spinner pulse --title "psexec.exe \\\\$TARGET_HOST -s cmd.exe..." -- sleep 2
            ;;
        *"RDP"*)
            track_mitre "Lateral Movement" "T1021.001 - Remote Desktop Protocol"
            gum spin --spinner pulse --title "mstsc /v:$TARGET_HOST /admin..." -- sleep 2
            ;;
        *"SMB"*)
            track_mitre "Lateral Movement" "T1021.002 - SMB/Windows Admin Shares"
            gum spin --spinner pulse --title "net use \\\\$TARGET_HOST\\C$ /user:admin..." -- sleep 2
            ;;
        *"DCOM"*)
            track_mitre "Lateral Movement" "T1021.003 - Distributed Component Object Model"
            gum spin --spinner pulse --title "Exploiting DCOM via MMC20.Application..." -- sleep 2
            ;;
    esac
    
    if (( RANDOM % 100 < 85 )); then
        gum style --foreground 46 --bold "✅ LATERAL MOVEMENT SUCCESSFUL"
        gum style --foreground 46 "✅ Access: $TARGET_HOST"
        log_action "LATERAL MOVEMENT: Success to $TARGET_HOST"
        
        # Deploy malware on new host
        if gum confirm "Deploy $MALWARE_FAMILY on $TARGET_HOST?"; then
            gum spin --spinner pulse --title "Installing backdoor..." -- sleep 2
            gum style --foreground 46 "✅ $MALWARE_FAMILY active on $TARGET_HOST"
            gum style --foreground 46 "✅ Persistence established"
        fi
    else
        gum style --foreground 196 "❌ Lateral movement failed"
        update_stealth 10
    fi
    
    gum confirm "Proceed to collection?" || exit 0
}

# ============================================================================
# PHASE 11: COLLECTION - Data Theft
# ============================================================================
phase_collection() {
    phase_banner 11 "COLLECTION - INTELLECTUAL PROPERTY THEFT (TA0009)"
    
    gum format -- "## Data Collection Operations"
    
    case $OPERATIONAL_MODE in
        *"STATE-SPONSORED"*)
            collect_espionage_data
            ;;
        *"FINANCIAL"*)
            collect_financial_data
            ;;
        *"DUAL"*)
            collect_espionage_data
            echo
            collect_financial_data
            ;;
    esac
}

collect_espionage_data() {
    gum format -- "### State-Sponsored Intelligence Collection"
    
    # Research data
    if gum confirm "Steal research & development data?"; then
        track_mitre "Collection" "T1005 - Data from Local System"
        gum spin --spinner pulse --title "Collecting R&D documents..." -- sleep 3
        
        RND_FILES=$((1000 + RANDOM % 5000))
        RND_SIZE=$((RND_FILES * 2))
        INTELLECTUAL_PROPERTY_SIZE=$((INTELLECTUAL_PROPERTY_SIZE + RND_SIZE))
        
        STOLEN_DATA+=("R&D_Documents:$RND_FILES:${RND_SIZE}MB")
        gum style --foreground 46 "✅ R&D files collected: $RND_FILES ($RND_SIZE MB)"
        gum style --foreground 46 "✅ Includes: Patents, designs, source code"
    fi
    
    echo
    # Email collection
    if gum confirm "Collect executive emails?"; then
        track_mitre "Collection" "T1114.001 - Local Email Collection"
        gum spin --spinner pulse --title "Exporting Exchange mailboxes..." -- sleep 3
        
        EMAIL_COUNT=$((5000 + RANDOM % 15000))
        EMAIL_SIZE=$((EMAIL_COUNT / 10))
        INTELLECTUAL_PROPERTY_SIZE=$((INTELLECTUAL_PROPERTY_SIZE + EMAIL_SIZE))
        
        STOLEN_DATA+=("Emails:$EMAIL_COUNT:${EMAIL_SIZE}MB")
        gum style --foreground 46 "✅ Emails collected: $EMAIL_COUNT ($EMAIL_SIZE MB)"
    fi
    
    echo
    # Database theft
    if gum confirm "Exfiltrate sensitive databases?"; then
        track_mitre "Collection" "T1005 - Data from Local System"
        gum spin --spinner pulse --title "Dumping SQL databases..." -- sleep 4
        
        DB_SIZE=$((500 + RANDOM % 3000))
        INTELLECTUAL_PROPERTY_SIZE=$((INTELLECTUAL_PROPERTY_SIZE + DB_SIZE))
        
        STOLEN_DATA+=("Databases:5_databases:${DB_SIZE}MB")
        gum style --foreground 46 "✅ Databases exfiltrated: 5 (${DB_SIZE} MB)"
        gum style --foreground 46 "✅ Customer data, research data, financial records"
    fi
}

collect_financial_data() {
    gum format -- "### Financial Cybercrime Collection"
    
    # Payment card data
    if gum confirm "Steal payment card data (PCI)?"; then
        track_mitre "Collection" "T1005 - Data from Local System"
        gum spin --spinner pulse --title "Harvesting payment card database..." -- sleep 3
        
        CARD_COUNT=$((10000 + RANDOM % 50000))
        
        gum style --foreground 46 --bold "💳 PAYMENT CARDS STOLEN: $CARD_COUNT"
        gum style --foreground 46 "✅ Full card details (PAN, CVV, expiry)"
        
        FINANCIAL_GAIN=$((CARD_COUNT / 100))
        STOLEN_DATA+=("PaymentCards:$CARD_COUNT:PII")
    fi
    
    echo
    # Gaming virtual currency
    if gum confirm "Steal gaming virtual currency/items?"; then
        track_mitre "Collection" "T1005 - Data from Local System"
        gum spin --spinner pulse --title "Accessing game database..." -- sleep 2
        
        VIRTUAL_ITEMS=$((50000 + RANDOM % 200000))
        VALUE=$((VIRTUAL_ITEMS / 1000))
        
        gum style --foreground 46 "✅ Virtual items stolen: $VIRTUAL_ITEMS"
        gum style --foreground 46 "✅ Estimated value: \$$VALUE USD"
        
        FINANCIAL_GAIN=$((FINANCIAL_GAIN + VALUE))
        STOLEN_DATA+=("VirtualGoods:$VIRTUAL_ITEMS:\$${VALUE}")
    fi
    
    echo
    # Cryptocurrency wallets
    if gum confirm "Search for cryptocurrency wallets?"; then
        track_mitre "Collection" "T1005 - Data from Local System"
        gum spin --spinner pulse --title "Scanning for wallet files..." -- sleep 2
        
        WALLETS_FOUND=$(( RANDOM % 5 ))
        if [ $WALLETS_FOUND -gt 0 ]; then
            CRYPTO_VALUE=$(( 10 + RANDOM % 100 ))
            gum style --foreground 46 "✅ Crypto wallets found: $WALLETS_FOUND"
            gum style --foreground 46 "✅ Estimated value: \$$CRYPTO_VALUE thousand"
            FINANCIAL_GAIN=$((FINANCIAL_GAIN + CRYPTO_VALUE))
        else
            gum style --foreground 11 "⚠️  No cryptocurrency wallets found"
        fi
    fi
}

# Continue in next part due to length...
gum confirm "Proceed to command & control?" || exit 0
}

# ============================================================================
# PHASE 12: COMMAND & CONTROL
# ============================================================================
phase_command_control() {
    phase_banner 12 "COMMAND & CONTROL - COVERT CHANNELS (TA0011)"
    
    gum format -- "## C2 Infrastructure & Communication"
    
    track_mitre "Command and Control" "T1071.001 - Web Protocols"
    
    gum style --foreground 46 "✅ C2 Protocol: HTTPS (port 443)"
    gum style --foreground 46 "✅ C2 Domain: $C2_DOMAIN"
    gum style --foreground 46 "✅ Beacon interval: 300 seconds (jitter: ±60s)"
    gum style --foreground 46 "✅ Encryption: Custom AES-256 + RSA"
    
    echo
    gum format -- "### Domain Generation Algorithm (DGA)"
    
    if gum confirm "Activate DGA for C2 resilience?"; then
        track_mitre "Command and Control" "T1568.002 - Domain Generation Algorithms"
        gum spin --spinner pulse --title "Generating fallback C2 domains..." -- sleep 2
        
        for i in $(seq 1 3); do
            DGA_DOMAIN="$(openssl rand -hex 8).com"
            gum style --foreground 46 "   Fallback C2 #$i: $DGA_DOMAIN"
        done
        
        gum style --foreground 46 "✅ DGA active (20 domains/day)"
    fi
    
    echo
    gum format -- "### Encrypted Communication"
    track_mitre "Command and Control" "T1573.001 - Symmetric Cryptography"
    
    gum style --foreground 46 "✅ Traffic encryption: AES-256-CBC"
    gum style --foreground 46 "✅ SSL pinning: Custom CA certificate"
    gum style --foreground 46 "✅ Traffic obfuscation: Mimics legitimate HTTPS"
    
    log_action "C2: HTTPS to $C2_DOMAIN with DGA fallback"
    
    gum confirm "Continue to exfiltration?" || exit 0
}

# ============================================================================
# PHASE 13: EXFILTRATION
# ============================================================================
phase_exfiltration() {
    phase_banner 13 "EXFILTRATION - DATA EXTRACTION (TA0010)"
    
    gum format -- "## Covert Data Exfiltration"
    
    if [ ${#STOLEN_DATA[@]} -eq 0 ]; then
        gum style --foreground 196 "⚠️  No data collected for exfiltration"
        return
    fi
    
    # Display collected data
    gum format -- "### Staged Data for Exfiltration"
    TOTAL_SIZE=0
    for item in "${STOLEN_DATA[@]}"; do
        IFS=':' read -r type count size <<< "$item"
        echo "  📦 $type: $count items ($size)"
        
        # Calculate total size (if numeric)
        if [[ "$size" =~ ^[0-9]+MB$ ]]; then
            SIZE_NUM=$(echo $size | sed 's/MB//')
            TOTAL_SIZE=$((TOTAL_SIZE + SIZE_NUM))
        fi
    done
    
    echo
    gum format -- "### Exfiltration Method"
    
    EXFIL_METHOD=$(gum choose \
        "C2 channel (HTTPS beacon)" \
        "Cloud storage (compromised account)" \
        "FTP to attacker server" \
        "DNS tunneling (covert channel)" \
        "Email (encrypted attachments)")
    
    case $EXFIL_METHOD in
        *"C2 channel"*)
            track_mitre "Exfiltration" "T1041 - Exfiltration Over C2 Channel"
            ;;
        *"Cloud storage"*)
            track_mitre "Exfiltration" "T1567.002 - Exfiltration to Cloud Storage"
            ;;
        *"FTP"*)
            track_mitre "Exfiltration" "T1048.003 - Exfiltration Over Alternative Protocol"
            ;;
        *"DNS"*)
            track_mitre "Exfiltration" "T1048.002 - Exfiltration Over Alternative Protocol"
            ;;
        *"Email"*)
            track_mitre "Exfiltration" "T1048.003 - Exfiltration Over Alternative Protocol"
            ;;
    esac
    
    # Compression & encryption
    echo
    if gum confirm "Compress and encrypt exfiltration data?"; then
        track_mitre "Exfiltration" "T1560.001 - Archive via Utility"
        gum spin --spinner pulse --title "7z a -p$(openssl rand -hex 8) -mhe=on data.7z..." -- sleep 2
        COMPRESSED_SIZE=$((TOTAL_SIZE / 3))
        gum style --foreground 46 "✅ Compressed: ${TOTAL_SIZE}MB → ${COMPRESSED_SIZE}MB"
        TOTAL_SIZE=$COMPRESSED_SIZE
    fi
    
    # Throttling
    echo
    gum format -- "### Exfiltration Rate Limiting (Stealth)"
    
    THROTTLE=$(gum choose \
        "Slow (10KB/s - maximum stealth)" \
        "Moderate (100KB/s)" \
        "Fast (1MB/s - higher risk)")
    
    case $THROTTLE in
        *"Slow"*)
            EXFIL_TIME=$((TOTAL_SIZE * 100))
            ;;
        *"Moderate"*)
            EXFIL_TIME=$((TOTAL_SIZE * 10))
            update_stealth 5
            ;;
        *"Fast"*)
            EXFIL_TIME=$((TOTAL_SIZE))
            update_stealth 15
            ;;
    esac
    
    # Execute exfiltration
    echo
    if [ $TOTAL_SIZE -gt 0 ]; then
        gum spin --spinner meter --title "Exfiltrating ${TOTAL_SIZE}MB via $EXFIL_METHOD..." -- sleep $((EXFIL_TIME < 10 ? EXFIL_TIME : 10))
    else
        gum spin --spinner meter --title "Exfiltrating collected data via $EXFIL_METHOD..." -- sleep 5
    fi
    
    if (( RANDOM % 100 < (STEALTH_SCORE - 5) )); then
        gum style --foreground 46 --bold "✅ EXFILTRATION COMPLETE"
        gum style --foreground 46 "✅ Data transferred successfully"
        gum style --foreground 46 "✅ Destination: APT41 collection infrastructure (China)"
        
        log_action "EXFILTRATION: Success via $EXFIL_METHOD"
    else
        gum style --foreground 196 "❌ EXFILTRATION DETECTED - DLP Alert"
        update_stealth 30
        log_action "EXFILTRATION: Detected and blocked"
    fi
    
    gum confirm "Proceed to impact/cleanup?" || exit 0
}

# ============================================================================
# PHASE 14: IMPACT & CLEANUP
# ============================================================================
phase_impact() {
    phase_banner 14 "IMPACT & CLEANUP (TA0040)"
    
    gum format -- "## Post-Exploitation Actions"
    
    # APT41 typically maintains long-term access
    gum style --foreground 11 "ℹ️  APT41 typically maintains long-term stealthy access"
    gum style --foreground 11 "ℹ️  Avoid destructive actions unless specific operational need"
    
    echo
    if gum confirm "Deploy additional backdoors for persistence?"; then
        EXTRA_BACKDOOR=$(gum choose \
            "Web shell on IIS server" \
            "Second rootkit (backup access)" \
            "SSH backdoor on Linux servers")
        
        gum spin --spinner pulse --title "Installing $EXTRA_BACKDOOR..." -- sleep 2
        gum style --foreground 46 "✅ Backup access: $EXTRA_BACKDOOR"
        log_action "BACKDOOR: $EXTRA_BACKDOOR for long-term access"
    fi
    
    echo
    gum format -- "## Operational Security Cleanup"
    
    CLEANUP_LEVEL=$(gum choose \
        "Minimal - Maintain all access (stealth priority)" \
        "Moderate - Remove obvious artifacts" \
        "Extensive - Cover all tracks (mission complete)")
    
    case $CLEANUP_LEVEL in
        *"Minimal"*)
            gum spin --spinner dot --title "Light cleanup..." -- sleep 1
            gum style --foreground 11 "✅ Minimal cleanup - All backdoors remain"
            gum style --foreground 11 "✅ Rootkit protecting all artifacts"
            ;;
        *"Moderate"*)
            track_mitre "Defense Evasion" "T1070 - Indicator Removal"
            gum spin --spinner pulse --title "Removing obvious IOCs..." -- sleep 3
            gum style --foreground 46 "✅ Temporary files deleted"
            gum style --foreground 46 "✅ Event logs selectively cleared"
            gum style --foreground 46 "✅ Rootkit and primary backdoors remain"
            ;;
        *"Extensive"*)
            track_mitre "Defense Evasion" "T1070 - Indicator Removal"
            gum spin --spinner pulse --title "Full sanitization..." -- sleep 4
            gum style --foreground 46 "✅ All logs cleared"
            gum style --foreground 46 "✅ Temporary artifacts removed"
            gum style --foreground 46 "✅ Secondary backdoors removed"
            gum style --foreground 11 "⚠️  Primary rootkit remains (UEFI persistence)"
            update_stealth -10
            ;;
    esac
    
    log_action "CLEANUP: $CLEANUP_LEVEL - Mission phase complete"
}

# ============================================================================
# MISSION REPORT
# ============================================================================
generate_report() {
    local mission_end=$(date +%s)
    local duration=$((mission_end - MISSION_START))
    local duration_min=$((duration / 60))
    
    clear
    gum style \
        --foreground 208 --border-foreground 208 --border double \
        --width 90 --align center --padding "2 4" --bold \
        "🎖️  MISSION COMPLETE" \
        "APT41 (Double Dragon) Operation - MSS Success"
    
    echo
    gum format -- "## Mission Statistics"
    
    gum table --border rounded --widths 40,40 <<EOF
Metric,Value
Operational Mode,$OPERATIONAL_MODE
Mission Duration,${duration_min} minutes
Compromised Hosts,${#COMPROMISED_HOSTS[@]}
Credentials Harvested,${#HARVESTED_CREDS[@]}
IP Stolen (MB),$INTELLECTUAL_PROPERTY_SIZE
Financial Gain,\$$FINANCIAL_GAIN thousand
Detection Events,$DETECTION_EVENTS
Final Stealth Score,$STEALTH_SCORE/100
MITRE Techniques,${#MITRE_TECHNIQUES[@]}
EOF
    
    echo
    gum format -- "## MITRE ATT&CK Coverage (APT41/G0096)"
    
    for tactic in "${!MITRE_TECHNIQUES[@]}"; do
        echo "  ✅ $tactic: ${MITRE_TECHNIQUES[$tactic]}"
    done
    
    echo
    gum format -- "## Compromised Assets"
    
    for host in "${COMPROMISED_HOSTS[@]}"; do
        IFS='|' read -r hostname ip os <<< "$host"
        echo "  🖥️  $hostname ($ip) - $os"
    done
    
    echo
    gum format -- "## Stolen Data Summary"
    
    if [ ${#STOLEN_DATA[@]} -gt 0 ]; then
        for item in "${STOLEN_DATA[@]}"; do
            IFS=':' read -r type count size <<< "$item"
            echo "  📦 $type: $count ($size)"
        done
    else
        echo "  ℹ️  No data exfiltration performed"
    fi
    
    echo
    gum format -- "## Mission Assessment"
    
    case $OPERATIONAL_MODE in
        *"STATE-SPONSORED"*)
            if [ $INTELLECTUAL_PROPERTY_SIZE -gt 1000 ]; then
                gum style --foreground 46 "🏆 HIGH-VALUE INTELLIGENCE: ${INTELLECTUAL_PROPERTY_SIZE}MB for MSS"
            else
                gum style --foreground 11 "💼 MODERATE INTELLIGENCE GAIN"
            fi
            ;;
        *"FINANCIAL"*)
            if [ $FINANCIAL_GAIN -gt 100 ]; then
                gum style --foreground 46 "💰 PROFITABLE OPERATION: \$$FINANCIAL_GAIN thousand"
            else
                gum style --foreground 11 "💸 MODERATE FINANCIAL GAIN"
            fi
            ;;
        *"DUAL"*)
            gum style --foreground 46 "🎯 DUAL SUCCESS:"
            gum style --foreground 46 "   State Intelligence: ${INTELLECTUAL_PROPERTY_SIZE}MB"
            gum style --foreground 46 "   Financial Profit: \$$FINANCIAL_GAIN thousand"
            ;;
    esac
    
    echo
    if [ $STEALTH_SCORE -gt 75 ]; then
        gum style --foreground 46 "🕵️  OPERATIONAL SECURITY: Excellent (Winnti stealth)"
    elif [ $STEALTH_SCORE -gt 50 ]; then
        gum style --foreground 11 "⚠️  OPERATIONAL SECURITY: Moderate detection risk"
    else
        gum style --foreground 196 "❌ OPERATIONAL SECURITY: High attribution probability"
    fi
    
    echo
    gum style --foreground 240 "Detailed log: $LOG_FILE"
    
    echo
    if gum confirm "Save mission report for APT41 group?"; then
        REPORT_FILE="/tmp/apt41-report-$(date +%Y%m%d-%H%M%S).txt"
        {
            echo "============================================"
            echo "APT41 (DOUBLE DRAGON) MISSION REPORT"
            echo "MSS Cyber Operations - Dual Purpose"
            echo "Generated: $(date)"
            echo "============================================"
            echo
            echo "OPERATIONAL MODE: $OPERATIONAL_MODE"
            echo "DURATION: ${duration_min} minutes"
            echo "STEALTH SCORE: $STEALTH_SCORE/100"
            echo "IP STOLEN: ${INTELLECTUAL_PROPERTY_SIZE}MB"
            echo "FINANCIAL GAIN: \$$FINANCIAL_GAIN thousand"
            echo
            echo "COMPROMISED HOSTS:"
            for host in "${COMPROMISED_HOSTS[@]}"; do
                echo "  - $host"
            done
            echo
            echo "CREDENTIALS:"
            for cred in "${HARVESTED_CREDS[@]}"; do
                echo "  - $cred"
            done
            echo
            echo "STOLEN DATA:"
            for item in "${STOLEN_DATA[@]}"; do
                echo "  - $item"
            done
        } > "$REPORT_FILE"
        
        gum style --foreground 46 "✅ Report saved: $REPORT_FILE"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    check_dependencies
    
    mission_briefing
    phase_reconnaissance
    phase_resource_development
    phase_initial_access
    phase_execution
    phase_persistence
    phase_privilege_escalation
    phase_defense_evasion
    phase_credential_access
    phase_discovery
    phase_lateral_movement
    phase_collection
    phase_command_control
    phase_exfiltration
    phase_impact
    
    generate_report
    
    echo
    gum style --foreground 208 --bold "🇨🇳 Mission complete. 任务完成 (Rènwù wánchéng)"
}

# Run main
main
