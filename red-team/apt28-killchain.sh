#!/bin/bash
# ============================================================================
# APT28 (Fancy Bear / Sofacy / Pawn Storm) Full Kill Chain Simulator
# ============================================================================
# Comprehensive red team training simulator covering complete APT28 TTPs
# Based on MITRE ATT&CK Group G0007 and documented Fancy Bear operations
# Make executable: chmod +x apt28-killchain.sh
# ============================================================================

set -euo pipefail
trap cleanup INT TERM

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
VERSION="1.0"
LOG_FILE="/tmp/apt28-mission-$(date +%Y%m%d-%H%M%S).log"
MISSION_START=$(date +%s)

# Mission state tracking
declare -a COMPROMISED_HOSTS=()
declare -a HARVESTED_CREDS=()
declare -a STOLEN_DATA=()
declare -A MITRE_TECHNIQUES=()
STEALTH_SCORE=100
DETECTION_EVENTS=0
EXFIL_SIZE=0

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
check_dependencies() {
    if ! command -v gum &> /dev/null; then
        echo "❌ ERROR: gum is required"
        echo "Install: brew install gum"
        echo "Or: go install github.com/charmbracelet/gum@latest"
        exit 1
    fi
}

log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

cleanup() {
    echo
    gum style --foreground 11 "🚨 Mission aborted by operator"
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

# ============================================================================
# MISSION PHASES
# ============================================================================

phase_banner() {
    local phase_num=$1
    local phase_name=$2
    clear
    gum style \
        --foreground 212 --border-foreground 212 --border double \
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
        --foreground 196 --background 0 --border-foreground 196 --border double \
        --width 90 --align center --padding "3 4" --bold \
        "🇷🇺 APT28 FANCY BEAR" \
        "GRU Main Directorate Unit 26165 / 74455" \
        "" \
        "Full Cyber Kill Chain Simulator v${VERSION}"
    
    echo
    
    gum format -- "# Mission Parameters"
    gum format -- "**Threat Actor**: APT28 (Fancy Bear, Sofacy, Pawn Storm, Sednit)"
    gum format -- "**Attribution**: GRU (Russian Military Intelligence)"
    gum format -- "**MITRE Group**: G0007"
    gum format -- "**Primary Objectives**: Political espionage, credential theft, intelligence collection"
    gum format -- "**Notable Campaigns**: DNC breach (2016), Olympic Destroyer, VPNFilter"
    
    echo
    
    if ! gum confirm "Begin operation?"; then
        echo "Mission cancelled"
        exit 0
    fi
    
    log_action "=== APT28 MISSION START ==="
}

# ============================================================================
# PHASE 1: RECONNAISSANCE (TA0043)
# ============================================================================
phase_reconnaissance() {
    phase_banner 1 "RECONNAISSANCE (TA0043)"
    
    gum format -- "## Target Selection"
    TARGET_ORG=$(gum choose --header "Select primary target:" \
        "US State Department" \
        "NATO Command Structure" \
        "Ukrainian Ministry of Defense" \
        "German Parliament (Bundestag)" \
        "Democratic National Committee" \
        "Anti-Doping Agency (WADA)" \
        "European Energy Sector")
    
    log_action "TARGET: $TARGET_ORG"
    track_mitre "Reconnaissance" "T1589.002 - Email Addresses"
    
    echo
    gum spin --title "Performing OSINT collection..." --spinner dot -- sleep 2
    
    # Active Scanning
    gum format -- "### Active Scanning (T1595)"
    RECON_TYPE=$(gum choose --header "Reconnaissance method:" \
        "Social media harvesting (LinkedIn, Twitter)" \
        "DNS enumeration and subdomain discovery" \
        "Public document metadata mining" \
        "Watering hole identification")
    
    track_mitre "Reconnaissance" "T1595 - Active Scanning"
    gum spin --title "Executing: $RECON_TYPE..." -- sleep 3
    
    # Results
    EMPLOYEE_COUNT=$((500 + RANDOM % 2000))
    EMAIL_COUNT=$((200 + RANDOM % 800))
    
    gum style --foreground 46 "✅ Employees identified: $EMPLOYEE_COUNT"
    gum style --foreground 46 "✅ Email addresses harvested: $EMAIL_COUNT"
    gum style --foreground 46 "✅ VPN infrastructure mapped: 12 gateways"
    gum style --foreground 46 "✅ Key personnel identified: 47 high-value targets"
    
    # Identify targets
    echo
    gum format -- "### High-Value Targets"
    TARGET_INDIVIDUAL=$(gum input --placeholder "Primary target (e.g., john.podesta@example.gov)")
    TARGET_ROLE=$(gum input --placeholder "Target's role (e.g., Chief of Staff)")
    
    log_action "HVT: $TARGET_INDIVIDUAL ($TARGET_ROLE)"
    
    gum confirm "Proceed to weaponization?" || exit 0
}

# ============================================================================
# PHASE 2: WEAPONIZATION & RESOURCE DEVELOPMENT (TA0042)
# ============================================================================
phase_weaponization() {
    phase_banner 2 "WEAPONIZATION & RESOURCE DEVELOPMENT (TA0042)"
    
    gum format -- "## Infrastructure Preparation"
    
    # C2 Infrastructure
    C2_INFRA=$(gum choose --header "Command & Control infrastructure:" \
        "Dedicated VPS network (Netherlands, Lithuania)" \
        "Compromised legitimate sites" \
        "Tor hidden services" \
        "Cloud hosting (AWS, Azure)")
    
    track_mitre "Resource Development" "T1583.003 - Virtual Private Server"
    gum spin --title "Provisioning C2 infrastructure: $C2_INFRA..." -- sleep 2
    
    C2_IP="185.220.101.$((10 + RANDOM % 240))"
    C2_DOMAIN="security-update-$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1).com"
    
    gum style --foreground 46 "✅ C2 Server: $C2_IP"
    gum style --foreground 46 "✅ C2 Domain: $C2_DOMAIN"
    
    echo
    gum format -- "## Payload Development"
    
    PAYLOAD_TYPE=$(gum choose --header "Select malware family:" \
        "X-Agent (CHOPSTICK) - Full-featured backdoor" \
        "X-Tunnel - Network tunneling tool" \
        "Komplex - macOS implant" \
        "Zebrocy (Zebro) - Delphi/AutoIt downloader" \
        "JHUHUGIT - Trojan" \
        "Cannon - Email-based backdoor")
    
    track_mitre "Resource Development" "T1587.001 - Malware"
    
    echo
    gum spin --title "Compiling $PAYLOAD_TYPE with obfuscation..." -- sleep 3
    
    # Exploit selection
    EXPLOIT=$(gum choose --header "Delivery exploit:" \
        "CVE-2017-0199 - RTF/HTA exploit" \
        "CVE-2017-11882 - Equation Editor exploit" \
        "CVE-2018-8174 - VBScript engine RCE" \
        "Macro-enabled document (social engineering)")
    
    track_mitre "Resource Development" "T1588.005 - Exploits"
    gum style --foreground 46 "✅ Weaponized exploit: $EXPLOIT"
    gum style --foreground 46 "✅ Payload compiled with anti-AV techniques"
    gum style --foreground 46 "✅ Code signing certificate (stolen/forged)"
    
    log_action "WEAPONIZATION: $PAYLOAD_TYPE via $EXPLOIT"
    
    gum confirm "Ready for initial access phase?" || exit 0
}

# ============================================================================
# PHASE 3: INITIAL ACCESS (TA0001)
# ============================================================================
phase_initial_access() {
    phase_banner 3 "INITIAL ACCESS (TA0001)"
    
    gum format -- "## Spear-Phishing Campaign"
    track_mitre "Initial Access" "T1566.001 - Spearphishing Attachment"
    
    # Phishing setup
    PHISH_LURE=$(gum choose --header "Phishing lure theme:" \
        "Security alert: Password reset required" \
        "Meeting invitation from senior official" \
        "Leaked document of interest" \
        "Software update notification" \
        "HR policy update")
    
    PHISH_FILE=$(gum input --placeholder "Attachment filename (e.g., NATO_Summit_Agenda.docx)" \
        --value "SecureDocument_$(date +%m%d).docx")
    
    echo
    gum format -- "### Email Crafting"
    gum write --height 5 --placeholder "Compose spear-phishing email body..." > /tmp/phish_body.txt
    
    echo
    gum spin --title "Sending phishing email to $TARGET_INDIVIDUAL..." -- sleep 3
    
    # Infection simulation
    OPEN_RATE=$((5 + RANDOM % 15))
    echo
    gum style --foreground 11 "📧 Email delivered: $(date '+%Y-%m-%d %H:%M')"
    gum style --foreground 11 "⏳ Waiting for user interaction..."
    
    gum spin --title "Monitoring..." -- sleep 5
    
    if gum confirm "Did target open attachment? (Success: ${OPEN_RATE}% typical)"; then
        gum style --foreground 46 "✅ CLICK EVENT DETECTED!"
        gum spin --title "Exploit executing $EXPLOIT..." -- sleep 2
        
        VICTIM_HOSTNAME="$(echo $TARGET_ORG | tr ' ' '-' | tr '[:upper:]' '[:lower:]')-wks-$(printf '%04d' $((RANDOM % 9999)))"
        VICTIM_IP="10.$(( RANDOM % 255 )).$(( RANDOM % 255 )).$(( RANDOM % 254 + 1 ))"
        VICTIM_OS=$(gum choose "Windows 10 Enterprise" "Windows 11 Pro" "macOS 13 Ventura")
        
        COMPROMISED_HOSTS+=("$VICTIM_HOSTNAME|$VICTIM_IP|$VICTIM_OS")
        
        gum style --foreground 46 --bold "🎯 FOOTHOLD ESTABLISHED"
        echo "  Host: $VICTIM_HOSTNAME"
        echo "  IP: $VICTIM_IP"
        echo "  OS: $VICTIM_OS"
        echo "  User: $TARGET_INDIVIDUAL"
        
        log_action "INITIAL ACCESS: $VICTIM_HOSTNAME ($VICTIM_IP)"
    else
        gum style --foreground 196 "❌ Target did not open attachment"
        if gum confirm "Retry with different lure?"; then
            phase_initial_access
            return
        else
            echo "Mission failed: No initial access"
            exit 1
        fi
    fi
    
    gum confirm "Proceed to execution?" || exit 0
}

# ============================================================================
# PHASE 4: EXECUTION (TA0002)
# ============================================================================
phase_execution() {
    phase_banner 4 "EXECUTION (TA0002)"
    
    gum format -- "## Malware Deployment"
    track_mitre "Execution" "T1059.001 - PowerShell"
    
    # Stage 1: Dropper
    gum spin --title "Stage 1: Dropper executing shellcode..." -- sleep 2
    gum style --foreground 46 "✅ Process injection into explorer.exe"
    
    # Stage 2: Downloader
    echo
    gum format -- "### Stage 2: Payload Download"
    gum spin --title "Downloading $PAYLOAD_TYPE from $C2_DOMAIN..." -- sleep 3
    track_mitre "Execution" "T1204.002 - Malicious File"
    
    gum style --foreground 46 "✅ $PAYLOAD_TYPE downloaded (248KB)"
    gum style --foreground 46 "✅ Reflective DLL injection successful"
    
    # Execution techniques
    echo
    EXEC_METHOD=$(gum choose --header "Execution method:" \
        "PowerShell Empire stager" \
        "WMI command execution" \
        "Scheduled task creation" \
        "Service installation")
    
    track_mitre "Execution" "T1053.005 - Scheduled Task"
    gum spin --title "Executing via $EXEC_METHOD..." -- sleep 2
    
    gum style --foreground 46 --bold "✅ X-Agent implant active"
    gum style --foreground 46 "✅ Callback to C2: $C2_IP:443"
    gum style --foreground 46 "✅ Encrypted C2 channel established"
    
    log_action "EXECUTION: $PAYLOAD_TYPE via $EXEC_METHOD"
    
    gum confirm "Continue to persistence?" || exit 0
}

# ============================================================================
# PHASE 5: PERSISTENCE (TA0003)
# ============================================================================
phase_persistence() {
    phase_banner 5 "PERSISTENCE (TA0003)"
    
    gum format -- "## Establishing Persistence Mechanisms"
    
    PERSIST_COUNT=0
    
    # Multiple persistence methods (APT28 uses defense in depth)
    gum format -- "### Method 1: Registry Modification"
    if gum confirm "Install registry run key?"; then
        track_mitre "Persistence" "T1547.001 - Registry Run Keys"
        REG_KEY="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth"
        gum spin --title "reg add $REG_KEY..." -- sleep 2
        gum style --foreground 46 "✅ Registry persistence: $REG_KEY"
        ((PERSIST_COUNT++))
    fi
    
    echo
    gum format -- "### Method 2: Scheduled Task"
    if gum confirm "Create scheduled task?"; then
        track_mitre "Persistence" "T1053.005 - Scheduled Task"
        TASK_NAME="MicrosoftEdgeUpdateTask$(printf '%02d' $((RANDOM % 99)))"
        gum spin --title "schtasks /create /tn $TASK_NAME..." -- sleep 2
        gum style --foreground 46 "✅ Scheduled task: $TASK_NAME (runs every 4 hours)"
        ((PERSIST_COUNT++))
    fi
    
    echo
    gum format -- "### Method 3: WMI Event Subscription"
    if gum confirm "Install WMI persistence?"; then
        track_mitre "Persistence" "T1546.003 - WMI Event Subscription"
        gum spin --title "Register-WmiEvent -Query..." -- sleep 2
        gum style --foreground 46 "✅ WMI event consumer registered"
        ((PERSIST_COUNT++))
    fi
    
    echo
    gum format -- "### Method 4: Service Installation"
    if gum confirm "Install Windows service?"; then
        track_mitre "Persistence" "T1543.003 - Windows Service"
        SERVICE_NAME="WinDefenderUpdate"
        gum spin --title "sc create $SERVICE_NAME binPath=..." -- sleep 2
        gum style --foreground 46 "✅ Service installed: $SERVICE_NAME"
        ((PERSIST_COUNT++))
    fi
    
    echo
    gum style --foreground 46 --bold "🔒 $PERSIST_COUNT persistence mechanisms deployed"
    log_action "PERSISTENCE: $PERSIST_COUNT mechanisms active"
    
    gum confirm "Proceed to privilege escalation?" || exit 0
}

# ============================================================================
# PHASE 6: PRIVILEGE ESCALATION (TA0004)
# ============================================================================
phase_privilege_escalation() {
    phase_banner 6 "PRIVILEGE ESCALATION (TA0004)"
    
    gum format -- "## Escalating to SYSTEM Privileges"
    
    CURRENT_PRIV=$(gum choose --header "Current privilege level:" \
        "Standard User" \
        "Local Administrator" \
        "Domain User")
    
    if [ "$CURRENT_PRIV" = "Local Administrator" ]; then
        gum style --foreground 11 "⚠️  Already elevated - escalating to SYSTEM"
    fi
    
    echo
    ESCALATION_METHOD=$(gum choose --header "Privilege escalation technique:" \
        "Token impersonation (Rotten Potato)" \
        "UAC bypass (Fodhelper)" \
        "Kernel exploit (CVE-2019-0808)" \
        "DLL hijacking" \
        "Service misconfiguration abuse")
    
    track_mitre "Privilege Escalation" "T1068 - Exploitation for Privilege Escalation"
    
    gum spin --title "Executing $ESCALATION_METHOD..." -- sleep 3
    
    if (( RANDOM % 100 < 85 )); then
        gum style --foreground 46 --bold "✅ PRIVILEGE ESCALATION SUCCESSFUL"
        gum style --foreground 46 "✅ Running as: NT AUTHORITY\\SYSTEM"
        log_action "PRIVILEGE ESCALATION: Success via $ESCALATION_METHOD"
    else
        gum style --foreground 196 "❌ Escalation failed - EDR detection"
        update_stealth 20
        if gum confirm "Retry with different technique?"; then
            phase_privilege_escalation
            return
        fi
    fi
    
    gum confirm "Continue to defense evasion?" || exit 0
}

# ============================================================================
# PHASE 7: DEFENSE EVASION (TA0005)
# ============================================================================
phase_defense_evasion() {
    phase_banner 7 "DEFENSE EVASION (TA0005)"
    
    gum format -- "## Evading Security Controls"
    
    # Detect EDR/AV
    gum spin --title "Detecting security products..." -- sleep 2
    
    DETECTED_EDR=$(gum choose --header "Detected endpoint protection:" \
        "CrowdStrike Falcon" \
        "Microsoft Defender for Endpoint" \
        "SentinelOne" \
        "Carbon Black" \
        "Trend Micro Apex One" \
        "None detected")
    
    echo
    if [ "$DETECTED_EDR" != "None detected" ]; then
        gum style --foreground 11 "⚠️  Detected: $DETECTED_EDR"
        
        EVASION_TACTIC=$(gum choose --header "Evasion technique:" \
            "Process hollowing / injection" \
            "Disable Windows Defender (reg)" \
            "Obfuscate PowerShell commands" \
            "Timestomping (modify file timestamps)" \
            "Rootkit deployment" \
            "Clear event logs")
        
        case $EVASION_TACTIC in
            *"Process hollowing"*)
                track_mitre "Defense Evasion" "T1055 - Process Injection"
                gum spin --title "Injecting into svchost.exe..." -- sleep 2
                gum style --foreground 46 "✅ Process injection successful"
                ;;
            *"Disable"*)
                track_mitre "Defense Evasion" "T1562.001 - Disable or Modify Tools"
                gum spin --title "Set-MpPreference -DisableRealtimeMonitoring..." -- sleep 2
                update_stealth 30
                gum style --foreground 11 "⚠️  High detection risk - EDR alert likely"
                ;;
            *"Obfuscate"*)
                track_mitre "Defense Evasion" "T1027 - Obfuscated Files or Information"
                gum spin --title "Encoding PowerShell with XOR+Base64..." -- sleep 2
                gum style --foreground 46 "✅ Commands obfuscated"
                ;;
            *"Timestomping"*)
                track_mitre "Defense Evasion" "T1070.006 - Timestomp"
                gum spin --title "Modifying MACE timestamps..." -- sleep 2
                gum style --foreground 46 "✅ Timestamps altered"
                ;;
            *"Rootkit"*)
                track_mitre "Defense Evasion" "T1014 - Rootkit"
                gum spin --title "Loading kernel driver..." -- sleep 3
                update_stealth 25
                gum style --foreground 46 "✅ Kernel-mode rootkit active"
                ;;
            *"Clear"*)
                track_mitre "Defense Evasion" "T1070.001 - Clear Windows Event Logs"
                gum spin --title "wevtutil cl Security..." -- sleep 2
                update_stealth 40
                gum style --foreground 196 "⚠️  CRITICAL: Log clearing detected by SIEM"
                ;;
        esac
    fi
    
    # Additional evasion
    echo
    if gum confirm "Implement anti-forensics?"; then
        gum format -- "### Anti-Forensics Techniques"
        gum spin --title "Clearing artifact traces..." -- sleep 2
        track_mitre "Defense Evasion" "T1070 - Indicator Removal"
        gum style --foreground 46 "✅ Prefetch files cleaned"
        gum style --foreground 46 "✅ USN journal entries sanitized"
        gum style --foreground 46 "✅ Memory artifacts wiped"
    fi
    
    echo
    gum style --foreground 11 "Current stealth score: $STEALTH_SCORE/100"
    
    gum confirm "Proceed to credential access?" || exit 0
}

# ============================================================================
# PHASE 8: CREDENTIAL ACCESS (TA0006)
# ============================================================================
phase_credential_access() {
    phase_banner 8 "CREDENTIAL ACCESS (TA0006)"
    
    gum format -- "## Credential Harvesting Operations"
    
    # Mimikatz
    gum format -- "### Method 1: LSASS Memory Dump"
    if gum confirm "Dump LSASS process memory?"; then
        track_mitre "Credential Access" "T1003.001 - LSASS Memory"
        
        DUMP_METHOD=$(gum choose \
            "Mimikatz (sekurlsa::logonpasswords)" \
            "ProcDump + Mimikatz offline" \
            "Comsvcs.dll (rundll32)")
        
        gum spin --title "Executing $DUMP_METHOD..." -- sleep 3
        
        # Generate fake credentials
        DOMAIN="$(echo $TARGET_ORG | cut -d' ' -f1 | tr '[:upper:]' '[:lower:]')"
        CRED1="$DOMAIN\\administrator:P@ssw0rd123!"
        CRED2="$DOMAIN\\svc_backup:Backup2024!!"
        CRED3="$DOMAIN\\$TARGET_INDIVIDUAL:Summer2024"
        
        HARVESTED_CREDS+=("$CRED1" "$CRED2" "$CRED3")
        
        gum style --foreground 46 "✅ Credentials extracted:"
        echo "  - $CRED1"
        echo "  - $CRED2"
        echo "  - $CRED3"
        
        log_action "CREDENTIAL ACCESS: 3 credentials harvested"
    fi
    
    # Kerberoasting
    echo
    gum format -- "### Method 2: Kerberoasting"
    if gum confirm "Perform Kerberoasting attack?"; then
        track_mitre "Credential Access" "T1558.003 - Kerberoasting"
        gum spin --title "Get-DomainSPNTicket -SPN..." -- sleep 3
        
        SERVICE_ACCOUNTS=$((3 + RANDOM % 8))
        gum style --foreground 46 "✅ Service tickets extracted: $SERVICE_ACCOUNTS"
        gum spin --title "Offline cracking with hashcat..." -- sleep 4
        
        CRACKED=$((SERVICE_ACCOUNTS / 2))
        for i in $(seq 1 $CRACKED); do
            CRED="$DOMAIN\\svc_sql$i:ServicePass$i"
            HARVESTED_CREDS+=("$CRED")
            gum style --foreground 46 "  ✅ Cracked: $CRED"
        done
    fi
    
    # Keylogging
    echo
    gum format -- "### Method 3: Keylogging"
    if gum confirm "Deploy keylogger?"; then
        track_mitre "Credential Access" "T1056.001 - Keylogging"
        gum spin --title "Installing keylogger module..." -- sleep 2
        gum style --foreground 46 "✅ Keylogger active - monitoring for 72 hours"
    fi
    
    # Credential dumping from browsers
    echo
    gum format -- "### Method 4: Browser Credential Theft"
    if gum confirm "Extract browser saved passwords?"; then
        track_mitre "Credential Access" "T1555.003 - Credentials from Web Browsers"
        gum spin --title "Parsing Chrome Login Data..." -- sleep 2
        
        BROWSER_CREDS=$((10 + RANDOM % 40))
        gum style --foreground 46 "✅ Browser credentials: $BROWSER_CREDS accounts"
        
        for i in $(seq 1 3); do
            SITE="https://webmail-$(cat /dev/urandom | tr -dc 'a-z' | fold -w 8 | head -n 1).com"
            CRED="$SITE:user$i@example.com:BrowserPass$i"
            HARVESTED_CREDS+=("$CRED")
        done
    fi
    
    echo
    gum style --foreground 46 --bold "🔑 Total credentials harvested: ${#HARVESTED_CREDS[@]}"
    log_action "TOTAL CREDENTIALS: ${#HARVESTED_CREDS[@]}"
    
    gum confirm "Continue to discovery?" || exit 0
}

# ============================================================================
# PHASE 9: DISCOVERY (TA0007)
# ============================================================================
phase_discovery() {
    phase_banner 9 "DISCOVERY (TA0007)"
    
    gum format -- "## Network & System Discovery"
    
    # Domain enumeration
    gum format -- "### Active Directory Enumeration"
    track_mitre "Discovery" "T1087.002 - Domain Account"
    
    gum spin --title "net user /domain..." -- sleep 2
    gum spin --title "Get-ADUser -Filter..." -- sleep 2
    
    DOMAIN_USERS=$((200 + RANDOM % 1000))
    ADMIN_USERS=$((5 + RANDOM % 15))
    
    gum style --foreground 46 "✅ Domain users enumerated: $DOMAIN_USERS"
    gum style --foreground 46 "✅ Domain admins identified: $ADMIN_USERS"
    
    # Network scanning
    echo
    gum format -- "### Network Reconnaissance"
    track_mitre "Discovery" "T1018 - Remote System Discovery"
    
    SCAN_METHOD=$(gum choose \
        "Built-in Windows tools (net view, ping)" \
        "PowerShell port scanner" \
        "Deploy lightweight nmap binary")
    
    gum spin --title "$SCAN_METHOD scanning subnet..." -- sleep 3
    
    DISCOVERED_HOSTS=$((30 + RANDOM % 100))
    gum style --foreground 46 "✅ Active hosts discovered: $DISCOVERED_HOSTS"
    
    # Identify high-value targets
    echo
    gum format -- "### High-Value Asset Identification"
    
    gum spin --title "Identifying critical systems..." -- sleep 2
    
    HVT_DC=$(gum input --placeholder "Domain Controller hostname (e.g., DC01)" --value "DC01")
    HVT_EXCHANGE=$(gum input --placeholder "Exchange Server hostname (e.g., EXCH01)" --value "EXCH01")
    HVT_FILESERVER=$(gum input --placeholder "File Server hostname (e.g., FS01)" --value "FS01")
    
    COMPROMISED_HOSTS+=("$HVT_DC|10.0.1.10|Windows Server 2019")
    COMPROMISED_HOSTS+=("$HVT_EXCHANGE|10.0.1.20|Windows Server 2016")
    COMPROMISED_HOSTS+=("$HVT_FILESERVER|10.0.1.30|Windows Server 2022")
    
    gum style --foreground 46 "✅ Critical systems mapped:"
    echo "  - Domain Controller: $HVT_DC"
    echo "  - Exchange Server: $HVT_EXCHANGE"
    echo "  - File Server: $HVT_FILESERVER"
    
    # Service discovery
    echo
    gum format -- "### Service Enumeration"
    track_mitre "Discovery" "T1046 - Network Service Discovery"
    
    if gum confirm "Enumerate running services?"; then
        gum spin --title "sc query type=service state=all..." -- sleep 2
        gum style --foreground 46 "✅ Services catalogued"
        gum style --foreground 46 "✅ Identified vulnerable service: Print Spooler"
    fi
    
    log_action "DISCOVERY: $DISCOVERED_HOSTS hosts, ${#COMPROMISED_HOSTS[@]} HVTs"
    
    gum confirm "Proceed to lateral movement?" || exit 0
}

# ============================================================================
# PHASE 10: LATERAL MOVEMENT (TA0008)
# ============================================================================
phase_lateral_movement() {
    phase_banner 10 "LATERAL MOVEMENT (TA0008)"
    
    gum format -- "## Spreading Across Network"
    
    if [ ${#HARVESTED_CREDS[@]} -eq 0 ]; then
        gum style --foreground 196 "❌ No credentials available for lateral movement"
        gum confirm "Return to credential access phase?" && phase_credential_access
        return
    fi
    
    # Target selection
    TARGET_HOST=$(gum choose --header "Select lateral movement target:" \
        "$HVT_DC (Domain Controller)" \
        "$HVT_EXCHANGE (Exchange Server)" \
        "$HVT_FILESERVER (File Server)" \
        "Random workstation")
    
    # Credential selection
    echo
    gum format -- "### Credential Selection"
    SELECTED_CRED=$(printf '%s\n' "${HARVESTED_CREDS[@]}" | gum filter --placeholder "Choose credential to use...")
    
    echo
    gum format -- "### Lateral Movement Technique"
    
    LATERAL_METHOD=$(gum choose \
        "PsExec (Service creation)" \
        "WMI (Remote command execution)" \
        "PowerShell Remoting (WinRM)" \
        "RDP (Remote Desktop)" \
        "SMB + scheduled task" \
        "Pass-the-Hash attack")
    
    case $LATERAL_METHOD in
        *"PsExec"*)
            track_mitre "Lateral Movement" "T1021.002 - SMB/Windows Admin Shares"
            gum spin --title "psexec.exe \\\\$(echo $TARGET_HOST | cut -d' ' -f1) -u $SELECTED_CRED..." -- sleep 3
            ;;
        *"WMI"*)
            track_mitre "Lateral Movement" "T1047 - Windows Management Instrumentation"
            gum spin --title "Invoke-WmiMethod -ComputerName $(echo $TARGET_HOST | cut -d' ' -f1)..." -- sleep 3
            ;;
        *"PowerShell"*)
            track_mitre "Lateral Movement" "T1021.006 - Windows Remote Management"
            gum spin --title "Enter-PSSession -ComputerName $(echo $TARGET_HOST | cut -d' ' -f1)..." -- sleep 3
            ;;
        *"RDP"*)
            track_mitre "Lateral Movement" "T1021.001 - Remote Desktop Protocol"
            gum spin --title "mstsc /v:$(echo $TARGET_HOST | cut -d' ' -f1)..." -- sleep 3
            ;;
        *"SMB"*)
            track_mitre "Lateral Movement" "T1053.005 - Scheduled Task"
            gum spin --title "schtasks /create /s $(echo $TARGET_HOST | cut -d' ' -f1)..." -- sleep 3
            ;;
        *"Pass-the-Hash"*)
            track_mitre "Lateral Movement" "T1550.002 - Pass the Hash"
            gum spin --title "Invoke-Mimikatz -Command 'sekurlsa::pth'..." -- sleep 3
            ;;
    esac
    
    # Success/failure
    if (( RANDOM % 100 < 80 )); then
        gum style --foreground 46 --bold "✅ LATERAL MOVEMENT SUCCESSFUL"
        gum style --foreground 46 "✅ Access gained to: $TARGET_HOST"
        log_action "LATERAL MOVEMENT: Success to $(echo $TARGET_HOST | cut -d' ' -f1)"
        
        # Deploy implant
        if gum confirm "Deploy implant on $TARGET_HOST?"; then
            gum spin --title "Deploying X-Agent on $(echo $TARGET_HOST | cut -d' ' -f1)..." -- sleep 2
            gum style --foreground 46 "✅ Implant deployed and reporting to C2"
        fi
    else
        gum style --foreground 196 "❌ Lateral movement failed - Access denied"
        update_stealth 15
    fi
    
    echo
    if gum confirm "Continue lateral movement to additional hosts?"; then
        phase_lateral_movement
    else
        gum confirm "Proceed to collection?" || exit 0
    fi
}

# ============================================================================
# PHASE 11: COLLECTION (TA0009)
# ============================================================================
phase_collection() {
    phase_banner 11 "COLLECTION (TA0009)"
    
    gum format -- "## Data Collection Operations"
    
    # Email collection
    gum format -- "### Email Harvesting"
    if gum confirm "Collect emails from Exchange Server?"; then
        track_mitre "Collection" "T1114.002 - Remote Email Collection"
        
        MAILBOX=$(gum input --placeholder "Target mailbox (e.g., podesta@dnc.org)" --value "$TARGET_INDIVIDUAL")
        gum spin --title "Accessing Exchange Web Services API..." -- sleep 3
        
        EMAIL_COUNT=$((500 + RANDOM % 5000))
        EMAIL_SIZE=$((EMAIL_COUNT * 50))
        EXFIL_SIZE=$((EXFIL_SIZE + EMAIL_SIZE))
        
        STOLEN_DATA+=("Emails:$EMAIL_COUNT:${EMAIL_SIZE}KB")
        gum style --foreground 46 "✅ Emails collected: $EMAIL_COUNT ($EMAIL_SIZE KB)"
        
        if gum confirm "Search for keywords (classified, confidential, etc.)?"; then
            gum spin --title "Searching email content..." -- sleep 2
            SENSITIVE_EMAILS=$((EMAIL_COUNT / 10))
            gum style --foreground 46 "✅ Sensitive emails identified: $SENSITIVE_EMAILS"
        fi
    fi
    
    # File collection
    echo
    gum format -- "### File Exfiltration"
    if gum confirm "Collect files from file servers?"; then
        track_mitre "Collection" "T1005 - Data from Local System"
        
        FILE_TYPES=$(gum choose --no-limit --header "Select file types to collect:" \
            "*.docx (Word documents)" \
            "*.xlsx (Excel spreadsheets)" \
            "*.pdf (PDF documents)" \
            "*.pptx (PowerPoint)" \
            "*.msg (Outlook emails)" \
            "*.zip (Archives)")
        
        gum spin --title "Robocopy file collection..." -- sleep 4
        
        FILE_COUNT=$((100 + RANDOM % 500))
        FILE_SIZE=$((FILE_COUNT * 200))
        EXFIL_SIZE=$((EXFIL_SIZE + FILE_SIZE))
        
        STOLEN_DATA+=("Documents:$FILE_COUNT:${FILE_SIZE}KB")
        gum style --foreground 46 "✅ Files collected: $FILE_COUNT ($FILE_SIZE KB)"
    fi
    
    # Database access
    echo
    gum format -- "### Database Extraction"
    if gum confirm "Access SQL databases?"; then
        track_mitre "Collection" "T1213.002 - Sharepoint"
        
        gum spin --title "Connecting to SQL Server..." -- sleep 2
        
        DB_TABLES=$(gum choose --no-limit \
            "Users table" \
            "Employee records" \
            "Financial data" \
            "Customer PII")
        
        gum spin --title "SELECT * FROM ..." -- sleep 3
        
        DB_ROWS=$((10000 + RANDOM % 100000))
        DB_SIZE=$((DB_ROWS / 10))
        EXFIL_SIZE=$((EXFIL_SIZE + DB_SIZE))
        
        STOLEN_DATA+=("Database:${DB_ROWS}_rows:${DB_SIZE}KB")
        gum style --foreground 46 "✅ Database records: $DB_ROWS ($DB_SIZE KB)"
    fi
    
    # Screenshots
    echo
    gum format -- "### Screen Capture"
    if gum confirm "Capture screenshots from active sessions?"; then
        track_mitre "Collection" "T1113 - Screen Capture"
        gum spin --title "Taking screenshots..." -- sleep 2
        
        SCREENSHOT_COUNT=$((10 + RANDOM % 50))
        SCREENSHOT_SIZE=$((SCREENSHOT_COUNT * 500))
        EXFIL_SIZE=$((EXFIL_SIZE + SCREENSHOT_SIZE))
        
        STOLEN_DATA+=("Screenshots:$SCREENSHOT_COUNT:${SCREENSHOT_SIZE}KB")
        gum style --foreground 46 "✅ Screenshots captured: $SCREENSHOT_COUNT"
    fi
    
    # Clipboard data
    echo
    if gum confirm "Monitor clipboard data?"; then
        track_mitre "Collection" "T1115 - Clipboard Data"
        gum spin --title "Clipboard logging active..." -- sleep 2
        gum style --foreground 46 "✅ Clipboard monitoring enabled"
    fi
    
    echo
    gum style --foreground 46 --bold "📦 Total data collected: ${EXFIL_SIZE} KB"
    gum style --foreground 46 "📊 Collection items: ${#STOLEN_DATA[@]}"
    
    log_action "COLLECTION: ${EXFIL_SIZE}KB total, ${#STOLEN_DATA[@]} categories"
    
    gum confirm "Proceed to exfiltration?" || exit 0
}

# ============================================================================
# PHASE 12: COMMAND & CONTROL (TA0011)
# ============================================================================
phase_command_control() {
    phase_banner 12 "COMMAND & CONTROL (TA0011)"
    
    gum format -- "## C2 Channel Management"
    
    # C2 protocol
    C2_PROTOCOL=$(gum choose --header "Primary C2 protocol:" \
        "HTTPS (TLS encrypted)" \
        "DNS tunneling" \
        "Email-based C2 (Gmail, Outlook)" \
        "Custom protocol over port 443" \
        "Tor hidden service")
    
    track_mitre "Command and Control" "T1071.001 - Web Protocols"
    
    gum style --foreground 46 "✅ C2 Protocol: $C2_PROTOCOL"
    gum style --foreground 46 "✅ C2 Server: $C2_IP"
    gum style --foreground 46 "✅ Beacon interval: 300 seconds"
    
    echo
    gum format -- "### Encrypted Communications"
    track_mitre "Command and Control" "T1573.002 - Asymmetric Cryptography"
    
    gum spin --title "Establishing encrypted channel with RSA-2048..." -- sleep 2
    gum style --foreground 46 "✅ End-to-end encryption active"
    
    # Fallback C2
    echo
    if gum confirm "Configure fallback C2 domains?"; then
        track_mitre "Command and Control" "T1008 - Fallback Channels"
        
        FALLBACK_COUNT=$(gum input --placeholder "Number of fallback domains (1-5)" --value "3")
        gum spin --title "Registering $FALLBACK_COUNT fallback domains..." -- sleep 2
        
        for i in $(seq 1 $FALLBACK_COUNT); do
            FALLBACK="backup-c2-$i-$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1).net"
            gum style --foreground 46 "  ✅ Fallback $i: $FALLBACK"
        done
    fi
    
    # Dead drop resolver
    echo
    if gum confirm "Implement dead drop resolver?"; then
        track_mitre "Command and Control" "T1102 - Web Service"
        
        DEAD_DROP=$(gum choose "Twitter" "Pastebin" "GitHub Gist" "Reddit")
        gum spin --title "Configuring $DEAD_DROP as dead drop..." -- sleep 2
        gum style --foreground 46 "✅ Dead drop resolver: $DEAD_DROP"
    fi
    
    log_action "C2: $C2_PROTOCOL via $C2_IP"
    
    gum confirm "Continue to exfiltration?" || exit 0
}

# ============================================================================
# PHASE 13: EXFILTRATION (TA0010)
# ============================================================================
phase_exfiltration() {
    phase_banner 13 "EXFILTRATION (TA0010)"
    
    gum format -- "## Data Exfiltration Operations"
    
    if [ ${#STOLEN_DATA[@]} -eq 0 ]; then
        gum style --foreground 196 "⚠️  No data collected for exfiltration"
        if gum confirm "Return to collection phase?"; then
            phase_collection
            return
        fi
    fi
    
    # Display collected data
    gum format -- "### Staged Data"
    for item in "${STOLEN_DATA[@]}"; do
        IFS=':' read -r type count size <<< "$item"
        echo "  - $type: $count items ($size)"
    done
    
    echo
    gum format -- "### Exfiltration Method"
    
    EXFIL_METHOD=$(gum choose \
        "C2 channel (HTTPS)" \
        "DNS tunneling" \
        "Cloud storage (Dropbox, OneDrive)" \
        "Email attachments" \
        "FTP to external server" \
        "Steganography in images")
    
    case $EXFIL_METHOD in
        *"C2 channel"*)
            track_mitre "Exfiltration" "T1041 - Exfiltration Over C2 Channel"
            ;;
        *"DNS"*)
            track_mitre "Exfiltration" "T1048.003 - Exfiltration Over Alternative Protocol"
            ;;
        *"Cloud"*)
            track_mitre "Exfiltration" "T1567.002 - Exfiltration to Cloud Storage"
            ;;
        *"Email"*)
            track_mitre "Exfiltration" "T1048.003 - Exfiltration Over Alternative Protocol"
            ;;
        *"Steganography"*)
            track_mitre "Exfiltration" "T1027.003 - Steganography"
            update_stealth -5  # Stealth bonus
            ;;
    esac
    
    # Compression
    echo
    if gum confirm "Compress data before exfiltration?"; then
        track_mitre "Exfiltration" "T1560.001 - Archive via Utility"
        gum spin --title "7z a -p$(openssl rand -hex 8) exfil.7z ..." -- sleep 2
        COMPRESSED_SIZE=$((EXFIL_SIZE / 3))
        gum style --foreground 46 "✅ Compressed: ${EXFIL_SIZE}KB → ${COMPRESSED_SIZE}KB"
        EXFIL_SIZE=$COMPRESSED_SIZE
    fi
    
    # Encryption
    if gum confirm "Encrypt exfiltration data?"; then
        track_mitre "Exfiltration" "T1560.001 - Archive Collected Data"
        gum spin --title "AES-256 encryption..." -- sleep 2
        gum style --foreground 46 "✅ Data encrypted with AES-256"
    fi
    
    # Throttling
    echo
    gum format -- "### Exfiltration Rate Limiting"
    
    THROTTLE=$(gum choose \
        "Full speed (risky)" \
        "Moderate (100KB/s)" \
        "Slow (10KB/s - stealth)")
    
    case $THROTTLE in
        *"Full"*)
            EXFIL_TIME=$((EXFIL_SIZE / 1000))
            update_stealth 30
            ;;
        *"Moderate"*)
            EXFIL_TIME=$((EXFIL_SIZE / 100))
            update_stealth 10
            ;;
        *"Slow"*)
            EXFIL_TIME=$((EXFIL_SIZE / 10))
            ;;
    esac
    
    # Execute exfiltration
    echo
    gum spin --title "Exfiltrating ${EXFIL_SIZE}KB via $EXFIL_METHOD..." --spinner meter -- sleep $((EXFIL_TIME < 10 ? EXFIL_TIME : 10))
    
    if (( RANDOM % 100 < (STEALTH_SCORE - 20) )); then
        gum style --foreground 46 --bold "✅ EXFILTRATION COMPLETE"
        gum style --foreground 46 "✅ Data transferred: ${EXFIL_SIZE} KB"
        gum style --foreground 46 "✅ Transfer time: ${EXFIL_TIME} seconds"
        gum style --foreground 46 "✅ Destination: Moscow relay station"
        
        log_action "EXFILTRATION: Success - ${EXFIL_SIZE}KB via $EXFIL_METHOD"
    else
        gum style --foreground 196 "❌ EXFILTRATION DETECTED - DLP Alert"
        gum style --foreground 196 "⚠️  Partial data loss"
        update_stealth 50
        
        log_action "EXFILTRATION: Detected - Mission compromised"
        
        if ! gum confirm "Attempt alternative exfil method?"; then
            generate_report
            exit 1
        fi
    fi
    
    gum confirm "Proceed to impact/cleanup?" || exit 0
}

# ============================================================================
# PHASE 14: IMPACT & CLEANUP (TA0040)
# ============================================================================
phase_impact() {
    phase_banner 14 "IMPACT & CLEANUP (TA0040)"
    
    gum format -- "## Post-Exploitation Actions"
    
    # Optional destructive actions
    gum format -- "### Impact Operations (Optional)"
    
    if gum confirm "Execute impact/destructive actions?"; then
        IMPACT_TYPE=$(gum choose \
            "None - Pure espionage" \
            "Deploy wiper malware" \
            "Ransomware deployment" \
            "Data destruction" \
            "Defacement")
        
        case $IMPACT_TYPE in
            *"wiper"*)
                track_mitre "Impact" "T1485 - Data Destruction"
                gum spin --title "Deploying NotPetya wiper..." -- sleep 3
                gum style --foreground 196 "⚠️  Wiper deployed - High attribution risk"
                ;;
            *"Ransomware"*)
                track_mitre "Impact" "T1486 - Data Encrypted for Impact"
                gum spin --title "Encrypting files..." -- sleep 3
                gum style --foreground 196 "⚠️  Ransomware active"
                ;;
            *"destruction"*)
                track_mitre "Impact" "T1485 - Data Destruction"
                gum spin --title "Wiping evidence..." -- sleep 2
                ;;
        esac
    fi
    
    # Cleanup
    echo
    gum format -- "### Operational Cleanup"
    
    if gum confirm "Perform cleanup operations?"; then
        CLEANUP_LEVEL=$(gum choose \
            "Minimal - Leave backdoors" \
            "Moderate - Remove obvious traces" \
            "Complete - Full sanitization")
        
        case $CLEANUP_LEVEL in
            *"Minimal"*)
                gum spin --title "Clearing immediate traces..." -- sleep 2
                gum style --foreground 11 "✅ Minimal cleanup - Backdoors remain"
                ;;
            *"Moderate"*)
                track_mitre "Defense Evasion" "T1070 - Indicator Removal"
                gum spin --title "Removing logs and artifacts..." -- sleep 3
                gum style --foreground 46 "✅ Major artifacts removed"
                ;;
            *"Complete"*)
                track_mitre "Defense Evasion" "T1070 - Indicator Removal"
                gum spin --title "Full sanitization in progress..." -- sleep 5
                gum style --foreground 46 "✅ Complete cleanup - All traces removed"
                update_stealth -20  # Cleanup reduces detection
                ;;
        esac
    fi
    
    # Final backdoor
    echo
    if gum confirm "Install long-term strategic backdoor?"; then
        BACKDOOR_TYPE=$(gum choose \
            "Firmware implant" \
            "Supply chain compromise" \
            "VPN backdoor" \
            "Certificate-based access")
        
        gum spin --title "Installing $BACKDOOR_TYPE..." -- sleep 3
        gum style --foreground 46 "✅ Strategic access maintained"
        log_action "BACKDOOR: $BACKDOOR_TYPE installed for future operations"
    fi
    
    log_action "CLEANUP: Mission complete"
}

# ============================================================================
# MISSION REPORT GENERATION
# ============================================================================
generate_report() {
    local mission_end=$(date +%s)
    local duration=$((mission_end - MISSION_START))
    local duration_min=$((duration / 60))
    
    clear
    gum style \
        --foreground 46 --border-foreground 46 --border double \
        --width 90 --align center --padding "2 4" --bold \
        "🎖️  MISSION COMPLETE" \
        "APT28 Operation - After Action Report"
    
    echo
    gum format -- "## Mission Statistics"
    
    # Create statistics table
    gum table --border rounded --width 90 <<EOF
Metric,Value
Mission Duration,${duration_min} minutes
Compromised Hosts,${#COMPROMISED_HOSTS[@]}
Credentials Harvested,${#HARVESTED_CREDS[@]}
Data Exfiltrated,${EXFIL_SIZE} KB
Detection Events,$DETECTION_EVENTS
Final Stealth Score,$STEALTH_SCORE/100
MITRE Techniques Used,${#MITRE_TECHNIQUES[@]}
EOF
    
    echo
    gum format -- "## MITRE ATT&CK Coverage"
    
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
    gum format -- "## Exfiltrated Data"
    
    if [ ${#STOLEN_DATA[@]} -gt 0 ]; then
        for item in "${STOLEN_DATA[@]}"; do
            IFS=':' read -r type count size <<< "$item"
            echo "  📦 $type: $count items ($size)"
        done
    else
        echo "  No data exfiltrated"
    fi
    
    echo
    gum format -- "## Mission Assessment"
    
    if [ $STEALTH_SCORE -gt 70 ]; then
        gum style --foreground 46 "🏆 EXCELLENT: Low detection probability - Mission success"
    elif [ $STEALTH_SCORE -gt 40 ]; then
        gum style --foreground 11 "⚠️  MODERATE: Some detection risk - Acceptable"
    else
        gum style --foreground 196 "❌ HIGH RISK: Likely detected - Attribution probable"
    fi
    
    echo
    gum style --foreground 240 "Detailed log saved to: $LOG_FILE"
    
    echo
    if gum confirm "Save mission report to file?"; then
        REPORT_FILE="/tmp/apt28-report-$(date +%Y%m%d-%H%M%S).txt"
        {
            echo "============================================"
            echo "APT28 FANCY BEAR MISSION REPORT"
            echo "Generated: $(date)"
            echo "============================================"
            echo
            echo "MISSION STATISTICS:"
            echo "  Duration: ${duration_min} minutes"
            echo "  Compromised Hosts: ${#COMPROMISED_HOSTS[@]}"
            echo "  Credentials: ${#HARVESTED_CREDS[@]}"
            echo "  Data Exfiltrated: ${EXFIL_SIZE} KB"
            echo "  Stealth Score: $STEALTH_SCORE/100"
            echo
            echo "MITRE ATT&CK TECHNIQUES:"
            for tactic in "${!MITRE_TECHNIQUES[@]}"; do
                echo "  - $tactic: ${MITRE_TECHNIQUES[$tactic]}"
            done
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
        } > "$REPORT_FILE"
        
        gum style --foreground 46 "✅ Report saved: $REPORT_FILE"
    fi
    
    echo
    gum style \
        --foreground 196 --border normal \
        --align center --padding "1 2" \
        "Mission log: $LOG_FILE"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    check_dependencies
    
    mission_briefing
    phase_reconnaissance
    phase_weaponization
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
    gum style --foreground 46 --bold "🎯 Mission complete. До свидания, товарищ."
}

# Run main
main
