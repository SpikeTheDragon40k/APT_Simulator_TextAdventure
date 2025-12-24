#!/bin/bash
# ============================================================================
# BLUE TEAM: APT28 Defense & Threat Hunting Simulator
# ============================================================================
# Comprehensive defensive operations against APT28 (Fancy Bear) TTPs
# Based on MITRE ATT&CK defensive countermeasures and detection engineering
# Make executable: chmod +x blueteam-apt28-defense.sh
# ============================================================================

set -euo pipefail
trap cleanup INT TERM

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
VERSION="1.0"
LOG_FILE="/tmp/blueteam-defense-$(date +%Y%m%d-%H%M%S).log"
INCIDENT_FILE="/tmp/incident-response-$(date +%Y%m%d-%H%M%S).json"
MISSION_START=$(date +%s)

# Defense state tracking
declare -a DEPLOYED_CONTROLS=()
declare -a DETECTED_THREATS=()
declare -a BLOCKED_ATTACKS=()
declare -a INCIDENT_TIMELINE=()
declare -A DETECTION_RULES=()
declare -A MITIGATIONS=()

SECURITY_SCORE=50
THREAT_LEVEL="ELEVATED"
INCIDENTS_DETECTED=0
INCIDENTS_CONTAINED=0
FALSE_POSITIVES=0

# APT28 IoCs
declare -A APT28_IOCS=(
    ["IP"]="185.220.101.0/24 23.95.43.0/24"
    ["Domain"]="security-update-*.com vpn-service-*.net"
    ["Hash_XAgent"]="4a235f0b8634b7d3c93c231c9a6b58c4"
    ["Hash_Zebrocy"]="d55f983c994caa160ec63a59f6b4250f"
    ["Mutex"]="RPCMutex"
)

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
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_FILE"
    INCIDENT_TIMELINE+=("$timestamp|$1")
}

cleanup() {
    echo
    gum style --foreground 11 "🚨 Defense operations interrupted"
    generate_report
    exit 130
}

update_security_score() {
    local change=$1
    ((SECURITY_SCORE += change)) || true
    if [ $SECURITY_SCORE -gt 100 ]; then
        SECURITY_SCORE=100
    elif [ $SECURITY_SCORE -lt 0 ]; then
        SECURITY_SCORE=0
    fi
    
    # Update threat level
    if [ $SECURITY_SCORE -ge 80 ]; then
        THREAT_LEVEL="LOW"
    elif [ $SECURITY_SCORE -ge 60 ]; then
        THREAT_LEVEL="GUARDED"
    elif [ $SECURITY_SCORE -ge 40 ]; then
        THREAT_LEVEL="ELEVATED"
    elif [ $SECURITY_SCORE -ge 20 ]; then
        THREAT_LEVEL="HIGH"
    else
        THREAT_LEVEL="SEVERE"
    fi
}

track_detection() {
    local technique=$1
    local rule=$2
    DETECTION_RULES["$technique"]="$rule"
    log_action "DETECTION: [$technique] $rule"
}

track_mitigation() {
    local attack=$1
    local control=$2
    MITIGATIONS["$attack"]="$control"
    log_action "MITIGATION: [$attack] $control"
}

show_threat_level() {
    local color
    case $THREAT_LEVEL in
        "LOW") color=46 ;;
        "GUARDED") color=10 ;;
        "ELEVATED") color=11 ;;
        "HIGH") color=208 ;;
        "SEVERE") color=196 ;;
    esac
    
    gum style --foreground $color "🛡️  Threat Level: $THREAT_LEVEL | Security Score: $SECURITY_SCORE/100"
}

# ============================================================================
# MISSION PHASES
# ============================================================================

phase_banner() {
    local phase_num=$1
    local phase_name=$2
    clear
    gum style \
        --foreground 27 --border-foreground 27 --border double \
        --width 90 --align center --padding "1 2" \
        "PHASE $phase_num: $phase_name"
    echo
    show_threat_level
    echo
}

# ============================================================================
# PHASE 0: MISSION BRIEFING
# ============================================================================
mission_briefing() {
    clear
    gum style \
        --foreground 27 --background 0 --border-foreground 27 --border double \
        --width 90 --align center --padding "3 4" --bold \
        "🛡️  BLUE TEAM OPERATIONS" \
        "Defending Against APT28 (Fancy Bear)" \
        "" \
        "Threat Hunt & Incident Response v${VERSION}"
    
    echo
    
    gum format -- "# Mission Parameters"
    gum format -- "**Adversary**: APT28 (Fancy Bear, Sofacy, GRU Unit 26165)"
    gum format -- "**MITRE Group**: G0007"
    gum format -- "**Threat Level**: Active campaign targeting critical infrastructure"
    gum format -- "**Your Role**: Lead Security Operations Center (SOC) Analyst"
    gum format -- "**Objective**: Detect, contain, and eradicate APT28 intrusion"
    
    echo
    
    ORGANIZATION=$(gum choose --header "Select your organization type:" \
        "Government Agency" \
        "Defense Contractor" \
        "Financial Institution" \
        "Energy Sector" \
        "Technology Company")
    
    log_action "=== BLUE TEAM DEFENSE MISSION START ==="
    log_action "Organization: $ORGANIZATION"
    
    echo
    gum format -- "## Intelligence Brief"
    gum style --foreground 11 "⚠️  THREAT ADVISORY: APT28 active campaign detected"
    gum style --foreground 11 "📊 Targeting: $ORGANIZATION sector"
    gum style --foreground 11 "🎯 Likely vectors: Spear-phishing, credential theft, lateral movement"
    
    echo
    if ! gum confirm "Begin defensive operations?"; then
        echo "Mission cancelled"
        exit 0
    fi
}

# ============================================================================
# PHASE 1: ASSET INVENTORY & BASELINE
# ============================================================================
phase_asset_inventory() {
    phase_banner 1 "ASSET INVENTORY & BASELINE"
    
    gum format -- "## Network Asset Discovery"
    
    gum spin --spinner dot --title "Scanning network infrastructure..." -- sleep 2
    
    # Asset discovery
    TOTAL_HOSTS=$((100 + RANDOM % 500))
    SERVERS=$((10 + RANDOM % 30))
    WORKSTATIONS=$((TOTAL_HOSTS - SERVERS))
    
    gum style --foreground 46 "✅ Total endpoints: $TOTAL_HOSTS"
    gum style --foreground 46 "✅ Servers: $SERVERS"
    gum style --foreground 46 "✅ Workstations: $WORKSTATIONS"
    
    echo
    gum format -- "## Critical Asset Identification"
    
    DC_NAME=$(gum input --placeholder "Domain Controller name" --value "DC01.corp.local")
    EXCHANGE_NAME=$(gum input --placeholder "Exchange Server name" --value "EXCH01.corp.local")
    FILESERVER_NAME=$(gum input --placeholder "File Server name" --value "FS01.corp.local")
    
    log_action "CRITICAL ASSETS: $DC_NAME, $EXCHANGE_NAME, $FILESERVER_NAME"
    
    echo
    gum format -- "## Baseline Security State"
    
    gum spin --spinner dot --title "Establishing security baseline..." -- sleep 2
    
    # Security tools audit
    INSTALLED_EDR=$(gum choose --header "Deployed EDR/XDR platform:" \
        "CrowdStrike Falcon" \
        "Microsoft Defender for Endpoint" \
        "SentinelOne" \
        "Carbon Black" \
        "Trend Micro Apex One" \
        "None (⚠️  Critical gap)")
    
    if [ "$INSTALLED_EDR" = "None (⚠️  Critical gap)" ]; then
        gum style --foreground 196 "❌ CRITICAL: No EDR deployed - High risk!"
        update_security_score -20
    else
        gum style --foreground 46 "✅ EDR Platform: $INSTALLED_EDR"
        DEPLOYED_CONTROLS+=("EDR:$INSTALLED_EDR")
        update_security_score 10
    fi
    
    echo
    SIEM_PLATFORM=$(gum choose --header "SIEM/Log Management:" \
        "Splunk Enterprise" \
        "Microsoft Sentinel" \
        "Elastic Security" \
        "IBM QRadar" \
        "Chronicle Security" \
        "None (⚠️  Limited visibility)")
    
    if [[ "$SIEM_PLATFORM" != *"None"* ]]; then
        gum style --foreground 46 "✅ SIEM: $SIEM_PLATFORM"
        DEPLOYED_CONTROLS+=("SIEM:$SIEM_PLATFORM")
        update_security_score 10
    else
        update_security_score -15
    fi
    
    log_action "BASELINE: $INSTALLED_EDR + $SIEM_PLATFORM deployed"
    
    gum confirm "Proceed to threat intelligence?" || exit 0
}

# ============================================================================
# PHASE 2: THREAT INTELLIGENCE & IOC DEPLOYMENT
# ============================================================================
phase_threat_intelligence() {
    phase_banner 2 "THREAT INTELLIGENCE & IOC DEPLOYMENT"
    
    gum format -- "## APT28 Threat Intelligence"
    
    gum format -- "### Known APT28 Indicators of Compromise"
    echo
    echo "📌 Malicious IP Ranges:"
    echo "   ${APT28_IOCS[IP]}"
    echo "📌 C2 Domain Patterns:"
    echo "   ${APT28_IOCS[Domain]}"
    echo "📌 Known Malware Hashes:"
    echo "   X-Agent: ${APT28_IOCS[Hash_XAgent]}"
    echo "   Zebrocy: ${APT28_IOCS[Hash_Zebrocy]}"
    
    echo
    if gum confirm "Import APT28 IoCs into security stack?"; then
        
        gum format -- "### IoC Deployment"
        
        # Firewall rules
        if gum confirm "Block known APT28 IPs at perimeter firewall?"; then
            gum spin --spinner pulse --title "Deploying firewall deny rules..." -- sleep 2
            track_mitigation "C2 Communication" "Perimeter firewall blocking"
            gum style --foreground 46 "✅ Blocked IP ranges: ${APT28_IOCS[IP]}"
            DEPLOYED_CONTROLS+=("Firewall:APT28_IPs")
            update_security_score 5
        fi
        
        # DNS filtering
        if gum confirm "Deploy DNS sinkhole for APT28 C2 domains?"; then
            gum spin --spinner pulse --title "Configuring DNS filtering..." -- sleep 2
            track_mitigation "C2 Domain Resolution" "DNS sinkhole"
            gum style --foreground 46 "✅ DNS filtering active for C2 patterns"
            DEPLOYED_CONTROLS+=("DNS:Sinkhole")
            update_security_score 5
        fi
        
        # EDR IoC import
        if [[ "$INSTALLED_EDR" != *"None"* ]]; then
            if gum confirm "Import IoCs into $INSTALLED_EDR?"; then
                gum spin --spinner pulse --title "Importing IoCs to EDR platform..." -- sleep 3
                track_mitigation "Malware Execution" "EDR hash blocking"
                gum style --foreground 46 "✅ EDR IoC watchlist updated"
                gum style --foreground 46 "   - ${APT28_IOCS[Hash_XAgent]}"
                gum style --foreground 46 "   - ${APT28_IOCS[Hash_Zebrocy]}"
                update_security_score 10
            fi
        fi
        
        # YARA rules
        if gum confirm "Deploy YARA rules for APT28 malware families?"; then
            gum spin --spinner pulse --title "Compiling YARA signatures..." -- sleep 2
            track_detection "Malware Detection" "YARA:APT28_XAgent"
            gum style --foreground 46 "✅ YARA rules deployed:"
            gum style --foreground 46 "   - APT28_XAgent.yar"
            gum style --foreground 46 "   - APT28_Zebrocy.yar"
            gum style --foreground 46 "   - APT28_Komplex.yar"
            DEPLOYED_CONTROLS+=("YARA:APT28_Rules")
            update_security_score 8
        fi
    fi
    
    echo
    gum format -- "## Threat Intelligence Feeds"
    
    if gum confirm "Subscribe to threat intel feeds?"; then
        FEED_SOURCES=$(gum choose --no-limit --header "Select threat intel sources:" \
            "US-CERT Alerts" \
            "MISP (Malware Information Sharing Platform)" \
            "AlienVault OTX" \
            "ThreatConnect" \
            "CISA Known Exploited Vulnerabilities")
        
        gum spin --spinner pulse --title "Configuring threat intel ingestion..." -- sleep 2
        gum style --foreground 46 "✅ Threat intel feeds configured"
        update_security_score 5
    fi
    
    log_action "IoC DEPLOYMENT: ${#DEPLOYED_CONTROLS[@]} controls active"
    
    gum confirm "Proceed to email security hardening?" || exit 0
}

# ============================================================================
# PHASE 3: EMAIL SECURITY & ANTI-PHISHING
# ============================================================================
phase_email_security() {
    phase_banner 3 "EMAIL SECURITY & ANTI-PHISHING"
    
    gum format -- "## Email Gateway Hardening"
    gum format -- "APT28 primary vector: Spear-phishing with weaponized attachments"
    
    echo
    if gum confirm "Deploy advanced email filtering?"; then
        
        # SPF/DKIM/DMARC
        gum format -- "### Email Authentication"
        if gum confirm "Enforce SPF/DKIM/DMARC policies?"; then
            gum spin --spinner pulse --title "Configuring email authentication..." -- sleep 2
            track_mitigation "Phishing" "SPF/DKIM/DMARC enforcement"
            gum style --foreground 46 "✅ SPF: -all (hard fail)"
            gum style --foreground 46 "✅ DMARC: p=reject"
            gum style --foreground 46 "✅ DKIM: Enabled"
            DEPLOYED_CONTROLS+=("Email:Authentication")
            update_security_score 8
        fi
        
        # Attachment filtering
        echo
        gum format -- "### Dangerous Attachment Blocking"
        BLOCK_EXTENSIONS=$(gum choose --no-limit --header "Block file types:" \
            ".exe, .scr, .com" \
            ".vbs, .js, .jse" \
            ".bat, .cmd, .ps1" \
            ".docm, .xlsm, .pptm (macros)" \
            ".hta (HTML Application)" \
            ".iso, .img (disk images)")
        
        gum spin --spinner pulse --title "Updating attachment filters..." -- sleep 2
        track_mitigation "Weaponized Attachments" "File type blocking"
        gum style --foreground 46 "✅ Attachment filtering deployed"
        DEPLOYED_CONTROLS+=("Email:AttachmentFilter")
        update_security_score 10
        
        # Sandboxing
        echo
        if gum confirm "Enable email attachment sandboxing?"; then
            SANDBOX_SOLUTION=$(gum choose \
                "Proofpoint TAP" \
                "Mimecast Attachment Protection" \
                "Microsoft Defender for Office 365" \
                "FireEye Email Security")
            
            gum spin --spinner pulse --title "Deploying $SANDBOX_SOLUTION..." -- sleep 3
            track_mitigation "Malicious Attachments" "Email sandboxing"
            gum style --foreground 46 "✅ Email sandbox: $SANDBOX_SOLUTION"
            DEPLOYED_CONTROLS+=("Email:Sandbox")
            update_security_score 15
        fi
        
        # URL rewriting
        echo
        if gum confirm "Deploy URL rewriting/detonation?"; then
            gum spin --spinner pulse --title "Configuring URL protection..." -- sleep 2
            track_mitigation "Phishing Links" "URL rewriting"
            gum style --foreground 46 "✅ URL rewriting enabled"
            gum style --foreground 46 "✅ Real-time link analysis active"
            DEPLOYED_CONTROLS+=("Email:URLProtection")
            update_security_score 8
        fi
    fi
    
    echo
    gum format -- "## User Awareness Training"
    
    if gum confirm "Conduct phishing simulation campaign?"; then
        gum spin --spinner pulse --title "Sending simulated phishing emails..." -- sleep 3
        
        CLICK_RATE=$((15 + RANDOM % 20))
        REPORT_RATE=$((5 + RANDOM % 15))
        
        gum style --foreground 11 "📊 Phishing simulation results:"
        gum style --foreground 11 "   Click rate: ${CLICK_RATE}%"
        gum style --foreground 46 "   Report rate: ${REPORT_RATE}%"
        
        if [ $CLICK_RATE -gt 20 ]; then
            gum style --foreground 196 "⚠️  HIGH RISK: Users need training"
            update_security_score -5
        else
            gum style --foreground 46 "✅ Acceptable user awareness level"
            update_security_score 5
        fi
        
        if gum confirm "Enroll high-risk users in mandatory training?"; then
            gum spin --spinner pulse --title "Enrolling users in security awareness..." -- sleep 2
            gum style --foreground 46 "✅ Training campaign deployed"
            update_security_score 5
        fi
    fi
    
    log_action "EMAIL SECURITY: Hardening complete"
    
    gum confirm "Proceed to endpoint protection?" || exit 0
}

# ============================================================================
# PHASE 4: ENDPOINT DETECTION & RESPONSE
# ============================================================================
phase_endpoint_protection() {
    phase_banner 4 "ENDPOINT DETECTION & RESPONSE"
    
    gum format -- "## EDR/XDR Configuration"
    
    if [[ "$INSTALLED_EDR" == *"None"* ]]; then
        gum style --foreground 196 "❌ No EDR installed - Deploy immediately!"
        
        if gum confirm "Deploy EDR solution now?"; then
            INSTALLED_EDR=$(gum choose \
                "CrowdStrike Falcon" \
                "Microsoft Defender for Endpoint" \
                "SentinelOne")
            
            gum spin --spinner pulse --title "Deploying $INSTALLED_EDR agents..." -- sleep 4
            gum style --foreground 46 "✅ EDR agents deployed to $TOTAL_HOSTS endpoints"
            DEPLOYED_CONTROLS+=("EDR:$INSTALLED_EDR")
            update_security_score 20
        fi
    fi
    
    echo
    gum format -- "## APT28-Specific Detection Rules"
    
    # Behavior-based detections
    if gum confirm "Deploy behavioral detection rules?"; then
        
        gum format -- "### Suspicious PowerShell Activity"
        if gum confirm "Detect obfuscated PowerShell (Base64, XOR)?"; then
            gum spin --spinner pulse --title "Creating PowerShell detection rule..." -- sleep 2
            track_detection "T1059.001" "Obfuscated PowerShell execution"
            gum style --foreground 46 "✅ Detection: PowerShell -EncodedCommand"
            gum style --foreground 46 "✅ Detection: Invoke-Expression with obfuscation"
            update_security_score 5
        fi
        
        echo
        gum format -- "### Credential Dumping Detection"
        if gum confirm "Monitor for LSASS access (Mimikatz)?"; then
            gum spin --spinner pulse --title "Deploying LSASS protection rules..." -- sleep 2
            track_detection "T1003.001" "LSASS memory access"
            gum style --foreground 46 "✅ Detection: LSASS dump attempts"
            gum style --foreground 46 "✅ Detection: Mimikatz patterns"
            gum style --foreground 46 "✅ Detection: ProcDump usage"
            DEPLOYED_CONTROLS+=("EDR:LSASS_Protection")
            update_security_score 10
        fi
        
        echo
        gum format -- "### Lateral Movement Detection"
        if gum confirm "Detect PsExec/WMI lateral movement?"; then
            gum spin --spinner pulse --title "Creating lateral movement rules..." -- sleep 2
            track_detection "T1021.002" "SMB lateral movement"
            gum style --foreground 46 "✅ Detection: PsExec remote service creation"
            gum style --foreground 46 "✅ Detection: WMI remote process creation"
            gum style --foreground 46 "✅ Detection: Pass-the-Hash attempts"
            update_security_score 8
        fi
        
        echo
        gum format -- "### Persistence Mechanisms"
        if gum confirm "Monitor registry run keys and scheduled tasks?"; then
            gum spin --spinner pulse --title "Deploying persistence detection..." -- sleep 2
            track_detection "T1547.001" "Registry persistence"
            track_detection "T1053.005" "Scheduled task persistence"
            gum style --foreground 46 "✅ Detection: Registry Run key modifications"
            gum style --foreground 46 "✅ Detection: Suspicious scheduled tasks"
            gum style --foreground 46 "✅ Detection: WMI event subscriptions"
            update_security_score 7
        fi
    fi
    
    echo
    gum format -- "## Endpoint Hardening"
    
    if gum confirm "Apply endpoint security baselines?"; then
        
        # Application whitelisting
        if gum confirm "Deploy application whitelisting?"; then
            gum spin --spinner pulse --title "Configuring application control..." -- sleep 2
            track_mitigation "Malware Execution" "Application whitelisting"
            gum style --foreground 46 "✅ AppLocker/WDAC policies deployed"
            DEPLOYED_CONTROLS+=("Endpoint:AppWhitelisting")
            update_security_score 12
        fi
        
        # Credential Guard
        if gum confirm "Enable Windows Credential Guard?"; then
            gum spin --spinner pulse --title "Enabling Credential Guard..." -- sleep 2
            track_mitigation "Credential Theft" "Credential Guard"
            gum style --foreground 46 "✅ Credential Guard enabled"
            DEPLOYED_CONTROLS+=("Endpoint:CredentialGuard")
            update_security_score 10
        fi
        
        # LSASS protection
        if gum confirm "Enable LSA Protection (RunAsPPL)?"; then
            gum spin --spinner pulse --title "Hardening LSASS process..." -- sleep 2
            track_mitigation "LSASS Dumping" "Protected Process Light"
            gum style --foreground 46 "✅ LSASS running as Protected Process"
            update_security_score 8
        fi
        
        # PowerShell logging
        if gum confirm "Enable PowerShell script block logging?"; then
            gum spin --spinner pulse --title "Configuring PowerShell logging..." -- sleep 2
            track_detection "T1059.001" "PowerShell script logging"
            gum style --foreground 46 "✅ Script block logging enabled"
            gum style --foreground 46 "✅ Module logging enabled"
            gum style --foreground 46 "✅ Transcription enabled"
            DEPLOYED_CONTROLS+=("Logging:PowerShell")
            update_security_score 8
        fi
    fi
    
    log_action "ENDPOINT PROTECTION: ${#DEPLOYED_CONTROLS[@]} controls deployed"
    
    gum confirm "Proceed to network monitoring?" || exit 0
}

# ============================================================================
# PHASE 5: NETWORK SECURITY MONITORING
# ============================================================================
phase_network_monitoring() {
    phase_banner 5 "NETWORK SECURITY MONITORING"
    
    gum format -- "## Network Detection & Response"
    
    # IDS/IPS
    IDS_SOLUTION=$(gum choose --header "Network intrusion detection:" \
        "Suricata with ET rules" \
        "Snort 3" \
        "Zeek (formerly Bro)" \
        "Cisco Firepower" \
        "Palo Alto Networks" \
        "None")
    
    if [ "$IDS_SOLUTION" != "None" ]; then
        gum spin --spinner pulse --title "Deploying $IDS_SOLUTION sensors..." -- sleep 3
        track_mitigation "Network Intrusion" "$IDS_SOLUTION"
        gum style --foreground 46 "✅ IDS/IPS: $IDS_SOLUTION"
        DEPLOYED_CONTROLS+=("Network:IDS")
        update_security_score 10
        
        echo
        if gum confirm "Enable APT28-specific Suricata rules?"; then
            gum spin --spinner pulse --title "Loading APT28 signatures..." -- sleep 2
            track_detection "C2 Traffic" "Suricata APT28 rules"
            gum style --foreground 46 "✅ Loaded APT28 C2 signatures"
            gum style --foreground 46 "✅ X-Agent beacon detection"
            gum style --foreground 46 "✅ X-Tunnel traffic patterns"
            update_security_score 8
        fi
    fi
    
    echo
    gum format -- "## Network Segmentation"
    
    if gum confirm "Implement network micro-segmentation?"; then
        gum spin --spinner pulse --title "Deploying zero-trust architecture..." -- sleep 3
        track_mitigation "Lateral Movement" "Network segmentation"
        gum style --foreground 46 "✅ VLANs segmented by function"
        gum style --foreground 46 "✅ East-West traffic inspection enabled"
        gum style --foreground 46 "✅ Jump servers for privileged access"
        DEPLOYED_CONTROLS+=("Network:Segmentation")
        update_security_score 15
    fi
    
    echo
    gum format -- "## DNS Security"
    
    if gum confirm "Deploy DNS monitoring and filtering?"; then
        DNS_SOLUTION=$(gum choose \
            "Cisco Umbrella" \
            "Infoblox BloxOne Threat Defense" \
            "Custom BIND with RPZ" \
            "Pi-hole Enterprise")
        
        gum spin --spinner pulse --title "Configuring $DNS_SOLUTION..." -- sleep 2
        track_detection "DNS Tunneling" "DNS monitoring"
        gum style --foreground 46 "✅ DNS monitoring: $DNS_SOLUTION"
        gum style --foreground 46 "✅ Detecting DNS tunneling attempts"
        gum style --foreground 46 "✅ Blocking malicious domains"
        DEPLOYED_CONTROLS+=("Network:DNS_Security")
        update_security_score 8
    fi
    
    echo
    gum format -- "## SSL/TLS Inspection"
    
    if gum confirm "Enable SSL/TLS decryption (C2 over HTTPS)?"; then
        gum style --foreground 11 "⚠️  NOTE: Privacy and performance impact"
        
        if gum confirm "Proceed with SSL inspection?"; then
            gum spin --spinner pulse --title "Deploying SSL decryption..." -- sleep 3
            track_detection "Encrypted C2" "SSL/TLS inspection"
            gum style --foreground 46 "✅ SSL inspection enabled"
            gum style --foreground 46 "✅ Certificate pinning bypass detection"
            DEPLOYED_CONTROLS+=("Network:SSL_Inspection")
            update_security_score 10
        fi
    fi
    
    echo
    gum format -- "## NetFlow/IPFIX Analysis"
    
    if gum confirm "Deploy network traffic analytics?"; then
        gum spin --spinner pulse --title "Configuring NetFlow collection..." -- sleep 2
        track_detection "Anomalous Traffic" "NetFlow analysis"
        gum style --foreground 46 "✅ NetFlow collectors deployed"
        gum style --foreground 46 "✅ Baseline traffic patterns established"
        gum style --foreground 46 "✅ Anomaly detection enabled"
        update_security_score 7
    fi
    
    log_action "NETWORK MONITORING: Complete"
    
    gum confirm "Proceed to Active Directory hardening?" || exit 0
}

# ============================================================================
# PHASE 6: ACTIVE DIRECTORY SECURITY
# ============================================================================
phase_ad_security() {
    phase_banner 6 "ACTIVE DIRECTORY SECURITY"
    
    gum format -- "## Domain Controller Hardening"
    gum format -- "APT28 targets: Domain credentials, Kerberos tickets, GPO"
    
    echo
    if gum confirm "Audit Active Directory security posture?"; then
        gum spin --spinner pulse --title "Running AD security assessment..." -- sleep 3
        
        gum style --foreground 11 "⚠️  Identified risks:"
        gum style --foreground 11 "   - 47 users with 'Password never expires'"
        gum style --foreground 11 "   - 12 service accounts with admin rights"
        gum style --foreground 11 "   - Domain Admins group has 8 members"
        gum style --foreground 11 "   - No protected users group configured"
    fi
    
    echo
    gum format -- "## Tiered Administration Model"
    
    if gum confirm "Implement tiered admin model (Red Forest)?"; then
        gum spin --spinner pulse --title "Deploying administrative tiers..." -- sleep 3
        track_mitigation "Privilege Escalation" "Tiered admin model"
        gum style --foreground 46 "✅ Tier 0: Domain Controllers isolated"
        gum style --foreground 46 "✅ Tier 1: Server management segregated"
        gum style --foreground 46 "✅ Tier 2: Workstation admins separated"
        gum style --foreground 46 "✅ PAWs (Privileged Access Workstations) deployed"
        DEPLOYED_CONTROLS+=("AD:TieredAdmin")
        update_security_score 15
    fi
    
    echo
    gum format -- "## Kerberos Security"
    
    if gum confirm "Harden Kerberos authentication?"; then
        
        # AES encryption
        if gum confirm "Enforce AES encryption for Kerberos?"; then
            gum spin --spinner pulse --title "Configuring Kerberos encryption..." -- sleep 2
            track_mitigation "Kerberoasting" "AES-256 enforcement"
            gum style --foreground 46 "✅ DES and RC4 disabled"
            gum style --foreground 46 "✅ AES-256 enforced"
            update_security_score 8
        fi
        
        # Protected Users group
        if gum confirm "Add privileged accounts to Protected Users group?"; then
            gum spin --spinner pulse --title "Configuring Protected Users..." -- sleep 2
            track_mitigation "Credential Theft" "Protected Users group"
            gum style --foreground 46 "✅ Domain Admins in Protected Users"
            gum style --foreground 46 "✅ NTLM disabled for these accounts"
            update_security_score 10
        fi
        
        # Ticket lifetime
        if gum confirm "Reduce Kerberos ticket lifetime?"; then
            gum spin --spinner pulse --title "Adjusting ticket policies..." -- sleep 2
            gum style --foreground 46 "✅ TGT lifetime: 10h → 4h"
            gum style --foreground 46 "✅ Service ticket lifetime: 10h → 2h"
            update_security_score 5
        fi
    fi
    
    echo
    gum format -- "## LDAP Hardening"
    
    if gum confirm "Enable LDAP signing and channel binding?"; then
        gum spin --spinner pulse --title "Hardening LDAP..." -- sleep 2
        track_mitigation "LDAP Relay" "LDAP signing/binding"
        gum style --foreground 46 "✅ LDAP signing required"
        gum style --foreground 46 "✅ LDAP channel binding enabled"
        gum style --foreground 46 "✅ LDAPS enforced"
        DEPLOYED_CONTROLS+=("AD:LDAP_Hardening")
        update_security_score 8
    fi
    
    echo
    gum format -- "## Privileged Account Monitoring"
    
    if gum confirm "Deploy privileged account monitoring?"; then
        gum spin --spinner pulse --title "Configuring advanced auditing..." -- sleep 2
        track_detection "Privileged Access" "Account monitoring"
        gum style --foreground 46 "✅ Monitoring: Domain Admin logons"
        gum style --foreground 46 "✅ Monitoring: Service account usage"
        gum style --foreground 46 "✅ Monitoring: Delegation changes"
        gum style --foreground 46 "✅ Monitoring: GPO modifications"
        DEPLOYED_CONTROLS+=("AD:PrivilegedMonitoring")
        update_security_score 10
    fi
    
    echo
    if gum confirm "Deploy Microsoft Defender for Identity (formerly ATP)?"; then
        gum spin --spinner pulse --title "Deploying Defender for Identity sensors..." -- sleep 3
        track_detection "AD Attacks" "Defender for Identity"
        gum style --foreground 46 "✅ Sensors deployed on all DCs"
        gum style --foreground 46 "✅ Detecting: Golden Ticket attacks"
        gum style --foreground 46 "✅ Detecting: DCSync attempts"
        gum style --foreground 46 "✅ Detecting: Pass-the-Hash/Ticket"
        DEPLOYED_CONTROLS+=("AD:DefenderForIdentity")
        update_security_score 15
    fi
    
    log_action "AD SECURITY: Hardening complete"
    
    gum confirm "Proceed to SIEM and detection engineering?" || exit 0
}

# ============================================================================
# PHASE 7: SIEM & DETECTION ENGINEERING
# ============================================================================
phase_siem_detection() {
    phase_banner 7 "SIEM & DETECTION ENGINEERING"
    
    gum format -- "## Log Collection & Aggregation"
    
    if [[ "$SIEM_PLATFORM" == *"None"* ]]; then
        gum style --foreground 196 "❌ No SIEM deployed - Critical visibility gap!"
        
        if gum confirm "Deploy SIEM now?"; then
            SIEM_PLATFORM=$(gum choose \
                "Splunk Enterprise" \
                "Microsoft Sentinel" \
                "Elastic Security")
            
            gum spin --spinner pulse --title "Deploying $SIEM_PLATFORM..." -- sleep 4
            gum style --foreground 46 "✅ SIEM deployed: $SIEM_PLATFORM"
            DEPLOYED_CONTROLS+=("SIEM:$SIEM_PLATFORM")
            update_security_score 20
        fi
    fi
    
    echo
    gum format -- "## Log Source Configuration"
    
    LOG_SOURCES=$(gum choose --no-limit --header "Configure log sources:" \
        "Windows Event Logs (Security, System, Application)" \
        "Windows PowerShell logs (4103, 4104)" \
        "Sysmon operational logs" \
        "Firewall logs" \
        "DNS query logs" \
        "Web proxy logs" \
        "VPN authentication logs" \
        "EDR/XDR telemetry" \
        "Active Directory audit logs")
    
    gum spin --spinner pulse --title "Configuring log ingestion..." -- sleep 3
    gum style --foreground 46 "✅ Log sources configured"
    gum style --foreground 46 "✅ Estimated log volume: $((TOTAL_HOSTS * 5))GB/day"
    DEPLOYED_CONTROLS+=("SIEM:LogSources")
    update_security_score 10
    
    echo
    gum format -- "## Sysmon Deployment"
    
    if gum confirm "Deploy Sysmon with SwiftOnSecurity config?"; then
        gum spin --spinner pulse --title "Deploying Sysmon to all endpoints..." -- sleep 3
        track_detection "Process Creation" "Sysmon telemetry"
        gum style --foreground 46 "✅ Sysmon deployed to $TOTAL_HOSTS hosts"
        gum style --foreground 46 "✅ Process creation logging (Event ID 1)"
        gum style --foreground 46 "✅ Network connection logging (Event ID 3)"
        gum style --foreground 46 "✅ Image load logging (Event ID 7)"
        DEPLOYED_CONTROLS+=("Logging:Sysmon")
        update_security_score 12
    fi
    
    echo
    gum format -- "## APT28 Detection Rules"
    
    if gum confirm "Deploy Sigma rules for APT28?"; then
        gum spin --spinner pulse --title "Converting Sigma rules to $SIEM_PLATFORM..." -- sleep 3
        
        gum format -- "### Deployed Detection Rules"
        
        track_detection "T1059.001" "PowerShell suspicious parameters"
        track_detection "T1003.001" "Mimikatz credential dumping"
        track_detection "T1021.002" "PsExec lateral movement"
        track_detection "T1053.005" "Suspicious scheduled task"
        track_detection "T1218.011" "Rundll32 proxy execution"
        track_detection "T1027" "Obfuscated command execution"
        track_detection "T1070.001" "Event log clearing"
        track_detection "T1547.001" "Registry persistence"
        
        gum style --foreground 46 "✅ 24 Sigma rules deployed"
        gum style --foreground 46 "✅ APT28-specific IoC matching"
        gum style --foreground 46 "✅ Behavioral analytics enabled"
        update_security_score 15
    fi
    
    echo
    gum format -- "## Use Case Development"
    
    if gum confirm "Create custom detection use cases?"; then
        
        USE_CASE=$(gum choose --header "Select use case to develop:" \
            "Credential Dumping Detection" \
            "Lateral Movement via WMI/PsExec" \
            "C2 Beacon Detection" \
            "Data Exfiltration Detection")
        
        case $USE_CASE in
            *"Credential Dumping"*)
                gum spin --spinner pulse --title "Building credential dump detection logic..." -- sleep 2
                gum style --foreground 46 "✅ Rule: LSASS access by non-system process"
                gum style --foreground 46 "✅ Rule: SAM registry access"
                gum style --foreground 46 "✅ Rule: DCSync detection"
                ;;
            *"Lateral Movement"*)
                gum spin --spinner pulse --title "Creating lateral movement detection..." -- sleep 2
                gum style --foreground 46 "✅ Rule: Multiple failed logons then success"
                gum style --foreground 46 "✅ Rule: Admin share access patterns"
                gum style --foreground 46 "✅ Rule: Remote service creation"
                ;;
            *"C2 Beacon"*)
                gum spin --spinner pulse --title "Developing C2 detection logic..." -- sleep 2
                gum style --foreground 46 "✅ Rule: Periodic beaconing intervals"
                gum style --foreground 46 "✅ Rule: HTTPS to suspicious IPs"
                gum style --foreground 46 "✅ Rule: DNS tunneling patterns"
                ;;
            *"Data Exfiltration"*)
                gum spin --spinner pulse --title "Building exfil detection rules..." -- sleep 2
                gum style --foreground 46 "✅ Rule: Large outbound transfers"
                gum style --foreground 46 "✅ Rule: Unusual cloud storage uploads"
                gum style --foreground 46 "✅ Rule: Archive creation followed by upload"
                ;;
        esac
        
        update_security_score 10
    fi
    
    echo
    gum format -- "## Alert Tuning"
    
    if gum confirm "Perform alert tuning and false positive reduction?"; then
        gum spin --spinner pulse --title "Analyzing historical alerts..." -- sleep 3
        
        TOTAL_ALERTS=$((500 + RANDOM % 1000))
        TRUE_POSITIVES=$((TOTAL_ALERTS / 20))
        FALSE_POSITIVES=$((TOTAL_ALERTS - TRUE_POSITIVES))
        
        gum style --foreground 11 "📊 Past 30 days:"
        gum style --foreground 11 "   Total alerts: $TOTAL_ALERTS"
        gum style --foreground 196 "   False positives: $FALSE_POSITIVES ($(( (FALSE_POSITIVES * 100) / TOTAL_ALERTS ))%)"
        gum style --foreground 46 "   True positives: $TRUE_POSITIVES"
        
        if gum confirm "Apply tuning to reduce noise?"; then
            gum spin --spinner pulse --title "Tuning detection rules..." -- sleep 2
            gum style --foreground 46 "✅ FP reduction: ~40%"
            gum style --foreground 46 "✅ Alert fidelity improved"
            update_security_score 8
        fi
    fi
    
    log_action "SIEM: Detection engineering complete"
    
    gum confirm "Proceed to threat hunting?" || exit 0
}

# ============================================================================
# PHASE 8: PROACTIVE THREAT HUNTING
# ============================================================================
phase_threat_hunting() {
    phase_banner 8 "PROACTIVE THREAT HUNTING"
    
    gum format -- "## Threat Hunting Mission"
    gum format -- "Hypothesis: APT28 may already be in the environment"
    
    echo
    HUNT_HYPOTHESIS=$(gum choose --header "Select hunting hypothesis:" \
        "Search for X-Agent implant artifacts" \
        "Hunt for living-off-the-land binaries (LOLBins)" \
        "Identify suspicious PowerShell usage" \
        "Find unauthorized scheduled tasks" \
        "Detect anomalous network connections")
    
    gum spin --spinner pulse --title "Executing threat hunt: $HUNT_HYPOTHESIS..." -- sleep 4
    
    echo
    gum format -- "### Hunt Results"
    
    # Simulate findings
    SUSPICIOUS_FINDINGS=$((RANDOM % 5))
    
    if [ $SUSPICIOUS_FINDINGS -gt 0 ]; then
        ((INCIDENTS_DETECTED += SUSPICIOUS_FINDINGS))
        gum style --foreground 196 "🚨 SUSPICIOUS ACTIVITY DETECTED!"
        
        for i in $(seq 1 $SUSPICIOUS_FINDINGS); do
            case $((RANDOM % 4)) in
                0)
                    FINDING="Unsigned PowerShell running with -EncodedCommand"
                    HOST="WKS-$(printf '%04d' $((RANDOM % 9999)))"
                    ;;
                1)
                    FINDING="LSASS memory read by non-system process"
                    HOST="SRV-$(printf '%04d' $((RANDOM % 9999)))"
                    ;;
                2)
                    FINDING="Scheduled task created via remote WMI"
                    HOST="WKS-$(printf '%04d' $((RANDOM % 9999)))"
                    ;;
                3)
                    FINDING="Connection to known APT28 IP: 185.220.101.$((RANDOM % 255))"
                    HOST="WKS-$(printf '%04d' $((RANDOM % 9999)))"
                    ;;
            esac
            
            DETECTED_THREATS+=("$HOST|$FINDING")
            gum style --foreground 196 "  ⚠️  $HOST: $FINDING"
            log_action "THREAT DETECTED: $HOST - $FINDING"
        done
        
        echo
        if gum confirm "Initiate incident response procedures?"; then
            phase_incident_response
            return
        fi
    else
        gum style --foreground 46 "✅ No suspicious activity detected"
        gum style --foreground 46 "   Environment appears clean"
        update_security_score 5
    fi
    
    echo
    gum format -- "## Hunt Documentation"
    
    if gum confirm "Document hunt methodology?"; then
        gum write --height 5 --placeholder "Document hunt procedures and findings..." > /tmp/threat-hunt-notes.txt
        gum style --foreground 46 "✅ Hunt notes saved to /tmp/threat-hunt-notes.txt"
    fi
    
    log_action "THREAT HUNT: Complete - $SUSPICIOUS_FINDINGS findings"
    
    if [ $SUSPICIOUS_FINDINGS -eq 0 ]; then
        gum confirm "Proceed to penetration testing?" || exit 0
    fi
}

# ============================================================================
# PHASE 9: INCIDENT RESPONSE
# ============================================================================
phase_incident_response() {
    phase_banner 9 "INCIDENT RESPONSE"
    
    gum format -- "## Active Incident: APT28 Activity Detected"
    gum style --foreground 196 --bold "🚨 SECURITY INCIDENT IN PROGRESS"
    
    echo
    gum format -- "### Detected Threats"
    for threat in "${DETECTED_THREATS[@]}"; do
        IFS='|' read -r host finding <<< "$threat"
        gum style --foreground 196 "  🎯 $host: $finding"
    done
    
    echo
    IR_LEAD=$(gum input --placeholder "Incident Response lead name" --value "SOC Analyst $(whoami)")
    INCIDENT_ID="INC-$(date +%Y%m%d)-$((1000 + RANDOM % 9000))"
    
    log_action "INCIDENT DECLARED: $INCIDENT_ID by $IR_LEAD"
    
    gum style --foreground 11 "📋 Incident ID: $INCIDENT_ID"
    gum style --foreground 11 "👤 IR Lead: $IR_LEAD"
    
    echo
    gum format -- "## Containment Actions"
    
    # Isolate infected hosts
    if gum confirm "Isolate compromised endpoints from network?"; then
        for threat in "${DETECTED_THREATS[@]}"; do
            IFS='|' read -r host finding <<< "$threat"
            gum spin --spinner pulse --title "Isolating $host via EDR..." -- sleep 2
            gum style --foreground 46 "✅ $host isolated (network quarantine)"
            BLOCKED_ATTACKS+=("$host|Network isolation")
            ((INCIDENTS_CONTAINED++))
        done
        update_security_score 10
    fi
    
    echo
    # Disable compromised accounts
    if gum confirm "Disable potentially compromised user accounts?"; then
        COMPROMISED_USER=$(gum input --placeholder "Username to disable" --value "john.smith")
        gum spin --spinner pulse --title "Disabling AD account $COMPROMISED_USER..." -- sleep 1
        gum style --foreground 46 "✅ Account disabled: $COMPROMISED_USER"
        gum style --foreground 46 "✅ Sessions terminated"
        gum style --foreground 46 "✅ Password reset required"
        ((INCIDENTS_CONTAINED++))
        update_security_score 5
    fi
    
    echo
    # Reset credentials
    if gum confirm "Force password reset for all privileged accounts?"; then
        gum spin --spinner pulse --title "Resetting privileged account passwords..." -- sleep 3
        gum style --foreground 46 "✅ Domain Admin passwords reset"
        gum style --foreground 46 "✅ Service account passwords reset"
        gum style --foreground 46 "✅ Kerberos golden ticket mitigation: krbtgt reset"
        update_security_score 15
    fi
    
    echo
    gum format -- "## Eradication"
    
    if gum confirm "Remove malware and persistence mechanisms?"; then
        
        # Malware removal
        gum spin --spinner pulse --title "Scanning for APT28 malware..." -- sleep 3
        gum style --foreground 46 "✅ X-Agent implant removed from 2 hosts"
        gum style --foreground 46 "✅ Scheduled task persistence deleted"
        gum style --foreground 46 "✅ Registry run keys cleaned"
        gum style --foreground 46 "✅ WMI subscriptions removed"
        
        # Re-image
        if gum confirm "Re-image compromised systems?"; then
            gum spin --spinner pulse --title "Re-imaging affected endpoints..." -- sleep 4
            gum style --foreground 46 "✅ Clean OS deployment initiated"
            update_security_score 10
        fi
    fi
    
    echo
    gum format -- "## Forensic Collection"
    
    if gum confirm "Collect forensic artifacts?"; then
        COLLECTION_TYPE=$(gum choose --no-limit \
            "Memory dump (LSASS, full RAM)" \
            "Disk images (C:\ drive)" \
            "Event logs (Security, Sysmon)" \
            "Network PCAP" \
            "Registry hives")
        
        gum spin --spinner pulse --title "Collecting forensic evidence..." -- sleep 4
        gum style --foreground 46 "✅ Artifacts collected and hashed"
        gum style --foreground 46 "✅ Chain of custody documented"
        gum style --foreground 46 "✅ Evidence stored: /tmp/forensics/$INCIDENT_ID/"
    fi
    
    echo
    gum format -- "## Recovery & Monitoring"
    
    if gum confirm "Restore affected systems to production?"; then
        gum spin --spinner pulse --title "Restoring services..." -- sleep 3
        gum style --foreground 46 "✅ Systems restored"
        gum style --foreground 46 "✅ Enhanced monitoring deployed"
        gum style --foreground 46 "✅ Threat hunt scheduled for 7 days"
    fi
    
    echo
    gum format -- "## Incident Documentation"
    
    if gum confirm "Generate incident report?"; then
        gum write --height 8 --placeholder "Executive summary of incident..." > /tmp/incident-summary-$INCIDENT_ID.txt
        gum style --foreground 46 "✅ Incident report saved"
    fi
    
    log_action "INCIDENT $INCIDENT_ID: Contained and eradicated"
    
    gum confirm "Proceed to lessons learned?" || exit 0
}

# ============================================================================
# PHASE 10: RED TEAM ASSESSMENT
# ============================================================================
phase_red_team_test() {
    phase_banner 10 "RED TEAM ASSESSMENT"
    
    gum format -- "## Validate Defenses with Red Team Exercise"
    gum format -- "Simulate APT28 attack chain to test detection capabilities"
    
    echo
    if gum confirm "Authorize red team engagement?"; then
        
        gum format -- "### Engagement Rules"
        SCOPE=$(gum choose --no-limit --header "Red team scope:" \
            "Phishing simulation" \
            "External penetration test" \
            "Assumed breach (internal)" \
            "Full kill chain simulation")
        
        DURATION=$(gum choose \
            "1 week" \
            "2 weeks" \
            "30 days" \
            "90 days (purple team)")
        
        gum style --foreground 11 "📋 Engagement authorized: $DURATION"
        
        echo
        gum spin --spinner pulse --title "Red team executing APT28 TTPs..." -- sleep 5
        
        gum format -- "### Red Team Results"
        
        DETECTION_RATE=$((50 + (SECURITY_SCORE / 3) + RANDOM % 20))
        if [ $DETECTION_RATE -gt 100 ]; then
            DETECTION_RATE=100
        fi
        
        DWELL_TIME=$((20 - (SECURITY_SCORE / 10)))
        if [ $DWELL_TIME -lt 1 ]; then
            DWELL_TIME=1
        fi
        
        gum style --foreground 46 "📊 Detection Rate: ${DETECTION_RATE}%"
        gum style --foreground 11 "⏱️  Mean Time to Detect: ${DWELL_TIME} hours"
        
        if [ $DETECTION_RATE -ge 80 ]; then
            gum style --foreground 46 "✅ EXCELLENT: Strong detection capabilities"
            update_security_score 15
        elif [ $DETECTION_RATE -ge 60 ]; then
            gum style --foreground 11 "⚠️  GOOD: Some gaps identified"
            update_security_score 5
        else
            gum style --foreground 196 "❌ NEEDS IMPROVEMENT: Significant blind spots"
            update_security_score -10
        fi
        
        echo
        gum format -- "### Identified Gaps"
        gum style --foreground 11 "  - Lateral movement via WMI not detected"
        gum style --foreground 11 "  - Exfiltration over DNS tunneling missed"
        gum style --foreground 46 "  + Initial access detected quickly"
        gum style --foreground 46 "  + Credential dumping blocked"
        
        if gum confirm "Conduct purple team debrief?"; then
            gum style --foreground 46 "✅ Purple team session scheduled"
            gum style --foreground 46 "✅ Detection rules updated based on findings"
            update_security_score 10
        fi
    fi
    
    log_action "RED TEAM: Assessment complete - ${DETECTION_RATE}% detection rate"
    
    gum confirm "Proceed to final report?" || exit 0
}

# ============================================================================
# FINAL REPORT GENERATION
# ============================================================================
generate_report() {
    local mission_end=$(date +%s)
    local duration=$((mission_end - MISSION_START))
    local duration_min=$((duration / 60))
    
    clear
    gum style \
        --foreground 27 --border-foreground 27 --border double \
        --width 90 --align center --padding "2 4" --bold \
        "🛡️  BLUE TEAM MISSION COMPLETE" \
        "APT28 Defense Operations - After Action Report"
    
    echo
    gum format -- "## Defense Posture Summary"
    
    # Overall score assessment
    local grade
    if [ $SECURITY_SCORE -ge 90 ]; then
        grade="A - Excellent"
        gum style --foreground 46 --bold "🏆 SECURITY GRADE: $grade"
    elif [ $SECURITY_SCORE -ge 80 ]; then
        grade="B - Good"
        gum style --foreground 46 "✅ SECURITY GRADE: $grade"
    elif [ $SECURITY_SCORE -ge 70 ]; then
        grade="C - Adequate"
        gum style --foreground 11 "⚠️  SECURITY GRADE: $grade"
    elif [ $SECURITY_SCORE -ge 60 ]; then
        grade="D - Needs Improvement"
        gum style --foreground 208 "⚠️  SECURITY GRADE: $grade"
    else
        grade="F - Critical Gaps"
        gum style --foreground 196 "❌ SECURITY GRADE: $grade"
    fi
    
    echo
    gum table --border rounded --width 90 <<EOF
Metric,Value
Mission Duration,${duration_min} minutes
Final Security Score,$SECURITY_SCORE/100
Threat Level,$THREAT_LEVEL
Deployed Controls,${#DEPLOYED_CONTROLS[@]}
Detection Rules,${#DETECTION_RULES[@]}
Incidents Detected,$INCIDENTS_DETECTED
Incidents Contained,$INCIDENTS_CONTAINED
Blocked Attacks,${#BLOCKED_ATTACKS[@]}
EOF
    
    echo
    gum format -- "## Deployed Security Controls"
    
    if [ ${#DEPLOYED_CONTROLS[@]} -gt 0 ]; then
        for control in "${DEPLOYED_CONTROLS[@]}"; do
            gum style --foreground 46 "  ✅ $control"
        done
    else
        gum style --foreground 196 "  ❌ No controls deployed"
    fi
    
    echo
    gum format -- "## Detection Coverage (MITRE ATT&CK)"
    
    if [ ${#DETECTION_RULES[@]} -gt 0 ]; then
        for technique in "${!DETECTION_RULES[@]}"; do
            echo "  🔍 $technique: ${DETECTION_RULES[$technique]}"
        done
    fi
    
    echo
    gum format -- "## Threat Detections"
    
    if [ ${#DETECTED_THREATS[@]} -gt 0 ]; then
        for threat in "${DETECTED_THREATS[@]}"; do
            IFS='|' read -r host finding <<< "$threat"
            gum style --foreground 196 "  🚨 $host: $finding"
        done
    else
        gum style --foreground 46 "  ✅ No threats detected - Clean environment"
    fi
    
    echo
    gum format -- "## Recommendations"
    
    if [ $SECURITY_SCORE -lt 70 ]; then
        gum style --foreground 196 "### Critical Actions Required"
        echo "  1. Deploy EDR/XDR platform immediately"
        echo "  2. Implement SIEM with APT28 detection rules"
        echo "  3. Harden Active Directory (tiered admin model)"
        echo "  4. Deploy email sandboxing"
        echo "  5. Conduct security awareness training"
    elif [ $SECURITY_SCORE -lt 85 ]; then
        gum style --foreground 11 "### Recommended Improvements"
        echo "  1. Enhance network segmentation"
        echo "  2. Deploy additional detection rules"
        echo "  3. Conduct red team assessment"
        echo "  4. Improve incident response procedures"
    else
        gum style --foreground 46 "### Maintain and Enhance"
        echo "  1. Continue threat hunting operations"
        echo "  2. Regular red team exercises"
        echo "  3. Stay current with APT28 TTPs"
        echo "  4. Share threat intelligence with peers"
    fi
    
    echo
    gum format -- "## Incident Timeline"
    
    if [ ${#INCIDENT_TIMELINE[@]} -gt 0 ]; then
        # Show last 10 events
        local start=$((${#INCIDENT_TIMELINE[@]} - 10))
        if [ $start -lt 0 ]; then
            start=0
        fi
        
        for i in $(seq $start $((${#INCIDENT_TIMELINE[@]} - 1))); do
            IFS='|' read -r timestamp event <<< "${INCIDENT_TIMELINE[$i]}"
            echo "  [$timestamp] $event"
        done
    fi
    
    echo
    gum style --foreground 240 "Detailed log saved to: $LOG_FILE"
    
    echo
    if gum confirm "Generate formal security assessment report?"; then
        REPORT_FILE="/tmp/blueteam-assessment-$(date +%Y%m%d-%H%M%S).txt"
        {
            echo "============================================"
            echo "BLUE TEAM SECURITY ASSESSMENT REPORT"
            echo "APT28 (Fancy Bear) Defense Evaluation"
            echo "Generated: $(date)"
            echo "============================================"
            echo
            echo "EXECUTIVE SUMMARY:"
            echo "  Organization: $ORGANIZATION"
            echo "  Security Grade: $grade"
            echo "  Security Score: $SECURITY_SCORE/100"
            echo "  Threat Level: $THREAT_LEVEL"
            echo "  Assessment Duration: ${duration_min} minutes"
            echo
            echo "DEPLOYED CONTROLS: ${#DEPLOYED_CONTROLS[@]}"
            for control in "${DEPLOYED_CONTROLS[@]}"; do
                echo "  - $control"
            done
            echo
            echo "DETECTION CAPABILITIES: ${#DETECTION_RULES[@]} rules"
            for technique in "${!DETECTION_RULES[@]}"; do
                echo "  - $technique: ${DETECTION_RULES[$technique]}"
            done
            echo
            echo "INCIDENT RESPONSE:"
            echo "  Incidents Detected: $INCIDENTS_DETECTED"
            echo "  Incidents Contained: $INCIDENTS_CONTAINED"
            echo "  Containment Rate: $([ $INCIDENTS_DETECTED -gt 0 ] && echo "$((INCIDENTS_CONTAINED * 100 / INCIDENTS_DETECTED))%" || echo "N/A")"
            echo
            echo "MITIGATIONS DEPLOYED: ${#MITIGATIONS[@]}"
            for attack in "${!MITIGATIONS[@]}"; do
                echo "  - $attack: ${MITIGATIONS[$attack]}"
            done
            echo
            if [ $SECURITY_SCORE -lt 70 ]; then
                echo "RISK ASSESSMENT: HIGH"
                echo "  Organization remains vulnerable to APT28 attack chain."
                echo "  Immediate remediation required."
            elif [ $SECURITY_SCORE -lt 85 ]; then
                echo "RISK ASSESSMENT: MODERATE"
                echo "  Baseline defenses in place, but gaps remain."
                echo "  Continue security program maturity."
            else
                echo "RISK ASSESSMENT: LOW"
                echo "  Strong defensive posture against APT28 TTPs."
                echo "  Maintain vigilance and continuous improvement."
            fi
            echo
            echo "============================================"
        } > "$REPORT_FILE"
        
        gum style --foreground 46 "✅ Report saved: $REPORT_FILE"
    fi
    
    echo
    gum style \
        --foreground 27 --border normal \
        --align center --padding "1 2" \
        "Defense log: $LOG_FILE"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    check_dependencies
    
    mission_briefing
    phase_asset_inventory
    phase_threat_intelligence
    phase_email_security
    phase_endpoint_protection
    phase_network_monitoring
    phase_ad_security
    phase_siem_detection
    phase_threat_hunting
    
    # Only do red team if no incidents
    if [ $INCIDENTS_DETECTED -eq 0 ]; then
        phase_red_team_test
    fi
    
    generate_report
    
    echo
    if [ $SECURITY_SCORE -ge 80 ]; then
        gum style --foreground 46 --bold "🛡️  Defense mission successful. Network secured."
    else
        gum style --foreground 11 --bold "⚠️  Defense gaps identified. Continue hardening operations."
    fi
}

# Run main
main
