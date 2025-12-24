#!/bin/bash
# ============================================================================
# BLUE TEAM: LAZARUS GROUP DEFENSE SIMULATOR
# ============================================================================
# Defending against North Korean APT: WannaCry, Financial heists, Destructive attacks
# Focus: Ransomware defense, SWIFT security, cryptocurrency protection
# ============================================================================

set -euo pipefail
trap cleanup INT TERM

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
VERSION="1.0"
LOG_FILE="/tmp/blueteam-lazarus-$(date +%Y%m%d-%H%M%S).log"
INCIDENT_FILE="/tmp/lazarus-incidents-$(date +%Y%m%d-%H%M%S).json"
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
RANSOMWARE_RISK="HIGH"
FINANCIAL_RISK="HIGH"

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
    if [ $SECURITY_SCORE -ge 85 ]; then
        THREAT_LEVEL="LOW"
        RANSOMWARE_RISK="LOW"
        FINANCIAL_RISK="LOW"
    elif [ $SECURITY_SCORE -ge 70 ]; then
        THREAT_LEVEL="GUARDED"
        RANSOMWARE_RISK="MODERATE"
        FINANCIAL_RISK="MODERATE"
    elif [ $SECURITY_SCORE -ge 50 ]; then
        THREAT_LEVEL="ELEVATED"
        RANSOMWARE_RISK="ELEVATED"
        FINANCIAL_RISK="ELEVATED"
    elif [ $SECURITY_SCORE -ge 30 ]; then
        THREAT_LEVEL="HIGH"
        RANSOMWARE_RISK="HIGH"
        FINANCIAL_RISK="HIGH"
    else
        THREAT_LEVEL="SEVERE"
        RANSOMWARE_RISK="CRITICAL"
        FINANCIAL_RISK="CRITICAL"
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
    
    gum style --foreground $color "🛡️  Threat: $THREAT_LEVEL | Ransomware: $RANSOMWARE_RISK | Financial: $FINANCIAL_RISK | Score: $SECURITY_SCORE/100"
}

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
        "Defending Against Lazarus Group" \
        "" \
        "Ransomware & Financial Crime Defense v${VERSION}"
    
    echo
    
    gum format -- "# Mission Parameters"
    gum format -- "**Adversary**: Lazarus Group (HIDDEN COBRA, APT38, Zinc)"
    gum format -- "**Attribution**: RGB Bureau 121 - North Korea"
    gum format -- "**MITRE Group**: G0032"
    gum format -- "**Threat Focus**: WannaCry ransomware, SWIFT heists, destructive attacks, crypto theft"
    gum format -- "**Your Role**: Chief Security Officer & Incident Response Lead"
    gum format -- "**Objective**: Prevent ransomware, secure financial systems, protect assets"
    
    echo
    
    ORGANIZATION=$(gum choose --header "Select your organization type:" \
        "Financial Institution (Bank/SWIFT)" \
        "Healthcare Network (Ransomware target)" \
        "Cryptocurrency Exchange" \
        "Government Agency" \
        "Critical Infrastructure")
    
    log_action "=== BLUE TEAM LAZARUS DEFENSE START ==="
    log_action "Organization: $ORGANIZATION"
    
    echo
    gum format -- "## Intelligence Brief"
    gum style --foreground 196 "🚨 CRITICAL: Lazarus Group activity detected globally"
    gum style --foreground 11 "📊 Targeting: $ORGANIZATION sector"
    gum style --foreground 11 "🎯 Attack vectors: Ransomware (WannaCry), Financial fraud, Crypto theft"
    gum style --foreground 11 "💰 Estimated losses: \$2.1 billion globally (2014-2024)"
    
    echo
    if ! gum confirm "Begin defensive operations?"; then
        echo "Mission cancelled"
        exit 0
    fi
}

# ============================================================================
# PHASE 1: VULNERABILITY MANAGEMENT - ETERNALBLUE PATCHING
# ============================================================================
phase_vulnerability_management() {
    phase_banner 1 "VULNERABILITY MANAGEMENT - ETERNALBLUE DEFENSE"
    
    gum format -- "## Critical Patch Assessment"
    gum format -- "### MS17-010 (EternalBlue) - WannaCry Vulnerability"
    
    gum spin --spinner dot --title "Scanning network for MS17-010 vulnerability..." -- sleep 3
    
    TOTAL_HOSTS=$((200 + RANDOM % 800))
    VULNERABLE_HOSTS=$((RANDOM % (TOTAL_HOSTS / 2)))
    PATCHED_HOSTS=$((TOTAL_HOSTS - VULNERABLE_HOSTS))
    
    gum style --foreground 11 "📊 Total Windows hosts: $TOTAL_HOSTS"
    
    if [ $VULNERABLE_HOSTS -gt 0 ]; then
        gum style --foreground 196 --bold "🚨 CRITICAL: $VULNERABLE_HOSTS hosts vulnerable to EternalBlue!"
        gum style --foreground 46 "✅ Patched hosts: $PATCHED_HOSTS"
        
        echo
        if gum confirm "Deploy MS17-010 patch emergency rollout?"; then
            track_mitigation "WannaCry/EternalBlue" "MS17-010 patching"
            gum spin --spinner pulse --title "Deploying KB4012212 via WSUS/SCCM..." -- sleep 4
            
            PATCHED_NOW=$((VULNERABLE_HOSTS * 95 / 100))
            REMAINING=$((VULNERABLE_HOSTS - PATCHED_NOW))
            
            gum style --foreground 46 "✅ Patched: $PATCHED_NOW hosts"
            if [ $REMAINING -gt 0 ]; then
                gum style --foreground 11 "⚠️  Offline/unreachable: $REMAINING hosts"
            fi
            
            DEPLOYED_CONTROLS+=("Patching:MS17-010_Emergency")
            update_security_score 20
        else
            gum style --foreground 196 "❌ WARNING: Network remains vulnerable to WannaCry"
            update_security_score -10
        fi
    else
        gum style --foreground 46 --bold "✅ ALL SYSTEMS PATCHED"
        gum style --foreground 46 "   No EternalBlue vulnerability detected"
        update_security_score 15
    fi
    
    echo
    gum format -- "## SMBv1 Protocol Hardening"
    
    if gum confirm "Disable SMBv1 protocol (recommended)?"; then
        track_mitigation "SMB Exploits" "SMBv1 disabled"
        gum spin --spinner pulse --title "Disable-WindowsOptionalFeature -FeatureName SMB1Protocol..." -- sleep 2
        gum style --foreground 46 "✅ SMBv1 disabled network-wide"
        gum style --foreground 46 "✅ Only SMBv2/v3 allowed"
        DEPLOYED_CONTROLS+=("Network:SMBv1_Disabled")
        update_security_score 10
    fi
    
    log_action "PATCHING: MS17-010 deployed to $TOTAL_HOSTS hosts"
    
    gum confirm "Proceed to ransomware defenses?" || exit 0
}

# ============================================================================
# PHASE 2: RANSOMWARE DEFENSES
# ============================================================================
phase_ransomware_defense() {
    phase_banner 2 "RANSOMWARE DEFENSE - WANNACRY PROTECTION"
    
    gum format -- "## Multi-Layer Ransomware Protection"
    
    # Backup verification
    gum format -- "### Backup Infrastructure"
    
    if gum confirm "Verify backup integrity and isolation?"; then
        track_mitigation "Ransomware Data Loss" "Immutable backups"
        gum spin --spinner pulse --title "Testing backup systems..." -- sleep 3
        
        gum style --foreground 46 "✅ Backup status:"
        gum style --foreground 46 "   • Daily full backups: Active"
        gum style --foreground 46 "   • Incremental backups: Every 4 hours"
        gum style --foreground 46 "   • Air-gapped offline backup: Weekly"
        gum style --foreground 46 "   • Backup testing: Last verified 2 days ago"
        gum style --foreground 46 "   • Retention: 90 days"
        
        if gum confirm "Implement immutable backup storage (S3 Object Lock)?"; then
            gum spin --spinner pulse --title "Configuring immutable backups..." -- sleep 2
            gum style --foreground 46 "✅ Immutable backups enabled (90-day retention lock)"
            update_security_score 15
        fi
        
        DEPLOYED_CONTROLS+=("Backup:Immutable")
        update_security_score 10
    fi
    
    echo
    gum format -- "### Anti-Ransomware Solutions"
    
    EDR_SOLUTION=$(gum choose --header "Deploy/enhance anti-ransomware EDR:" \
        "Microsoft Defender for Endpoint (Controlled Folder Access)" \
        "CrowdStrike Falcon (Behavioral prevention)" \
        "Sophos Intercept X (CryptoGuard)" \
        "SentinelOne (Ransomware rollback)")
    
    if [[ "$EDR_SOLUTION" != *"None"* ]]; then
        track_mitigation "Ransomware Execution" "$EDR_SOLUTION"
        gum spin --spinner pulse --title "Deploying $EDR_SOLUTION..." -- sleep 3
        
        gum style --foreground 46 "✅ EDR: $EDR_SOLUTION"
        gum style --foreground 46 "✅ Ransomware behavioral detection: Active"
        gum style --foreground 46 "✅ File encryption monitoring: Enabled"
        gum style --foreground 46 "✅ Automatic process termination: Configured"
        
        DEPLOYED_CONTROLS+=("EDR:AntiRansomware")
        update_security_score 15
    fi
    
    echo
    gum format -- "### Controlled Folder Access (Windows)"
    
    if gum confirm "Enable Controlled Folder Access (protect critical folders)?"; then
        track_mitigation "Ransomware Encryption" "Controlled Folder Access"
        gum spin --spinner pulse --title "Set-MpPreference -EnableControlledFolderAccess Enabled..." -- sleep 2
        
        gum style --foreground 46 "✅ Protected folders:"
        gum style --foreground 46 "   • C:\\Users\\*\\Documents"
        gum style --foreground 46 "   • C:\\Users\\*\\Pictures"
        gum style --foreground 46 "   • C:\\Users\\*\\Desktop"
        gum style --foreground 46 "   • Custom: D:\\SharedData"
        
        DEPLOYED_CONTROLS+=("Windows:ControlledFolderAccess")
        update_security_score 12
    fi
    
    echo
    gum format -- "### Network Segmentation"
    
    if gum confirm "Implement network segmentation (prevent lateral spread)?"; then
        track_mitigation "Ransomware Propagation" "Network segmentation"
        gum spin --spinner pulse --title "Configuring VLANs and firewall rules..." -- sleep 3
        
        gum style --foreground 46 "✅ Network segments created:"
        gum style --foreground 46 "   • User VLAN (restricted)"
        gum style --foreground 46 "   • Server VLAN (isolated)"
        gum style --foreground 46 "   • Management VLAN (admin only)"
        gum style --foreground 46 "✅ Inter-VLAN traffic: Firewall-inspected"
        
        DEPLOYED_CONTROLS+=("Network:Segmentation")
        update_security_score 12
    fi
    
    echo
    gum format -- "### User Awareness Training"
    
    if gum confirm "Deploy anti-phishing and ransomware awareness training?"; then
        gum spin --spinner pulse --title "Scheduling mandatory training..." -- sleep 2
        gum style --foreground 46 "✅ Training modules deployed"
        gum style --foreground 46 "✅ Phishing simulations: Monthly"
        gum style --foreground 46 "✅ Completion rate target: 95%"
        DEPLOYED_CONTROLS+=("Training:Awareness")
        update_security_score 8
    fi
    
    log_action "RANSOMWARE DEFENSE: ${#DEPLOYED_CONTROLS[@]} controls deployed"
    
    gum confirm "Proceed to financial system security?" || exit 0
}

# ============================================================================
# PHASE 3: FINANCIAL SYSTEM SECURITY (SWIFT/Banking)
# ============================================================================
phase_financial_security() {
    if [[ "$ORGANIZATION" != *"Financial"* ]] && [[ "$ORGANIZATION" != *"Crypto"* ]]; then
        gum style --foreground 11 "⏭️  Skipping financial controls (not applicable to $ORGANIZATION)"
        return
    fi
    
    phase_banner 3 "FINANCIAL SYSTEM SECURITY - SWIFT & TRANSACTION PROTECTION"
    
    gum format -- "## SWIFT Customer Security Program (CSP)"
    
    if gum confirm "Implement SWIFT CSP mandatory controls?"; then
        track_mitigation "SWIFT Fraud" "SWIFT CSP compliance"
        
        gum format -- "### Control 1: Restrict Internet Access"
        gum spin --spinner pulse --title "Implementing network isolation..." -- sleep 2
        gum style --foreground 46 "✅ SWIFT environment: Air-gapped from internet"
        gum style --foreground 46 "✅ Jump servers: Required for access"
        
        echo
        gum format -- "### Control 2: Transaction Integrity"
        gum spin --spinner pulse --title "Deploying message integrity validation..." -- sleep 2
        gum style --foreground 46 "✅ SWIFT message signing: Mandatory"
        gum style --foreground 46 "✅ Cryptographic verification: Enabled"
        
        echo
        gum format -- "### Control 3: Database Integrity"
        if gum confirm "Enable database integrity monitoring?"; then
            track_detection "T1565.001" "Database tampering detection"
            gum spin --spinner pulse --title "Configuring file integrity monitoring..." -- sleep 2
            gum style --foreground 46 "✅ FIM on SWIFT database files"
            gum style --foreground 46 "✅ Transaction log monitoring: Real-time"
            gum style --foreground 46 "✅ Alerts on unauthorized changes"
        fi
        
        echo
        gum format -- "### Control 4: Multi-Factor Authentication"
        gum spin --spinner pulse --title "Enforcing MFA for SWIFT operators..." -- sleep 2
        gum style --foreground 46 "✅ MFA: Hardware tokens required"
        gum style --foreground 46 "✅ Dual approval: High-value transactions"
        
        DEPLOYED_CONTROLS+=("SWIFT:CSP_Compliance")
        update_security_score 20
    fi
    
    echo
    gum format -- "## Transaction Monitoring & Fraud Detection"
    
    if gum confirm "Deploy AI-based transaction anomaly detection?"; then
        track_detection "Fraudulent Transactions" "ML anomaly detection"
        gum spin --spinner pulse --title "Training fraud detection models..." -- sleep 3
        
        gum style --foreground 46 "✅ Anomaly detection: Active"
        gum style --foreground 46 "✅ Unusual patterns flagged:"
        gum style --foreground 46 "   • Off-hours transactions"
        gum style --foreground 46 "   • Unusual destinations"
        gum style --foreground 46 "   • High-value anomalies"
        
        DEPLOYED_CONTROLS+=("SWIFT:AnomalyDetection")
        update_security_score 15
    fi
    
    echo
    gum format -- "## SWIFT Alliance Access Hardening"
    
    if gum confirm "Harden SWIFT workstations (whitelist applications)?"; then
        track_mitigation "Malware Execution" "Application whitelisting"
        gum spin --spinner pulse --title "Deploying AppLocker policies..." -- sleep 2
        
        gum style --foreground 46 "✅ Application whitelisting enabled"
        gum style --foreground 46 "✅ Only approved SWIFT software allowed"
        gum style --foreground 46 "✅ PowerShell: Constrained language mode"
        
        DEPLOYED_CONTROLS+=("SWIFT:AppWhitelisting")
        update_security_score 12
    fi
    
    log_action "FINANCIAL SECURITY: SWIFT CSP controls deployed"
    
    gum confirm "Proceed to endpoint detection?" || exit 0
}

# ============================================================================
# PHASE 4: ENDPOINT DETECTION & RESPONSE
# ============================================================================
phase_endpoint_detection() {
    phase_banner 4 "ENDPOINT DETECTION & RESPONSE"
    
    gum format -- "## EDR/XDR Platform Configuration"
    
    TOTAL_ENDPOINTS=$((300 + RANDOM % 700))
    
    gum spin --spinner dot --title "Scanning endpoint inventory..." -- sleep 2
    gum style --foreground 46 "📊 Total endpoints: $TOTAL_ENDPOINTS"
    
    echo
    gum format -- "## Lazarus-Specific Detection Signatures"
    
    if gum confirm "Deploy Lazarus Group IoC database?"; then
        track_detection "T1587.001" "Lazarus malware signatures"
        gum spin --spinner pulse --title "Loading threat intelligence..." -- sleep 3
        
        gum style --foreground 46 "✅ WannaCry/WannaCryptor detection"
        gum style --foreground 46 "✅ Destover wiper signatures"
        gum style --foreground 46 "✅ AppleJeus trojan detection"
        gum style --foreground 46 "✅ PowerRatankba banking trojan"
        gum style --foreground 46 "✅ BLINDINGCAN RAT detection"
        gum style --foreground 46 "✅ Known Lazarus C2 domains blocked"
        
        DEPLOYED_CONTROLS+=("EDR:Lazarus_IoCs")
        update_security_score 15
    fi
    
    echo
    gum format -- "## Behavioral Detection - Wiper Malware"
    
    if gum confirm "Enable destructive malware detection (wiper defense)?"; then
        track_detection "T1485" "Data destruction detection"
        gum spin --spinner pulse --title "Configuring behavioral rules..." -- sleep 2
        
        gum style --foreground 46 "✅ Mass file deletion detection"
        gum style --foreground 46 "✅ MBR modification alerts"
        gum style --foreground 46 "✅ Rapid file overwrite detection"
        gum style --foreground 46 "✅ Automatic process termination"
        
        DEPLOYED_CONTROLS+=("EDR:WiperDetection")
        update_security_score 12
    fi
    
    echo
    gum format -- "## Memory Analysis & Fileless Malware"
    
    if gum confirm "Enable advanced memory scanning?"; then
        track_detection "T1055" "Process injection detection"
        gum spin --spinner pulse --title "Enabling memory analysis..." -- sleep 2
        
        gum style --foreground 46 "✅ In-memory PE detection"
        gum style --foreground 46 "✅ Reflective DLL injection monitoring"
        gum style --foreground 46 "✅ PowerShell script block logging"
        
        DEPLOYED_CONTROLS+=("EDR:MemoryAnalysis")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Execution Prevention"
    
    if gum confirm "Block execution from temp directories?"; then
        track_mitigation "Malware Execution" "Temp directory restrictions"
        gum spin --spinner pulse --title "Configuring execution policies..." -- sleep 2
        
        gum style --foreground 46 "✅ Blocked execution paths:"
        gum style --foreground 46 "   • %TEMP%\\*"
        gum style --foreground 46 "   • %APPDATA%\\*"
        gum style --foreground 46 "   • C:\\Users\\*\\Downloads\\*"
        
        DEPLOYED_CONTROLS+=("Windows:ExecutionRestrictions")
        update_security_score 10
    fi
    
    log_action "ENDPOINT: $TOTAL_ENDPOINTS endpoints protected with Lazarus signatures"
    
    gum confirm "Proceed to network monitoring?" || exit 0
}

# ============================================================================
# PHASE 5: NETWORK SECURITY MONITORING
# ============================================================================
phase_network_monitoring() {
    phase_banner 5 "NETWORK SECURITY MONITORING"
    
    gum format -- "## Network Traffic Analysis"
    
    if gum confirm "Deploy network IDS/IPS (Suricata/Snort)?"; then
        track_detection "T1071.001" "C2 communication detection"
        gum spin --spinner pulse --title "Deploying Suricata with ET rulesets..." -- sleep 3
        
        gum style --foreground 46 "✅ IDS/IPS: Suricata"
        gum style --foreground 46 "✅ Emerging Threats ruleset: Active"
        gum style --foreground 46 "✅ Lazarus C2 signatures: Loaded"
        
        DEPLOYED_CONTROLS+=("Network:IDS_IPS")
        update_security_score 12
    fi
    
    echo
    gum format -- "## WannaCry Kill Switch Domain Monitoring"
    
    if gum confirm "Monitor for WannaCry kill switch domain queries?"; then
        track_detection "WannaCry Activation" "Kill switch monitoring"
        
        KILLSWITCH_DOMAIN="iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
        
        gum spin --spinner pulse --title "Configuring DNS sinkhole..." -- sleep 2
        gum style --foreground 46 "✅ Kill switch domain registered internally"
        gum style --foreground 46 "✅ Domain: $KILLSWITCH_DOMAIN"
        gum style --foreground 46 "✅ If queried → WannaCry presence detected"
        
        DEPLOYED_CONTROLS+=("DNS:WannaCry_Killswitch")
        update_security_score 10
    fi
    
    echo
    gum format -- "## SMB Traffic Monitoring"
    
    if gum confirm "Monitor for EternalBlue exploitation attempts?"; then
        track_detection "T1210" "EternalBlue detection"
        gum spin --spinner pulse --title "Analyzing SMB traffic patterns..." -- sleep 2
        
        gum style --foreground 46 "✅ SMB exploit detection rules deployed"
        gum style --foreground 46 "✅ Lateral movement via SMB: Monitored"
        gum style --foreground 46 "✅ Unusual SMB sessions: Alerted"
        
        DEPLOYED_CONTROLS+=("Network:SMB_Monitoring")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Egress Filtering"
    
    if gum confirm "Implement strict egress filtering (block C2)?"; then
        track_mitigation "C2 Communication" "Egress filtering"
        gum spin --spinner pulse --title "Configuring firewall rules..." -- sleep 2
        
        gum style --foreground 46 "✅ Default deny egress policy"
        gum style --foreground 46 "✅ Whitelist-only outbound"
        gum style --foreground 46 "✅ Known Lazarus C2 IPs: Blocked"
        gum style --foreground 46 "✅ Tor exit nodes: Blocked"
        
        DEPLOYED_CONTROLS+=("Network:EgressFiltering")
        update_security_score 12
    fi
    
    log_action "NETWORK: IDS/IPS and egress filtering deployed"
    
    gum confirm "Proceed to cryptocurrency protection?" || exit 0
}

# ============================================================================
# PHASE 6: CRYPTOCURRENCY SECURITY (if applicable)
# ============================================================================
phase_crypto_security() {
    if [[ "$ORGANIZATION" != *"Crypto"* ]]; then
        gum style --foreground 11 "⏭️  Skipping crypto controls (not applicable to $ORGANIZATION)"
        return
    fi
    
    phase_banner 6 "CRYPTOCURRENCY EXCHANGE SECURITY"
    
    gum format -- "## Hot Wallet Protection"
    
    if gum confirm "Implement hot wallet security controls?"; then
        track_mitigation "Crypto Theft" "Multi-sig hot wallets"
        
        gum spin --spinner pulse --title "Configuring multi-signature wallets..." -- sleep 3
        
        gum style --foreground 46 "✅ Hot wallet: Multi-sig 3-of-5"
        gum style --foreground 46 "✅ Transaction approval: Manual review required"
        gum style --foreground 46 "✅ Daily withdrawal limits: Enforced"
        gum style --foreground 46 "✅ Suspicious transaction alerts: Active"
        
        DEPLOYED_CONTROLS+=("Crypto:HotWallet_MultiSig")
        update_security_score 15
    fi
    
    echo
    gum format -- "## Cold Storage"
    
    if gum confirm "Verify cold storage air-gap and HSM usage?"; then
        gum spin --spinner dot --title "Auditing cold storage..." -- sleep 2
        
        gum style --foreground 46 "✅ Cold storage: 95% of assets"
        gum style --foreground 46 "✅ Air-gapped: Offline signing"
        gum style --foreground 46 "✅ HSM: Thales Luna"
        gum style --foreground 46 "✅ Geographic distribution: 3 locations"
        
        DEPLOYED_CONTROLS+=("Crypto:ColdStorage")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Transaction Monitoring"
    
    if gum confirm "Deploy blockchain analysis and AML monitoring?"; then
        track_detection "Suspicious Transactions" "Blockchain analytics"
        gum spin --spinner pulse --title "Integrating Chainalysis..." -- sleep 2
        
        gum style --foreground 46 "✅ Blockchain analytics: Chainalysis"
        gum style --foreground 46 "✅ Known Lazarus wallets: Flagged"
        gum style --foreground 46 "✅ Mixer/tumbler detection: Active"
        gum style --foreground 46 "✅ AML compliance: Automated"
        
        DEPLOYED_CONTROLS+=("Crypto:BlockchainAnalytics")
        update_security_score 12
    fi
    
    log_action "CRYPTO: Multi-sig wallets and cold storage verified"
    
    gum confirm "Proceed to threat hunting?" || exit 0
}

# ============================================================================
# PHASE 7: PROACTIVE THREAT HUNTING
# ============================================================================
phase_threat_hunting() {
    phase_banner 7 "PROACTIVE THREAT HUNTING"
    
    gum format -- "## Threat Hunt Mission"
    gum format -- "Hypothesis: Lazarus Group may have established persistence or deployed ransomware"
    
    echo
    HUNT_HYPOTHESIS=$(gum choose --header "Select hunting hypothesis:" \
        "Search for WannaCry artifacts" \
        "Hunt for destructive wiper malware" \
        "Detect unauthorized SWIFT access" \
        "Find AppleJeus trojanized applications" \
        "Identify cryptocurrency theft attempts")
    
    gum spin --spinner pulse --title "Executing threat hunt: $HUNT_HYPOTHESIS..." -- sleep 4
    
    echo
    gum format -- "### Hunt Results"
    
    # Simulate findings
    SUSPICIOUS_FINDINGS=$((RANDOM % 6))
    
    if [ $SUSPICIOUS_FINDINGS -gt 0 ]; then
        ((INCIDENTS_DETECTED += SUSPICIOUS_FINDINGS))
        gum style --foreground 196 "🚨 SUSPICIOUS ACTIVITY DETECTED!"
        
        for i in $(seq 1 $SUSPICIOUS_FINDINGS); do
            case $((RANDOM % 5)) in
                0)
                    FINDING="Suspicious executable: @WanaDecryptor@.exe"
                    HOST="WKS-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="WannaCry ransomware"
                    ;;
                1)
                    FINDING="Unauthorized SWIFT message modification attempt"
                    HOST="SWIFT-SRV-01"
                    THREAT="Financial fraud attempt"
                    ;;
                2)
                    FINDING="Mass file deletion pattern detected"
                    HOST="FS-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="Wiper malware (Destover-like)"
                    ;;
                3)
                    FINDING="Connection to known Lazarus C2: trade-$(openssl rand -hex 4).com"
                    HOST="SRV-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="RAT/Backdoor communication"
                    ;;
                4)
                    FINDING="Trojanized crypto trading app: CryptoTrader.exe"
                    HOST="USER-PC-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="AppleJeus trojan"
                    ;;
            esac
            
            DETECTED_THREATS+=("$HOST|$FINDING|$THREAT")
            gum style --foreground 196 "  ⚠️  $HOST: $FINDING"
            log_action "THREAT DETECTED: $HOST - $FINDING ($THREAT)"
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
    
    log_action "THREAT HUNT: Complete - $SUSPICIOUS_FINDINGS findings"
    
    if [ $SUSPICIOUS_FINDINGS -eq 0 ]; then
        gum confirm "Proceed to incident response readiness?" || exit 0
    fi
}

# ============================================================================
# PHASE 8: INCIDENT RESPONSE (IF THREATS DETECTED)
# ============================================================================
phase_incident_response() {
    phase_banner 8 "INCIDENT RESPONSE - LAZARUS GROUP COMPROMISE"
    
    gum format -- "## Active Incident: Lazarus Group Activity Detected"
    gum style --foreground 196 --bold "🚨 SECURITY INCIDENT IN PROGRESS"
    
    echo
    gum format -- "### Detected Threats"
    for threat in "${DETECTED_THREATS[@]}"; do
        IFS='|' read -r host finding threat_type <<< "$threat"
        gum style --foreground 196 "  🎯 $host: $finding"
        gum style --foreground 11 "     Threat: $threat_type"
    done
    
    echo
    IR_LEAD=$(gum input --placeholder "Incident Response lead name" --value "CIRT Lead $(whoami)")
    INCIDENT_ID="INC-LAZARUS-$(date +%Y%m%d)-$((1000 + RANDOM % 9000))"
    
    log_action "INCIDENT DECLARED: $INCIDENT_ID by $IR_LEAD"
    
    gum style --foreground 11 "📋 Incident ID: $INCIDENT_ID"
    gum style --foreground 11 "👤 IR Lead: $IR_LEAD"
    gum style --foreground 11 "🎯 Threat Actor: Lazarus Group (HIDDEN COBRA / APT38)"
    
    echo
    gum format -- "## Containment Actions"
    
    # Check for ransomware
    RANSOMWARE_DETECTED=false
    for threat in "${DETECTED_THREATS[@]}"; do
        if [[ "$threat" == *"WannaCry"* ]] || [[ "$threat" == *"ransomware"* ]]; then
            RANSOMWARE_DETECTED=true
            break
        fi
    done
    
    if [ "$RANSOMWARE_DETECTED" = true ]; then
        gum style --foreground 196 --bold "🔒 RANSOMWARE DETECTED - EMERGENCY RESPONSE"
        
        if gum confirm "Isolate entire network segment (prevent worm spread)?"; then
            gum spin --spinner pulse --title "Disabling inter-VLAN routing..." -- sleep 2
            gum style --foreground 46 "✅ Network segments isolated"
            gum style --foreground 46 "✅ SMB ports blocked at firewall"
            ((INCIDENTS_CONTAINED++))
            update_security_score 15
        fi
        
        echo
        if gum confirm "Kill all SMB services (stop EternalBlue propagation)?"; then
            gum spin --spinner pulse --title "Stop-Service LanmanServer..." -- sleep 2
            gum style --foreground 46 "✅ SMB services stopped on all hosts"
            ((INCIDENTS_CONTAINED++))
        fi
    fi
    
    echo
    # Isolate compromised systems
    if gum confirm "Isolate all affected systems from network?"; then
        for threat in "${DETECTED_THREATS[@]}"; do
            IFS='|' read -r host finding threat_type <<< "$threat"
            
            gum spin --spinner pulse --title "Isolating $host via EDR..." -- sleep 1
            gum style --foreground 46 "✅ $host isolated (network quarantine)"
            BLOCKED_ATTACKS+=("$host|Network isolation")
            ((INCIDENTS_CONTAINED++))
        done
        update_security_score 10
    fi
    
    echo
    # SWIFT-specific containment
    if [[ "$ORGANIZATION" == *"Financial"* ]]; then
        if gum confirm "Lock down SWIFT environment (freeze transactions)?"; then
            gum spin --spinner pulse --title "Disabling SWIFT Alliance Access..." -- sleep 3
            gum style --foreground 46 "✅ SWIFT transactions: FROZEN"
            gum style --foreground 46 "✅ All SWIFT operators: Logged out"
            gum style --foreground 46 "✅ Pending transactions: Quarantined for review"
            ((INCIDENTS_CONTAINED++))
            update_security_score 15
        fi
    fi
    
    echo
    gum format -- "## Eradication"
    
    if gum confirm "Remove malware and backdoors?"; then
        gum spin --spinner pulse --title "Scanning for Lazarus malware..." -- sleep 3
        
        gum style --foreground 46 "✅ WannaCry ransomware: Quarantined"
        gum style --foreground 46 "✅ Backdoors: Removed"
        gum style --foreground 46 "✅ Wiper malware: Neutralized"
        gum style --foreground 46 "✅ C2 connections: Terminated"
        
        if gum confirm "Re-image compromised systems from golden image?"; then
            gum spin --spinner pulse --title "Deploying clean OS images..." -- sleep 4
            gum style --foreground 46 "✅ Systems rebuilt from trusted baseline"
            update_security_score 15
        fi
    fi
    
    echo
    # Ransomware recovery
    if [ "$RANSOMWARE_DETECTED" = true ]; then
        if gum confirm "Restore from backups (ransomware recovery)?"; then
            gum spin --spinner pulse --title "Restoring from last clean backup..." -- sleep 5
            
            FILES_RESTORED=$((10000 + RANDOM % 50000))
            gum style --foreground 46 --bold "✅ BACKUP RESTORATION COMPLETE"
            gum style --foreground 46 "📁 Files restored: $FILES_RESTORED"
            gum style --foreground 46 "📅 Restore point: $(date -d '1 day ago' '+%Y-%m-%d %H:%M')"
            gum style --foreground 46 "💰 Ransom payment: NOT PAID (recovery successful)"
            
            update_security_score 20
        fi
    fi
    
    echo
    gum format -- "## Forensic Collection"
    
    if gum confirm "Collect forensic artifacts?"; then
        gum spin --spinner pulse --title "Collecting evidence..." -- sleep 3
        gum style --foreground 46 "✅ Memory dumps collected"
        gum style --foreground 46 "✅ Disk images acquired"
        gum style --foreground 46 "✅ Event logs preserved"
        gum style --foreground 46 "✅ Network PCAPs saved"
        gum style --foreground 46 "✅ Malware samples submitted to CISA"
    fi
    
    echo
    gum format -- "## Recovery"
    
    if gum confirm "Restore services with enhanced monitoring?"; then
        gum spin --spinner pulse --title "Restoring operations..." -- sleep 3
        gum style --foreground 46 "✅ Systems restored to production"
        gum style --foreground 46 "✅ Enhanced logging: Deployed"
        gum style --foreground 46 "✅ Continuous monitoring: 24/7 SOC"
        gum style --foreground 46 "✅ Threat hunt cadence: Daily for 30 days"
    fi
    
    log_action "INCIDENT $INCIDENT_ID: Contained ($INCIDENTS_CONTAINED actions) and eradicated"
    
    gum confirm "Continue to post-incident hardening?" || exit 0
}

# ============================================================================
# PHASE 9: POST-INCIDENT HARDENING
# ============================================================================
phase_post_incident() {
    phase_banner 9 "POST-INCIDENT HARDENING"
    
    gum format -- "## Enhanced Security Posture"
    
    if gum confirm "Deploy additional preventive controls?"; then
        
        # Privileged Access Management
        if gum confirm "Implement Privileged Access Management (PAM)?"; then
            track_mitigation "Credential Theft" "PAM solution"
            gum spin --spinner pulse --title "Deploying CyberArk PAM..." -- sleep 3
            gum style --foreground 46 "✅ PAM: Admin credentials vaulted"
            gum style --foreground 46 "✅ Just-in-time access: Enabled"
            gum style --foreground 46 "✅ Session recording: Active"
            DEPLOYED_CONTROLS+=("IAM:PAM")
            update_security_score 15
        fi
        
        echo
        # Deception technology
        if gum confirm "Deploy honeypots and canary tokens?"; then
            track_detection "Lateral Movement" "Deception technology"
            gum spin --spinner pulse --title "Deploying deception layer..." -- sleep 2
            gum style --foreground 46 "✅ Honeypot servers: 5 deployed"
            gum style --foreground 46 "✅ Canary files: Distributed"
            gum style --foreground 46 "✅ Fake SWIFT credentials: Planted"
            DEPLOYED_CONTROLS+=("Deception:Honeypots")
            update_security_score 10
        fi
        
        echo
        # Threat intelligence sharing
        if gum confirm "Share IoCs with CISA and FS-ISAC?"; then
            gum spin --spinner pulse --title "Submitting threat intelligence..." -- sleep 2
            gum style --foreground 46 "✅ IoCs shared with CISA"
            gum style --foreground 46 "✅ FS-ISAC notification sent"
            gum style --foreground 46 "✅ Industry threat briefing published"
        fi
    fi
    
    log_action "POST-INCIDENT: Enhanced controls deployed"
    
    gum confirm "Proceed to final assessment?" || exit 0
}

# ============================================================================
# PHASE 10: RED TEAM VALIDATION
# ============================================================================
phase_red_team_validation() {
    phase_banner 10 "RED TEAM VALIDATION"
    
    gum format -- "## Purple Team Exercise"
    gum format -- "Simulate Lazarus Group attack to test defenses"
    
    echo
    if gum confirm "Authorize Lazarus-style red team engagement?"; then
        
        SCOPE=$(gum choose --no-limit --header "Red team scope:" \
            "WannaCry ransomware simulation" \
            "SWIFT fraud scenario" \
            "Destructive wiper test" \
            "Cryptocurrency theft attempt")
        
        gum spin --spinner pulse --title "Red team executing Lazarus TTPs..." -- sleep 5
        
        gum format -- "### Red Team Results"
        
        DETECTION_RATE=$((55 + (SECURITY_SCORE / 3) + RANDOM % 15))
        if [ $DETECTION_RATE -gt 100 ]; then
            DETECTION_RATE=100
        fi
        
        DWELL_TIME=$((40 - (SECURITY_SCORE / 4)))
        if [ $DWELL_TIME -lt 1 ]; then
            DWELL_TIME=1
        fi
        
        gum style --foreground 46 "📊 Detection Rate: ${DETECTION_RATE}%"
        gum style --foreground 11 "⏱️  Mean Time to Detect: ${DWELL_TIME} hours"
        gum style --foreground 11 "🔒 Ransomware Prevention: $([ $DETECTION_RATE -gt 75 ] && echo "STRONG" || echo "GAPS EXIST")"
        gum style --foreground 11 "💰 Financial Fraud Prevention: $([ $DETECTION_RATE -gt 80 ] && echo "EFFECTIVE" || echo "NEEDS WORK")"
        
        if [ $DETECTION_RATE -ge 85 ]; then
            gum style --foreground 46 "✅ EXCELLENT: Strong Lazarus defense posture"
            update_security_score 20
        elif [ $DETECTION_RATE -ge 70 ]; then
            gum style --foreground 11 "⚠️  GOOD: Some gaps remain"
            update_security_score 10
        else
            gum style --foreground 196 "❌ CRITICAL GAPS: Lazarus could succeed"
            update_security_score -5
        fi
        
        echo
        gum format -- "### Identified Gaps"
        gum style --foreground 11 "  - EternalBlue patching incomplete on legacy systems"
        gum style --foreground 11 "  - SWIFT transaction monitoring needs tuning"
        gum style --foreground 46 "  + Ransomware detected and contained quickly"
        gum style --foreground 46 "  + Backup restoration successful"
        
        if gum confirm "Conduct purple team debrief?"; then
            gum style --foreground 46 "✅ Purple team session complete"
            gum style --foreground 46 "✅ Detection rules tuned based on findings"
            update_security_score 10
        fi
    fi
    
    log_action "RED TEAM: Validation complete - ${DETECTION_RATE}% detection"
    
    gum confirm "Generate final report?" || exit 0
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
        "🛡️  DEFENSE MISSION COMPLETE" \
        "Lazarus Group Defense Assessment"
    
    echo
    gum format -- "## Defense Posture Summary"
    
    # Overall assessment
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
    echo "┌────────────────────────────────────────┬──────────────────────┐"
    echo "│ Metric                                 │ Value                │"
    echo "├────────────────────────────────────────┼──────────────────────┤"
    printf "│ %-38s │ %-20s │\n" "Mission Duration" "${duration_min} minutes"
    printf "│ %-38s │ %-20s │\n" "Security Score" "$SECURITY_SCORE/100"
    printf "│ %-38s │ %-20s │\n" "Threat Level" "$THREAT_LEVEL"
    printf "│ %-38s │ %-20s │\n" "Ransomware Risk" "$RANSOMWARE_RISK"
    printf "│ %-38s │ %-20s │\n" "Financial Risk" "$FINANCIAL_RISK"
    printf "│ %-38s │ %-20s │\n" "Deployed Controls" "${#DEPLOYED_CONTROLS[@]}"
    printf "│ %-38s │ %-20s │\n" "Detection Rules" "${#DETECTION_RULES[@]}"
    printf "│ %-38s │ %-20s │\n" "Incidents Detected" "$INCIDENTS_DETECTED"
    printf "│ %-38s │ %-20s │\n" "Incidents Contained" "$INCIDENTS_CONTAINED"
    echo "└────────────────────────────────────────┴──────────────────────┘"
    
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
    gum format -- "## Detection Coverage (Lazarus TTPs)"
    
    if [ ${#DETECTION_RULES[@]} -gt 0 ]; then
        for technique in "${!DETECTION_RULES[@]}"; do
            echo "  🔍 $technique: ${DETECTION_RULES[$technique]}"
        done
    fi
    
    echo
    gum format -- "## Threat Detections"
    
    if [ ${#DETECTED_THREATS[@]} -gt 0 ]; then
        for threat in "${DETECTED_THREATS[@]}"; do
            IFS='|' read -r host finding threat_type <<< "$threat"
            gum style --foreground 196 "  🚨 $host: $finding ($threat_type)"
        done
    else
        gum style --foreground 46 "  ✅ No threats detected - Clean environment"
    fi
    
    echo
    gum format -- "## Key Recommendations"
    
    if [ $SECURITY_SCORE -lt 70 ]; then
        gum style --foreground 196 "### Critical Actions Required"
        echo "  1. URGENT: Patch MS17-010 (EternalBlue) on all systems"
        echo "  2. Deploy anti-ransomware EDR solution"
        echo "  3. Implement immutable backups with offline copies"
        echo "  4. Harden SWIFT environment (CSP compliance)"
        echo "  5. Deploy network segmentation to prevent worm spread"
    elif [ $SECURITY_SCORE -lt 85 ]; then
        gum style --foreground 11 "### Recommended Enhancements"
        echo "  1. Enhance backup testing and recovery procedures"
        echo "  2. Deploy deception technology (honeypots)"
        echo "  3. Implement PAM for privileged access control"
        echo "  4. Conduct regular purple team exercises"
    else
        gum style --foreground 46 "### Maintain and Enhance"
        echo "  1. Continue proactive threat hunting for Lazarus IoCs"
        echo "  2. Maintain MS17-010 patch compliance"
        echo "  3. Regular backup restoration testing"
        echo "  4. Quarterly red team ransomware simulations"
    fi
    
    echo
    gum style --foreground 240 "Detailed log: $LOG_FILE"
    
    echo
    if gum confirm "Generate formal assessment report?"; then
        REPORT_FILE="/tmp/lazarus-defense-report-$(date +%Y%m%d-%H%M%S).txt"
        {
            echo "============================================"
            echo "LAZARUS GROUP DEFENSE ASSESSMENT"
            echo "Ransomware & Financial Crime Prevention"
            echo "Generated: $(date)"
            echo "============================================"
            echo
            echo "EXECUTIVE SUMMARY:"
            echo "  Organization: $ORGANIZATION"
            echo "  Security Grade: $grade"
            echo "  Security Score: $SECURITY_SCORE/100"
            echo "  Ransomware Risk: $RANSOMWARE_RISK"
            echo "  Financial Risk: $FINANCIAL_RISK"
            echo "  Threat Level: $THREAT_LEVEL"
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
            echo
            echo "RISK ASSESSMENT:"
            if [ $SECURITY_SCORE -lt 70 ]; then
                echo "  Level: HIGH"
                echo "  Organization vulnerable to Lazarus ransomware and financial attacks."
                echo "  Immediate patching and backup hardening required."
            elif [ $SECURITY_SCORE -lt 85 ]; then
                echo "  Level: MODERATE"
                echo "  Baseline defenses present, continue enhancement."
            else
                echo "  Level: LOW"
                echo "  Strong defense against Lazarus TTPs."
                echo "  Maintain vigilance and continuous improvement."
            fi
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
    phase_vulnerability_management
    phase_ransomware_defense
    phase_financial_security
    phase_endpoint_detection
    phase_network_monitoring
    phase_crypto_security
    phase_threat_hunting
    
    # Conditional incident response
    if [ $INCIDENTS_DETECTED -gt 0 ]; then
        phase_incident_response
        phase_post_incident
    fi
    
    phase_red_team_validation
    
    generate_report
    
    echo
    if [ $SECURITY_SCORE -ge 85 ]; then
        gum style --foreground 46 --bold "🛡️  Defense mission successful. Organization secured against Lazarus."
    else
        gum style --foreground 11 --bold "⚠️  Defense gaps identified. Continue hardening operations."
    fi
}

# Run main
main
