#!/bin/bash
# ============================================================================
# BLUE TEAM: APT41 (WINNTI / DOUBLE DRAGON) DEFENSE SIMULATOR
# ============================================================================
# Defending against Chinese dual-purpose APT: Rootkits, supply chain, gaming
# Focus: Rootkit detection, code signing validation, supply chain security
# ============================================================================

set -euo pipefail
trap cleanup INT TERM

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
VERSION="1.0"
LOG_FILE="/tmp/blueteam-apt41-$(date +%Y%m%d-%H%M%S).log"
INCIDENT_FILE="/tmp/apt41-incidents-$(date +%Y%m%d-%H%M%S).json"
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
ROOTKIT_RISK="HIGH"
SUPPLY_CHAIN_RISK="HIGH"

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
        ROOTKIT_RISK="LOW"
        SUPPLY_CHAIN_RISK="LOW"
    elif [ $SECURITY_SCORE -ge 70 ]; then
        THREAT_LEVEL="GUARDED"
        ROOTKIT_RISK="MODERATE"
        SUPPLY_CHAIN_RISK="MODERATE"
    elif [ $SECURITY_SCORE -ge 50 ]; then
        THREAT_LEVEL="ELEVATED"
        ROOTKIT_RISK="ELEVATED"
        SUPPLY_CHAIN_RISK="ELEVATED"
    elif [ $SECURITY_SCORE -ge 30 ]; then
        THREAT_LEVEL="HIGH"
        ROOTKIT_RISK="HIGH"
        SUPPLY_CHAIN_RISK="HIGH"
    else
        THREAT_LEVEL="SEVERE"
        ROOTKIT_RISK="CRITICAL"
        SUPPLY_CHAIN_RISK="CRITICAL"
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
    
    gum style --foreground $color "🛡️  Threat: $THREAT_LEVEL | Rootkit: $ROOTKIT_RISK | Supply Chain: $SUPPLY_CHAIN_RISK | Score: $SECURITY_SCORE/100"
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
        "Defending Against APT41 (Winnti / Double Dragon)" \
        "" \
        "Rootkit & Supply Chain Defense v${VERSION}"
    
    echo
    
    gum format -- "# Mission Parameters"
    gum format -- "**Adversary**: APT41 (Winnti, Double Dragon, Wicked Panda, Barium)"
    gum format -- "**Attribution**: MSS Contractor - Chengdu 404, Axiom"
    gum format -- "**MITRE Group**: G0096"
    gum format -- "**Threat Focus**: Winnti rootkits, supply chain attacks, dual operations (espionage + crime)"
    gum format -- "**Your Role**: Chief Information Security Officer & Threat Hunter"
    gum format -- "**Objective**: Detect rootkits, secure supply chain, prevent data theft"
    
    echo
    
    ORGANIZATION=$(gum choose --header "Select your organization type:" \
        "Technology Company (Software development)" \
        "Gaming Industry (Virtual currency target)" \
        "Healthcare Organization (Research IP)" \
        "Pharmaceutical Company (Drug R&D)" \
        "Telecommunications Provider" \
        "Financial Institution")
    
    log_action "=== BLUE TEAM APT41 DEFENSE START ==="
    log_action "Organization: $ORGANIZATION"
    
    echo
    gum format -- "## Intelligence Brief"
    gum style --foreground 196 "🚨 CRITICAL: APT41 (Winnti) activity targeting $ORGANIZATION sector"
    gum style --foreground 11 "📊 Known TTPs: Winnti rootkits, code signing abuse, supply chain"
    gum style --foreground 11 "🎯 Targets: Intellectual property, source code, gaming assets, PII"
    gum style --foreground 11 "⚠️  Unique: Dual-purpose operations (state + financial cybercrime)"
    
    echo
    if ! gum confirm "Begin defensive operations?"; then
        echo "Mission cancelled"
        exit 0
    fi
}

# ============================================================================
# PHASE 1: ROOTKIT DETECTION & DEFENSE
# ============================================================================
phase_rootkit_detection() {
    phase_banner 1 "ROOTKIT DETECTION - WINNTI DEFENSE"
    
    gum format -- "## Kernel-Mode Rootkit Detection"
    gum format -- "### Winnti Rootkit Characteristics"
    gum style --foreground 11 "⚠️  APT41 uses sophisticated kernel-mode rootkits (Winnti malware family)"
    gum style --foreground 11 "⚠️  Capabilities: Process hiding, file hiding, network concealment"
    
    echo
    # Driver signature verification
    if gum confirm "Enable driver signature enforcement (block unsigned drivers)?"; then
        track_mitigation "Rootkit Installation" "Driver signature enforcement"
        gum spin --spinner pulse --title "bcdedit /set testsigning off..." -- sleep 2
        gum style --foreground 46 "✅ Driver signature enforcement: ENABLED"
        gum style --foreground 46 "✅ Secure Boot: Verified active"
        gum style --foreground 46 "✅ Unsigned drivers: BLOCKED"
        DEPLOYED_CONTROLS+=("Windows:DriverSignatureEnforcement")
        update_security_score 15
    fi
    
    echo
    gum format -- "### Kernel Integrity Monitoring"
    
    if gum confirm "Deploy kernel integrity checking (GMER, PCHunter)?"; then
        track_detection "T1014" "Rootkit detection tools"
        gum spin --spinner pulse --title "Scanning kernel structures for anomalies..." -- sleep 4
        
        SUSPICIOUS_DRIVERS=$((RANDOM % 3))
        
        if [ $SUSPICIOUS_DRIVERS -gt 0 ]; then
            ((INCIDENTS_DETECTED += SUSPICIOUS_DRIVERS))
            gum style --foreground 196 --bold "🚨 SUSPICIOUS KERNEL DRIVERS DETECTED!"
            
            for i in $(seq 1 $SUSPICIOUS_DRIVERS); do
                DRIVER_NAME="WinntiBios$(printf '%02d' $((RANDOM % 99))).sys"
                FINDING="Unsigned kernel driver: $DRIVER_NAME"
                DETECTED_THREATS+=("KERNEL|$FINDING|Winnti Rootkit")
                gum style --foreground 196 "  ⚠️  $DRIVER_NAME: Hidden driver (rootkit signature)"
            done
            
            log_action "ROOTKIT DETECTED: $SUSPICIOUS_DRIVERS suspicious drivers"
        else
            gum style --foreground 46 "✅ No suspicious kernel drivers detected"
            update_security_score 10
        fi
        
        DEPLOYED_CONTROLS+=("Rootkit:KernelIntegrityCheck")
        update_security_score 15
    fi
    
    echo
    gum format -- "### BYOVD (Bring Your Own Vulnerable Driver) Defense"
    
    if gum confirm "Block known vulnerable drivers exploited by APT41?"; then
        track_mitigation "BYOVD Exploitation" "Vulnerable driver blocklist"
        gum spin --spinner pulse --title "Deploying vulnerable driver blocklist..." -- sleep 2
        
        gum style --foreground 46 "✅ Vulnerable drivers blocked:"
        gum style --foreground 46 "   • Capcom.sys (CVE-2016-5728)"
        gum style --foreground 46 "   • RTCore64.sys"
        gum style --foreground 46 "   • DBUtil_2_3.sys"
        gum style --foreground 46 "   • 50+ additional vulnerable drivers"
        
        DEPLOYED_CONTROLS+=("Windows:VulnerableDriverBlocklist")
        update_security_score 12
    fi
    
    echo
    gum format -- "### Memory Analysis"
    
    if gum confirm "Enable advanced memory scanning (Volatility-style analysis)?"; then
        track_detection "Hidden Processes" "Memory forensics"
        gum spin --spinner pulse --title "Analyzing process memory for anomalies..." -- sleep 3
        
        gum style --foreground 46 "✅ Memory analysis tools deployed"
        gum style --foreground 46 "✅ Hidden process detection: Active"
        gum style --foreground 46 "✅ DKOM (Direct Kernel Object Manipulation) detection"
        
        DEPLOYED_CONTROLS+=("Rootkit:MemoryAnalysis")
        update_security_score 10
    fi
    
    log_action "ROOTKIT DEFENSE: ${#DEPLOYED_CONTROLS[@]} controls deployed"
    
    gum confirm "Proceed to code signing validation?" || exit 0
}

# ============================================================================
# PHASE 2: CODE SIGNING VALIDATION
# ============================================================================
phase_code_signing() {
    phase_banner 2 "CODE SIGNING VALIDATION - CERTIFICATE ABUSE DEFENSE"
    
    gum format -- "## APT41 Code Signing Certificate Abuse"
    gum style --foreground 11 "⚠️  APT41 frequently uses stolen/forged code signing certificates"
    gum style --foreground 11 "⚠️  Malware appears legitimate to Windows Defender and users"
    
    echo
    gum format -- "### Certificate Transparency Monitoring"
    
    if gum confirm "Monitor certificate transparency logs for org certificates?"; then
        track_detection "T1588.003" "Certificate transparency monitoring"
        gum spin --spinner pulse --title "Querying crt.sh and CT logs..." -- sleep 3
        
        gum style --foreground 46 "✅ Certificate monitoring active"
        gum style --foreground 46 "✅ Alerts on unauthorized certificate issuance"
        gum style --foreground 46 "✅ Daily CT log review scheduled"
        
        DEPLOYED_CONTROLS+=("PKI:CertificateTransparency")
        update_security_score 10
    fi
    
    echo
    gum format -- "### Code Signature Verification"
    
    if gum confirm "Enforce strict code signature validation on all executables?"; then
        track_mitigation "Signed Malware" "Enhanced signature validation"
        gum spin --spinner pulse --title "Configuring AppLocker with certificate rules..." -- sleep 2
        
        gum style --foreground 46 "✅ AppLocker: Publisher rules enforced"
        gum style --foreground 46 "✅ Only trusted CAs accepted"
        gum style --foreground 46 "✅ Certificate revocation checking: MANDATORY"
        gum style --foreground 46 "✅ Expired certificates: REJECTED"
        
        DEPLOYED_CONTROLS+=("Windows:StrictCodeSigning")
        update_security_score 15
    fi
    
    echo
    gum format -- "### Stolen Certificate Detection"
    
    if gum confirm "Scan for known stolen/revoked certificates used by APT41?"; then
        track_detection "Stolen Certificates" "Certificate reputation database"
        gum spin --spinner pulse --title "Checking against APT41 certificate IoCs..." -- sleep 2
        
        SUSPICIOUS_CERTS=$((RANDOM % 2))
        
        if [ $SUSPICIOUS_CERTS -gt 0 ]; then
            ((INCIDENTS_DETECTED++))
            gum style --foreground 196 --bold "🚨 STOLEN CERTIFICATE DETECTED IN USE!"
            
            CERT_SUBJECT="Legitimate Software Company Ltd."
            CERT_SERIAL="7E $(openssl rand -hex 8)"
            
            DETECTED_THREATS+=("CODE_SIGNING|Certificate: $CERT_SUBJECT (Serial: $CERT_SERIAL)|Stolen cert - APT41")
            gum style --foreground 196 "  ⚠️  Certificate: $CERT_SUBJECT"
            gum style --foreground 196 "  ⚠️  Serial: $CERT_SERIAL"
            gum style --foreground 196 "  ⚠️  Status: REVOKED (known APT41 stolen cert)"
            
            log_action "STOLEN CERT DETECTED: $CERT_SUBJECT"
        else
            gum style --foreground 46 "✅ No stolen certificates detected"
            update_security_score 8
        fi
        
        DEPLOYED_CONTROLS+=("PKI:StolenCertDetection")
    fi
    
    echo
    gum format -- "### Certificate Pinning"
    
    if gum confirm "Implement certificate pinning for critical applications?"; then
        track_mitigation "Certificate Forgery" "Certificate pinning"
        gum spin --spinner pulse --title "Configuring certificate pinning..." -- sleep 2
        
        gum style --foreground 46 "✅ Internal applications: Certificate pinning enabled"
        gum style --foreground 46 "✅ Only org-issued certificates accepted"
        
        DEPLOYED_CONTROLS+=("PKI:CertificatePinning")
        update_security_score 10
    fi
    
    log_action "CODE SIGNING: Certificate validation controls deployed"
    
    gum confirm "Proceed to supply chain security?" || exit 0
}

# ============================================================================
# PHASE 3: SUPPLY CHAIN SECURITY
# ============================================================================
phase_supply_chain() {
    phase_banner 3 "SUPPLY CHAIN SECURITY - TROJANIZED SOFTWARE DEFENSE"
    
    gum format -- "## Software Supply Chain Protection"
    gum style --foreground 11 "⚠️  APT41 is known for supply chain attacks (CCleaner-style)"
    gum style --foreground 11 "⚠️  Targets: Software vendors, build systems, update mechanisms"
    
    echo
    gum format -- "### Software Bill of Materials (SBOM)"
    
    if gum confirm "Generate and maintain SBOM for all software?"; then
        track_mitigation "Supply Chain Compromise" "SBOM generation"
        gum spin --spinner pulse --title "Generating SBOM for installed software..." -- sleep 3
        
        SOFTWARE_COUNT=$((100 + RANDOM % 200))
        DEPENDENCIES=$((SOFTWARE_COUNT * 20))
        
        gum style --foreground 46 "✅ SBOM generated"
        gum style --foreground 46 "   Tracked software: $SOFTWARE_COUNT packages"
        gum style --foreground 46 "   Dependencies: $DEPENDENCIES components"
        gum style --foreground 46 "✅ Baseline established for change detection"
        
        DEPLOYED_CONTROLS+=("SupplyChain:SBOM")
        update_security_score 12
    fi
    
    echo
    gum format -- "### Update Mechanism Integrity"
    
    if gum confirm "Verify integrity of software update mechanisms?"; then
        track_mitigation "Trojanized Updates" "Update integrity validation"
        gum spin --spinner pulse --title "Auditing update channels..." -- sleep 2
        
        gum style --foreground 46 "✅ Update verification:"
        gum style --foreground 46 "   • HTTPS-only update channels"
        gum style --foreground 46 "   • Cryptographic signature validation"
        gum style --foreground 46 "   • Hash verification (SHA-256)"
        gum style --foreground 46 "   • Vendor certificate pinning"
        
        DEPLOYED_CONTROLS+=("SupplyChain:UpdateIntegrity")
        update_security_score 15
    fi
    
    echo
    gum format -- "### Build Environment Security"
    
    if [[ "$ORGANIZATION" == *"Technology"* ]] || [[ "$ORGANIZATION" == *"Gaming"* ]]; then
        if gum confirm "Harden software build/compilation environment?"; then
            track_mitigation "Build System Compromise" "Secure build pipeline"
            gum spin --spinner pulse --title "Hardening CI/CD pipeline..." -- sleep 3
            
            gum style --foreground 46 "✅ Build environment hardening:"
            gum style --foreground 46 "   • Build servers: Air-gapped from internet"
            gum style --foreground 46 "   • Code signing: Automated in HSM"
            gum style --foreground 46 "   • Build integrity: Reproducible builds"
            gum style --foreground 46 "   • Access control: MFA + privileged access"
            
            DEPLOYED_CONTROLS+=("SupplyChain:SecureBuild")
            update_security_score 15
        fi
    fi
    
    echo
    gum format -- "### Third-Party Software Vetting"
    
    if gum confirm "Implement vendor security assessment program?"; then
        track_mitigation "Third-Party Risk" "Vendor assessment"
        gum spin --spinner pulse --title "Deploying vendor security program..." -- sleep 2
        
        gum style --foreground 46 "✅ Vendor security requirements:"
        gum style --foreground 46 "   • Security questionnaires mandatory"
        gum style --foreground 46 "   • Code review for critical software"
        gum style --foreground 46 "   • Vulnerability disclosure SLAs"
        gum style --foreground 46 "   • Incident notification requirements"
        
        DEPLOYED_CONTROLS+=("SupplyChain:VendorAssessment")
        update_security_score 10
    fi
    
    log_action "SUPPLY CHAIN: ${#DEPLOYED_CONTROLS[@]} controls deployed"
    
    gum confirm "Proceed to endpoint detection?" || exit 0
}

# ============================================================================
# PHASE 4: ENDPOINT DETECTION & RESPONSE
# ============================================================================
phase_endpoint_detection() {
    phase_banner 4 "ENDPOINT DETECTION & RESPONSE - APT41 SIGNATURES"
    
    gum format -- "## EDR/XDR Deployment"
    
    TOTAL_ENDPOINTS=$((300 + RANDOM % 700))
    
    EDR_SOLUTION=$(gum choose --header "Deploy/enhance EDR platform:" \
        "CrowdStrike Falcon (Behavioral AI)" \
        "Microsoft Defender for Endpoint" \
        "SentinelOne (Autonomous response)" \
        "Carbon Black (Threat hunting)")
    
    if [[ "$EDR_SOLUTION" != *"None"* ]]; then
        track_mitigation "Malware Execution" "$EDR_SOLUTION"
        gum spin --spinner pulse --title "Deploying $EDR_SOLUTION to $TOTAL_ENDPOINTS endpoints..." -- sleep 4
        
        gum style --foreground 46 "✅ EDR coverage: $TOTAL_ENDPOINTS/$TOTAL_ENDPOINTS (100%)"
        gum style --foreground 46 "✅ Agent version: Latest"
        gum style --foreground 46 "✅ Cloud-connected: Real-time threat intelligence"
        
        DEPLOYED_CONTROLS+=("EDR:$EDR_SOLUTION")
        update_security_score 15
    fi
    
    echo
    gum format -- "## APT41/Winnti-Specific Detection Signatures"
    
    if gum confirm "Deploy APT41/Winnti IoC database and YARA rules?"; then
        track_detection "T1587.001" "APT41 malware signatures"
        gum spin --spinner pulse --title "Loading APT41 threat intelligence..." -- sleep 3
        
        gum style --foreground 46 "✅ Winnti malware family detection"
        gum style --foreground 46 "✅ KEYPLUG backdoor signatures"
        gum style --foreground 46 "✅ DEADEYE dropper detection"
        gum style --foreground 46 "✅ MESSAGETAP (telecom-specific)"
        gum style --foreground 46 "✅ HIGHNOON RAT detection"
        gum style --foreground 46 "✅ Known APT41 C2 domains blocked"
        
        DEPLOYED_CONTROLS+=("EDR:APT41_Signatures")
        update_security_score 15
    fi
    
    echo
    gum format -- "## Rootkit-Specific Detection"
    
    if gum confirm "Enable kernel-mode monitoring and rootkit detection?"; then
        track_detection "T1014" "Kernel-mode monitoring"
        gum spin --spinner pulse --title "Enabling kernel callbacks and driver monitoring..." -- sleep 2
        
        gum style --foreground 46 "✅ Kernel-mode telemetry: Enabled"
        gum style --foreground 46 "✅ Driver load monitoring: Active"
        gum style --foreground 46 "✅ SSDT hook detection: Enabled"
        gum style --foreground 46 "✅ Hidden process detection: Active"
        
        DEPLOYED_CONTROLS+=("EDR:RootkitDetection")
        update_security_score 12
    fi
    
    echo
    gum format -- "## DLL Side-Loading Detection"
    
    if gum confirm "Monitor for DLL side-loading (APT41 persistence technique)?"; then
        track_detection "T1574.002" "DLL side-loading detection"
        gum spin --spinner pulse --title "Configuring DLL load monitoring..." -- sleep 2
        
        gum style --foreground 46 "✅ DLL load order monitoring"
        gum style --foreground 46 "✅ Suspicious DLL placement detection"
        gum style --foreground 46 "✅ High-risk applications monitored:"
        gum style --foreground 46 "   • VMware Tools"
        gum style --foreground 46 "   • Microsoft Defender utilities"
        gum style --foreground 46 "   • Google Update services"
        
        DEPLOYED_CONTROLS+=("EDR:DLL_SideLoading")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Behavioral Detection"
    
    if gum confirm "Enable behavioral analysis (fileless attacks, living-off-the-land)?"; then
        track_detection "T1620" "Behavioral analytics"
        gum spin --spinner pulse --title "Training behavioral models..." -- sleep 3
        
        gum style --foreground 46 "✅ PowerShell obfuscation detection"
        gum style --foreground 46 "✅ WMI abuse detection"
        gum style --foreground 46 "✅ LOLBin (Living-off-the-land) monitoring"
        gum style --foreground 46 "✅ Reflective DLL injection detection"
        
        DEPLOYED_CONTROLS+=("EDR:BehavioralAnalysis")
        update_security_score 12
    fi
    
    log_action "ENDPOINT: $TOTAL_ENDPOINTS endpoints with APT41 signatures"
    
    gum confirm "Proceed to network monitoring?" || exit 0
}

# ============================================================================
# PHASE 5: NETWORK SECURITY MONITORING
# ============================================================================
phase_network_monitoring() {
    phase_banner 5 "NETWORK SECURITY MONITORING"
    
    gum format -- "## Network Traffic Analysis"
    
    if gum confirm "Deploy network IDS/IPS with APT41 signatures?"; then
        track_detection "T1071.001" "C2 communication detection"
        gum spin --spinner pulse --title "Deploying Suricata with APT41 rules..." -- sleep 3
        
        gum style --foreground 46 "✅ IDS/IPS: Suricata with ET Pro"
        gum style --foreground 46 "✅ APT41 C2 signatures: Loaded"
        gum style --foreground 46 "✅ DGA (Domain Generation Algorithm) detection"
        gum style --foreground 46 "✅ HTTPS inspection: Decryption enabled"
        
        DEPLOYED_CONTROLS+=("Network:IDS_IPS")
        update_security_score 12
    fi
    
    echo
    gum format -- "## DNS Monitoring"
    
    if gum confirm "Deploy DNS security (sinkholing, DGA detection)?"; then
        track_detection "T1568.002" "DGA detection"
        gum spin --spinner pulse --title "Configuring DNS security..." -- sleep 2
        
        gum style --foreground 46 "✅ DNS sinkhole for known APT41 domains"
        gum style --foreground 46 "✅ DGA detection: Machine learning model"
        gum style --foreground 46 "✅ DNS tunneling detection: Active"
        gum style --foreground 46 "✅ Newly registered domain alerts"
        
        DEPLOYED_CONTROLS+=("Network:DNS_Security")
        update_security_score 10
    fi
    
    echo
    gum format -- "## SSL/TLS Inspection"
    
    if gum confirm "Enable SSL/TLS decryption and inspection?"; then
        track_detection "Encrypted C2" "SSL inspection"
        gum spin --spinner pulse --title "Deploying SSL inspection proxy..." -- sleep 3
        
        gum style --foreground 46 "✅ SSL/TLS decryption: Active"
        gum style --foreground 46 "✅ Certificate inspection for anomalies"
        gum style --foreground 46 "✅ Custom SSL pinning detection"
        gum style --foreground 46 "✅ JA3 fingerprinting for malware C2"
        
        DEPLOYED_CONTROLS+=("Network:SSL_Inspection")
        update_security_score 15
    fi
    
    echo
    gum format -- "## Network Segmentation"
    
    if gum confirm "Implement micro-segmentation (Zero Trust)?"; then
        track_mitigation "Lateral Movement" "Network segmentation"
        gum spin --spinner pulse --title "Configuring network segmentation..." -- sleep 3
        
        gum style --foreground 46 "✅ Network segments created:"
        gum style --foreground 46 "   • Development: Isolated VLAN"
        gum style --foreground 46 "   • Production: DMZ with strict ACLs"
        gum style --foreground 46 "   • Administrative: Jump box access only"
        gum style --foreground 46 "   • Research: Air-gapped"
        gum style --foreground 46 "✅ East-West traffic: Inspected by firewall"
        
        DEPLOYED_CONTROLS+=("Network:Segmentation")
        update_security_score 12
    fi
    
    log_action "NETWORK: IDS/IPS and segmentation deployed"
    
    gum confirm "Proceed to gaming/industry-specific controls?" || exit 0
}

# ============================================================================
# PHASE 6: INDUSTRY-SPECIFIC CONTROLS
# ============================================================================
phase_industry_specific() {
    phase_banner 6 "INDUSTRY-SPECIFIC SECURITY CONTROLS"
    
    case $ORGANIZATION in
        *"Gaming"*)
            deploy_gaming_security
            ;;
        *"Healthcare"* | *"Pharmaceutical"*)
            deploy_healthcare_security
            ;;
        *"Technology"*)
            deploy_tech_security
            ;;
        *"Financial"*)
            deploy_financial_security
            ;;
        *)
            gum style --foreground 11 "⏭️  No specific industry controls for $ORGANIZATION"
            return
            ;;
    esac
    
    gum confirm "Proceed to threat hunting?" || exit 0
}

deploy_gaming_security() {
    gum format -- "## Gaming Industry Security (APT41 Primary Target)"
    gum style --foreground 11 "⚠️  Gaming companies are high-priority targets for APT41"
    gum style --foreground 11 "⚠️  Focus: Virtual currency theft, player account compromise"
    
    echo
    if gum confirm "Deploy virtual currency/item theft protection?"; then
        track_mitigation "Virtual Currency Theft" "Game economy monitoring"
        gum spin --spinner pulse --title "Deploying game economy fraud detection..." -- sleep 3
        
        gum style --foreground 46 "✅ Virtual currency transaction monitoring"
        gum style --foreground 46 "✅ Anomalous item transfer detection"
        gum style --foreground 46 "✅ Account takeover prevention"
        gum style --foreground 46 "✅ Rate limiting on valuable transactions"
        
        DEPLOYED_CONTROLS+=("Gaming:VirtualCurrencyProtection")
        update_security_score 15
    fi
    
    echo
    if gum confirm "Harden game server infrastructure?"; then
        track_mitigation "Game Server Compromise" "Server hardening"
        gum spin --spinner pulse --title "Hardening game servers..." -- sleep 2
        
        gum style --foreground 46 "✅ Database encryption at rest"
        gum style --foreground 46 "✅ Multi-factor authentication for admin access"
        gum style --foreground 46 "✅ Game logic obfuscation"
        gum style --foreground 46 "✅ Anti-cheat integration with security monitoring"
        
        DEPLOYED_CONTROLS+=("Gaming:ServerHardening")
        update_security_score 10
    fi
}

deploy_healthcare_security() {
    gum format -- "## Healthcare/Pharma Security"
    gum style --foreground 11 "⚠️  APT41 targets healthcare for research IP and patient data"
    
    echo
    if gum confirm "Protect research & development data?"; then
        track_mitigation "IP Theft" "R&D data protection"
        gum spin --spinner pulse --title "Deploying R&D data controls..." -- sleep 2
        
        gum style --foreground 46 "✅ Research data classification"
        gum style --foreground 46 "✅ DLP (Data Loss Prevention) for R&D files"
        gum style --foreground 46 "✅ Encryption: AES-256 for sensitive research"
        gum style --foreground 46 "✅ Access control: Need-to-know basis"
        
        DEPLOYED_CONTROLS+=("Healthcare:R&D_Protection")
        update_security_score 15
    fi
}

deploy_tech_security() {
    gum format -- "## Technology Company Security"
    
    echo
    if gum confirm "Protect source code and intellectual property?"; then
        track_mitigation "Source Code Theft" "Code repository security"
        gum spin --spinner pulse --title "Hardening source code repositories..." -- sleep 2
        
        gum style --foreground 46 "✅ Git repository access control"
        gum style --foreground 46 "✅ Code signing enforcement"
        gum style --foreground 46 "✅ Repository integrity monitoring"
        gum style --foreground 46 "✅ Secrets scanning (API keys, credentials)"
        
        DEPLOYED_CONTROLS+=("Tech:SourceCodeProtection")
        update_security_score 12
    fi
}

deploy_financial_security() {
    gum format -- "## Financial Institution Security"
    
    echo
    if gum confirm "Enhance payment fraud detection?"; then
        track_mitigation "Payment Fraud" "Transaction monitoring"
        gum spin --spinner pulse --title "Deploying fraud detection..." -- sleep 2
        
        gum style --foreground 46 "✅ Real-time transaction monitoring"
        gum style --foreground 46 "✅ Anomaly detection (AI/ML)"
        gum style --foreground 46 "✅ Multi-factor authentication on high-value transfers"
        
        DEPLOYED_CONTROLS+=("Finance:FraudDetection")
        update_security_score 12
    fi
}

# ============================================================================
# PHASE 7: PROACTIVE THREAT HUNTING
# ============================================================================
phase_threat_hunting() {
    phase_banner 7 "PROACTIVE THREAT HUNTING - APT41 INDICATORS"
    
    gum format -- "## Threat Hunt Mission"
    gum format -- "Hypothesis: APT41 may have deployed Winnti rootkit or established persistence"
    
    echo
    HUNT_HYPOTHESIS=$(gum choose --header "Select hunting hypothesis:" \
        "Search for Winnti rootkit artifacts" \
        "Hunt for DLL side-loading persistence" \
        "Detect signed malware (stolen certificates)" \
        "Find KEYPLUG backdoor indicators" \
        "Identify supply chain compromise")
    
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
                    FINDING="Suspicious kernel driver: WinntiBios64.sys (unsigned, hidden)"
                    HOST="SRV-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="Winnti rootkit"
                    ;;
                1)
                    FINDING="DLL side-loading: version.dll alongside VMware Tools"
                    HOST="WKS-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="APT41 persistence"
                    ;;
                2)
                    FINDING="Revoked code signing certificate in use"
                    HOST="APP-SRV-$(printf '%02d' $((RANDOM % 99)))"
                    THREAT="Signed malware (stolen cert)"
                    ;;
                3)
                    FINDING="Connection to known APT41 C2: update-$(openssl rand -hex 4).com"
                    HOST="PC-$(printf '%04d' $((RANDOM % 9999)))"
                    THREAT="KEYPLUG backdoor"
                    ;;
                4)
                    FINDING="Trojanized software: Modified hash on legitimate installer"
                    HOST="BUILD-SRV-01"
                    THREAT="Supply chain compromise"
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
    phase_banner 8 "INCIDENT RESPONSE - APT41 (WINNTI) COMPROMISE"
    
    gum format -- "## Active Incident: APT41/Winnti Activity Detected"
    gum style --foreground 196 --bold "🚨 SECURITY INCIDENT IN PROGRESS"
    
    echo
    gum format -- "### Detected Threats"
    for threat in "${DETECTED_THREATS[@]}"; do
        IFS='|' read -r host finding threat_type <<< "$threat"
        gum style --foreground 196 "  🎯 $host: $finding"
        gum style --foreground 11 "     Threat: $threat_type"
    done
    
    echo
    IR_LEAD=$(gum input --placeholder "Incident Response lead name" --value "CSIRT Lead $(whoami)")
    INCIDENT_ID="INC-APT41-$(date +%Y%m%d)-$((1000 + RANDOM % 9000))"
    
    log_action "INCIDENT DECLARED: $INCIDENT_ID by $IR_LEAD"
    
    gum style --foreground 11 "📋 Incident ID: $INCIDENT_ID"
    gum style --foreground 11 "👤 IR Lead: $IR_LEAD"
    gum style --foreground 11 "🎯 Threat Actor: APT41 (Winnti / Double Dragon)"
    
    echo
    gum format -- "## Containment Actions"
    
    # Check for rootkit
    ROOTKIT_DETECTED=false
    for threat in "${DETECTED_THREATS[@]}"; do
        if [[ "$threat" == *"rootkit"* ]] || [[ "$threat" == *"Winnti"* ]]; then
            ROOTKIT_DETECTED=true
            break
        fi
    done
    
    if [ "$ROOTKIT_DETECTED" = true ]; then
        gum style --foreground 196 --bold "🦠 WINNTI ROOTKIT DETECTED - SPECIALIZED RESPONSE REQUIRED"
        
        if gum confirm "Boot into safe mode or WinPE for rootkit removal?"; then
            gum spin --spinner pulse --title "Preparing bootable forensics environment..." -- sleep 3
            gum style --foreground 46 "✅ Hosts scheduled for offline rootkit removal"
            gum style --foreground 46 "✅ WinPE boot media prepared"
            ((INCIDENTS_CONTAINED++))
            update_security_score 15
        fi
        
        echo
        if gum confirm "Rebuild compromised systems from trusted baseline?"; then
            gum spin --spinner pulse --title "Deploying clean OS images..." -- sleep 4
            gum style --foreground 46 "✅ Systems rebuilt from golden image"
            gum style --foreground 46 "✅ Firmware verified (no UEFI rootkit)"
            ((INCIDENTS_CONTAINED++))
            update_security_score 15
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
    # Revoke stolen certificates
    CERT_DETECTED=false
    for threat in "${DETECTED_THREATS[@]}"; do
        if [[ "$threat" == *"certificate"* ]]; then
            CERT_DETECTED=true
            break
        fi
    done
    
    if [ "$CERT_DETECTED" = true ]; then
        if gum confirm "Revoke compromised code signing certificates?"; then
            gum spin --spinner pulse --title "Submitting certificate revocation to CA..." -- sleep 3
            gum style --foreground 46 "✅ Certificates revoked"
            gum style --foreground 46 "✅ CRL (Certificate Revocation List) updated"
            gum style --foreground 46 "✅ Internal blocklist deployed"
            ((INCIDENTS_CONTAINED++))
            update_security_score 15
        fi
    fi
    
    echo
    gum format -- "## Eradication"
    
    if gum confirm "Remove all APT41 malware, backdoors, and rootkits?"; then
        gum spin --spinner pulse --title "Scanning for APT41 artifacts..." -- sleep 3
        
        gum style --foreground 46 "✅ Winnti rootkit: Removed (offline cleaning)"
        gum style --foreground 46 "✅ KEYPLUG backdoor: Eradicated"
        gum style --foreground 46 "✅ DLL side-loading: Cleaned"
        gum style --foreground 46 "✅ Persistence mechanisms: Removed"
        gum style --foreground 46 "✅ C2 connections: Terminated"
        
        update_security_score 15
    fi
    
    echo
    gum format -- "## Forensic Collection"
    
    if gum confirm "Collect forensic artifacts for attribution and analysis?"; then
        gum spin --spinner pulse --title "Collecting evidence..." -- sleep 3
        gum style --foreground 46 "✅ Memory dumps: Captured (rootkit analysis)"
        gum style --foreground 46 "✅ Disk images: Acquired"
        gum style --foreground 46 "✅ Malware samples: Submitted to CISA/vendors"
        gum style --foreground 46 "✅ Network PCAPs: Preserved"
        gum style --foreground 46 "✅ Timeline analysis: Complete"
    fi
    
    echo
    gum format -- "## Recovery"
    
    if gum confirm "Restore services with enhanced monitoring?"; then
        gum spin --spinner pulse --title "Restoring operations..." -- sleep 3
        gum style --foreground 46 "✅ Systems restored to production"
        gum style --foreground 46 "✅ Enhanced EDR telemetry: Deployed"
        gum style --foreground 46 "✅ Kernel monitoring: Maximum sensitivity"
        gum style --foreground 46 "✅ Threat hunt cadence: Daily for 90 days"
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
        
        # Application whitelisting
        if gum confirm "Implement application whitelisting (AppLocker)?"; then
            track_mitigation "Malware Execution" "Application whitelisting"
            gum spin --spinner pulse --title "Deploying AppLocker policies..." -- sleep 3
            gum style --foreground 46 "✅ AppLocker: Default deny policy"
            gum style --foreground 46 "✅ Whitelist: Only approved applications"
            gum style --foreground 46 "✅ Publisher rules: Verified signatures only"
            DEPLOYED_CONTROLS+=("Windows:AppLocker")
            update_security_score 15
        fi
        
        echo
        # Deception technology
        if gum confirm "Deploy honeypots and canary tokens?"; then
            track_detection "Lateral Movement" "Deception technology"
            gum spin --spinner pulse --title "Deploying deception layer..." -- sleep 2
            gum style --foreground 46 "✅ Honeypot systems: 3 deployed"
            gum style --foreground 46 "✅ Canary files: Distributed across shares"
            gum style --foreground 46 "✅ Fake credentials: Planted in memory"
            DEPLOYED_CONTROLS+=("Deception:Honeypots")
            update_security_score 10
        fi
        
        echo
        # Threat intelligence sharing
        if gum confirm "Share IoCs with threat intelligence community?"; then
            gum spin --spinner pulse --title "Submitting threat intelligence..." -- sleep 2
            gum style --foreground 46 "✅ IoCs shared with CISA"
            gum style --foreground 46 "✅ FS-ISAC notification sent"
            gum style --foreground 46 "✅ Vendor threat feeds updated"
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
    gum format -- "Simulate APT41 attack to test defenses"
    
    echo
    if gum confirm "Authorize APT41-style red team engagement?"; then
        
        SCOPE=$(gum choose --no-limit --header "Red team scope:" \
            "Winnti rootkit deployment simulation" \
            "Code signing certificate abuse" \
            "Supply chain attack scenario" \
            "DLL side-loading persistence test")
        
        gum spin --spinner pulse --title "Red team executing APT41 TTPs..." -- sleep 5
        
        gum format -- "### Red Team Results"
        
        DETECTION_RATE=$((60 + (SECURITY_SCORE / 3) + RANDOM % 15))
        if [ $DETECTION_RATE -gt 100 ]; then
            DETECTION_RATE=100
        fi
        
        DWELL_TIME=$((35 - (SECURITY_SCORE / 4)))
        if [ $DWELL_TIME -lt 1 ]; then
            DWELL_TIME=1
        fi
        
        gum style --foreground 46 "📊 Detection Rate: ${DETECTION_RATE}%"
        gum style --foreground 11 "⏱️  Mean Time to Detect: ${DWELL_TIME} hours"
        gum style --foreground 11 "🦠 Rootkit Detection: $([ $DETECTION_RATE -gt 75 ] && echo "STRONG" || echo "NEEDS WORK")"
        gum style --foreground 11 "📜 Code Signing Validation: $([ $DETECTION_RATE -gt 80 ] && echo "EFFECTIVE" || echo "GAPS EXIST")"
        
        if [ $DETECTION_RATE -ge 85 ]; then
            gum style --foreground 46 "✅ EXCELLENT: Strong APT41/Winnti defense posture"
            update_security_score 20
        elif [ $DETECTION_RATE -ge 70 ]; then
            gum style --foreground 11 "⚠️  GOOD: Some gaps remain"
            update_security_score 10
        else
            gum style --foreground 196 "❌ CRITICAL GAPS: APT41 could succeed"
            update_security_score -5
        fi
        
        echo
        gum format -- "### Identified Gaps"
        gum style --foreground 11 "  - Kernel-mode monitoring needs enhancement"
        gum style --foreground 11 "  - Certificate revocation checking incomplete"
        gum style --foreground 46 "  + Rootkit detected within acceptable timeframe"
        gum style --foreground 46 "  + Supply chain integrity validation effective"
        
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
        "APT41 (Winnti / Double Dragon) Defense Assessment"
    
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
    printf "│ %-38s │ %-20s │\n" "Rootkit Risk" "$ROOTKIT_RISK"
    printf "│ %-38s │ %-20s │\n" "Supply Chain Risk" "$SUPPLY_CHAIN_RISK"
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
    gum format -- "## Detection Coverage (APT41 TTPs)"
    
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
        echo "  1. URGENT: Deploy rootkit detection tools (kernel monitoring)"
        echo "  2. Enforce driver signature verification"
        echo "  3. Implement code signing certificate validation"
        echo "  4. Harden software supply chain (SBOM, update integrity)"
        echo "  5. Deploy advanced EDR with behavioral analysis"
    elif [ $SECURITY_SCORE -lt 85 ]; then
        gum style --foreground 11 "### Recommended Enhancements"
        echo "  1. Enhance kernel-mode telemetry collection"
        echo "  2. Deploy deception technology (honeypots)"
        echo "  3. Implement application whitelisting"
        echo "  4. Conduct quarterly purple team exercises"
    else
        gum style --foreground 46 "### Maintain and Enhance"
        echo "  1. Continue proactive threat hunting for APT41 IoCs"
        echo "  2. Maintain driver signature enforcement"
        echo "  3. Regular supply chain security audits"
        echo "  4. Quarterly APT41-focused red team assessments"
    fi
    
    echo
    gum style --foreground 240 "Detailed log: $LOG_FILE"
    
    echo
    if gum confirm "Generate formal assessment report?"; then
        REPORT_FILE="/tmp/apt41-defense-report-$(date +%Y%m%d-%H%M%S).txt"
        {
            echo "============================================"
            echo "APT41 (WINNTI / DOUBLE DRAGON) DEFENSE ASSESSMENT"
            echo "Rootkit & Supply Chain Security Evaluation"
            echo "Generated: $(date)"
            echo "============================================"
            echo
            echo "EXECUTIVE SUMMARY:"
            echo "  Organization: $ORGANIZATION"
            echo "  Security Grade: $grade"
            echo "  Security Score: $SECURITY_SCORE/100"
            echo "  Rootkit Risk: $ROOTKIT_RISK"
            echo "  Supply Chain Risk: $SUPPLY_CHAIN_RISK"
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
                echo "  Organization vulnerable to APT41 rootkit and supply chain attacks."
                echo "  Immediate action required on kernel monitoring and code signing validation."
            elif [ $SECURITY_SCORE -lt 85 ]; then
                echo "  Level: MODERATE"
                echo "  Baseline defenses present, enhancement recommended."
            else
                echo "  Level: LOW"
                echo "  Strong defense against APT41/Winnti TTPs."
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
    phase_rootkit_detection
    phase_code_signing
    phase_supply_chain
    phase_endpoint_detection
    phase_network_monitoring
    phase_industry_specific
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
        gum style --foreground 46 --bold "🛡️  Defense mission successful. Organization secured against APT41/Winnti."
    else
        gum style --foreground 11 --bold "⚠️  Defense gaps identified. Continue hardening operations against rootkits."
    fi
}

# Run main
main
