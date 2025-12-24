#!/bin/bash
# ============================================================================
# BLUE TEAM: APT29 (COZY BEAR) DEFENSE SIMULATOR
# ============================================================================
# Defending against Nobelium/SolarWinds-style supply chain attacks
# Focus: Supply chain security, cloud defense, advanced detection
# ============================================================================

set -euo pipefail
trap cleanup INT TERM

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================
VERSION="1.0"
LOG_FILE="/tmp/blueteam-apt29-$(date +%Y%m%d-%H%M%S).log"
INCIDENT_FILE="/tmp/apt29-incidents-$(date +%Y%m%d-%H%M%S).json"
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
        SUPPLY_CHAIN_RISK="LOW"
    elif [ $SECURITY_SCORE -ge 70 ]; then
        THREAT_LEVEL="GUARDED"
        SUPPLY_CHAIN_RISK="MODERATE"
    elif [ $SECURITY_SCORE -ge 50 ]; then
        THREAT_LEVEL="ELEVATED"
        SUPPLY_CHAIN_RISK="ELEVATED"
    elif [ $SECURITY_SCORE -ge 30 ]; then
        THREAT_LEVEL="HIGH"
        SUPPLY_CHAIN_RISK="HIGH"
    else
        THREAT_LEVEL="SEVERE"
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
    
    gum style --foreground $color "🛡️  Threat: $THREAT_LEVEL | Supply Chain: $SUPPLY_CHAIN_RISK | Score: $SECURITY_SCORE/100"
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
        "Defending Against APT29 (Cozy Bear)" \
        "" \
        "Supply Chain Defense & Cloud Security v${VERSION}"
    
    echo
    
    gum format -- "# Mission Parameters"
    gum format -- "**Adversary**: APT29 (Cozy Bear, Nobelium, The Dukes)"
    gum format -- "**Attribution**: SVR - Russian Foreign Intelligence"
    gum format -- "**MITRE Group**: G0016"
    gum format -- "**Threat Focus**: Supply chain attacks, cloud compromise, long-term espionage"
    gum format -- "**Your Role**: Lead Security Architect & Incident Response"
    gum format -- "**Objective**: Detect and prevent SolarWinds-style compromise"
    
    echo
    
    ORGANIZATION=$(gum choose --header "Select your organization type:" \
        "Government Agency" \
        "Cloud Service Provider" \
        "Software Vendor (Critical supply chain)" \
        "Financial Institution" \
        "Healthcare/Pharmaceutical")
    
    log_action "=== BLUE TEAM APT29 DEFENSE START ==="
    log_action "Organization: $ORGANIZATION"
    
    echo
    gum format -- "## Intelligence Brief"
    gum style --foreground 196 "🚨 CRITICAL: APT29 SolarWinds-style campaign detected"
    gum style --foreground 11 "📊 Targeting: $ORGANIZATION sector"
    gum style --foreground 11 "🎯 Attack vectors: Supply chain, cloud infrastructure, long-term persistence"
    
    echo
    if ! gum confirm "Begin defensive operations?"; then
        echo "Mission cancelled"
        exit 0
    fi
}

# ============================================================================
# PHASE 1: SUPPLY CHAIN RISK ASSESSMENT
# ============================================================================
phase_supply_chain() {
    phase_banner 1 "SUPPLY CHAIN RISK ASSESSMENT"
    
    gum format -- "## Software Supply Chain Inventory"
    
    gum spin --spinner dot --title "Cataloging third-party dependencies..." -- sleep 2
    
    VENDOR_COUNT=$((20 + RANDOM % 80))
    CRITICAL_VENDORS=$((VENDOR_COUNT / 4))
    
    gum style --foreground 46 "✅ Third-party vendors: $VENDOR_COUNT"
    gum style --foreground 11 "⚠️  Critical supply chain vendors: $CRITICAL_VENDORS"
    
    echo
    gum format -- "## Critical Vendor Identification"
    
    CRITICAL_VENDOR=$(gum choose --header "Identify highest-risk vendor:" \
        "IT Management Software (SolarWinds-type)" \
        "Cloud Email Security (Mimecast)" \
        "Identity Management (Okta)" \
        "Backup Software (Veeam)" \
        "Network Management Tools")
    
    log_action "CRITICAL VENDOR: $CRITICAL_VENDOR"
    
    echo
    gum format -- "## Software Bill of Materials (SBOM)"
    
    if gum confirm "Generate SBOM for all critical software?"; then
        gum spin --spinner pulse --title "Generating SBOM..." -- sleep 3
        track_mitigation "Supply Chain" "SBOM generation"
        gum style --foreground 46 "✅ SBOM generated for $CRITICAL_VENDORS critical vendors"
        gum style --foreground 46 "✅ Tracked components: $((CRITICAL_VENDORS * 150))"
        DEPLOYED_CONTROLS+=("SBOM:CriticalVendors")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Software Update Verification"
    
    if gum confirm "Implement code signing verification?"; then
        track_mitigation "Supply Chain Compromise" "Code signing verification"
        gum spin --spinner pulse --title "Deploying signature validation..." -- sleep 2
        gum style --foreground 46 "✅ Mandatory code signature verification"
        gum style --foreground 46 "✅ Certificate pinning enforced"
        DEPLOYED_CONTROLS+=("CodeSigning:Mandatory")
        update_security_score 12
    fi
    
    echo
    if gum confirm "Deploy software update sandboxing?"; then
        track_mitigation "Malicious Updates" "Update sandboxing"
        gum spin --spinner pulse --title "Configuring isolated update environment..." -- sleep 3
        gum style --foreground 46 "✅ Updates tested in isolated sandbox first"
        gum style --foreground 46 "✅ Behavioral analysis pre-deployment"
        DEPLOYED_CONTROLS+=("Sandbox:SoftwareUpdates")
        update_security_score 15
    fi
    
    log_action "SUPPLY CHAIN: $CRITICAL_VENDORS critical vendors assessed"
    
    gum confirm "Proceed to cloud security?" || exit 0
}

# ============================================================================
# PHASE 2: CLOUD SECURITY POSTURE
# ============================================================================
phase_cloud_security() {
    phase_banner 2 "CLOUD SECURITY POSTURE (AZURE/O365 FOCUS)"
    
    gum format -- "## Cloud Environment Assessment"
    
    CLOUD_ENV=$(gum choose --header "Primary cloud environment:" \
        "Microsoft Azure + O365" \
        "AWS + Google Workspace" \
        "Hybrid (Azure + On-prem)" \
        "Multi-cloud")
    
    gum spin --spinner dot --title "Scanning cloud infrastructure..." -- sleep 3
    
    CLOUD_USERS=$((500 + RANDOM % 2000))
    ADMIN_ACCOUNTS=$((10 + RANDOM % 50))
    SERVICE_PRINCIPALS=$((20 + RANDOM % 100))
    
    gum style --foreground 46 "✅ Cloud users: $CLOUD_USERS"
    gum style --foreground 11 "⚠️  Admin accounts: $ADMIN_ACCOUNTS"
    gum style --foreground 11 "⚠️  Service principals: $SERVICE_PRINCIPALS"
    
    echo
    gum format -- "## Azure AD Hardening"
    
    if gum confirm "Enforce MFA for all admin accounts?"; then
        track_mitigation "Credential Theft" "MFA enforcement"
        gum spin --spinner pulse --title "Deploying conditional access policies..." -- sleep 2
        gum style --foreground 46 "✅ MFA enforced for admins"
        gum style --foreground 46 "✅ Risk-based authentication enabled"
        DEPLOYED_CONTROLS+=("AzureAD:MFA_Mandatory")
        update_security_score 10
    fi
    
    echo
    if gum confirm "Enable Privileged Identity Management (PIM)?"; then
        track_mitigation "Persistent Admin Access" "Just-in-time access"
        gum spin --spinner pulse --title "Configuring Azure PIM..." -- sleep 3
        gum style --foreground 46 "✅ Just-in-time admin access"
        gum style --foreground 46 "✅ Time-limited role activation"
        gum style --foreground 46 "✅ Approval workflows for Global Admin"
        DEPLOYED_CONTROLS+=("AzureAD:PIM")
        update_security_score 15
    fi
    
    echo
    gum format -- "## SAML Token Security"
    
    if gum confirm "Protect ADFS token-signing certificate (Golden SAML defense)?"; then
        track_mitigation "Golden SAML" "Certificate protection"
        gum spin --spinner pulse --title "Hardening ADFS infrastructure..." -- sleep 2
        gum style --foreground 46 "✅ Token-signing cert in HSM"
        gum style --foreground 46 "✅ Certificate rotation policy: 90 days"
        gum style --foreground 46 "✅ ADFS audit logging enhanced"
        DEPLOYED_CONTROLS+=("ADFS:CertProtection")
        update_security_score 12
    fi
    
    echo
    gum format -- "## Azure AD Application Auditing"
    
    if gum confirm "Audit all registered applications and service principals?"; then
        track_detection "Rogue Apps" "Application inventory"
        gum spin --spinner pulse --title "Enumerating Azure AD apps..." -- sleep 2
        
        SUSPICIOUS_APPS=$((RANDOM % 5))
        
        if [ $SUSPICIOUS_APPS -gt 0 ]; then
            gum style --foreground 196 "🚨 SUSPICIOUS: $SUSPICIOUS_APPS unauthorized applications found!"
            ((INCIDENTS_DETECTED += SUSPICIOUS_APPS))
            DETECTED_THREATS+=("Rogue Azure AD app|T1098.001")
        else
            gum style --foreground 46 "✅ No suspicious applications detected"
        fi
        
        gum style --foreground 46 "✅ Application consent policies enforced"
        DEPLOYED_CONTROLS+=("AzureAD:AppAudit")
        update_security_score 8
    fi
    
    echo
    gum format -- "## Cloud Access Security Broker (CASB)"
    
    if gum confirm "Deploy Microsoft Defender for Cloud Apps?"; then
        track_mitigation "Cloud Threats" "CASB monitoring"
        gum spin --spinner pulse --title "Deploying CASB..." -- sleep 3
        gum style --foreground 46 "✅ Anomalous behavior detection"
        gum style --foreground 46 "✅ OAuth app governance"
        gum style --foreground 46 "✅ Cloud DLP policies"
        DEPLOYED_CONTROLS+=("Cloud:CASB")
        update_security_score 12
    fi
    
    log_action "CLOUD SECURITY: $CLOUD_ENV hardened, ${#DEPLOYED_CONTROLS[@]} controls"
    
    gum confirm "Proceed to network monitoring?" || exit 0
}

# ============================================================================
# PHASE 3: NETWORK & ENDPOINT DETECTION
# ============================================================================
phase_network_endpoint() {
    phase_banner 3 "NETWORK & ENDPOINT DETECTION"
    
    gum format -- "## EDR/XDR Deployment"
    
    TOTAL_ENDPOINTS=$((500 + RANDOM % 1500))
    
    EDR_SOLUTION=$(gum choose --header "Deploy/enhance EDR platform:" \
        "Microsoft Defender for Endpoint" \
        "CrowdStrike Falcon" \
        "SentinelOne" \
        "Carbon Black")
    
    if [[ "$EDR_SOLUTION" != *"None"* ]]; then
        gum spin --spinner pulse --title "Deploying $EDR_SOLUTION to $TOTAL_ENDPOINTS endpoints..." -- sleep 4
        track_mitigation "Malware Execution" "$EDR_SOLUTION"
        gum style --foreground 46 "✅ EDR coverage: $TOTAL_ENDPOINTS/$TOTAL_ENDPOINTS (100%)"
        DEPLOYED_CONTROLS+=("EDR:$EDR_SOLUTION")
        update_security_score 15
    fi
    
    echo
    gum format -- "## APT29-Specific Detection Rules"
    
    if gum confirm "Deploy SUNBURST/TEARDROP detection signatures?"; then
        gum spin --spinner pulse --title "Loading APT29 IoC database..." -- sleep 2
        track_detection "T1195.002" "SUNBURST backdoor detection"
        track_detection "T1055.001" "TEARDROP memory injection"
        
        gum style --foreground 46 "✅ SUNBURST DLL hash detection"
        gum style --foreground 46 "✅ Avsvmcloud domain pattern blocking"
        gum style --foreground 46 "✅ TEARDROP memory-only dropper signatures"
        gum style --foreground 46 "✅ GoldMax C2 beacon detection"
        DEPLOYED_CONTROLS+=("EDR:APT29_Signatures")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Behavioral Detection - Memory-Only Malware"
    
    if gum confirm "Enable advanced memory scanning (TEARDROP defense)?"; then
        track_detection "T1027" "Memory-only execution detection"
        gum spin --spinner pulse --title "Configuring memory analysis..." -- sleep 2
        gum style --foreground 46 "✅ In-memory PE detection"
        gum style --foreground 46 "✅ Reflective DLL injection monitoring"
        gum style --foreground 46 "✅ Process hollowing detection"
        DEPLOYED_CONTROLS+=("EDR:MemoryScanning")
        update_security_score 12
    fi
    
    echo
    gum format -- "## Network Traffic Analysis"
    
    if gum confirm "Deploy network detection (Cobalt Strike C2)?"; then
        track_detection "T1071.001" "Cobalt Strike beacon detection"
        gum spin --spinner pulse --title "Analyzing network patterns..." -- sleep 3
        
        gum style --foreground 46 "✅ Cobalt Strike Malleable C2 detection"
        gum style --foreground 46 "✅ DNS-over-HTTPS anomaly detection"
        gum style --foreground 46 "✅ Domain fronting detection"
        gum style --foreground 46 "✅ Long-duration HTTPS sessions flagged"
        DEPLOYED_CONTROLS+=("Network:CobaltStrike_Detection")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Sysmon Deployment"
    
    if gum confirm "Deploy Sysmon with APT29-focused config?"; then
        track_detection "Process Creation" "Sysmon EID 1"
        gum spin --spinner pulse --title "Deploying Sysmon..." -- sleep 3
        gum style --foreground 46 "✅ Sysmon deployed: SwiftOnSecurity config + APT29 additions"
        gum style --foreground 46 "✅ Process creation logging (EID 1)"
        gum style --foreground 46 "✅ Network connections (EID 3)"
        gum style --foreground 46 "✅ Image loads (EID 7) - DLL monitoring"
        DEPLOYED_CONTROLS+=("Logging:Sysmon")
        update_security_score 10
    fi
    
    log_action "ENDPOINT: $TOTAL_ENDPOINTS endpoints protected"
    
    gum confirm "Proceed to SIEM & detection engineering?" || exit 0
}

# ============================================================================
# PHASE 4: SIEM & DETECTION ENGINEERING
# ============================================================================
phase_siem_detection() {
    phase_banner 4 "SIEM & DETECTION ENGINEERING"
    
    gum format -- "## SIEM Platform Configuration"
    
    SIEM_PLATFORM=$(gum choose --header "SIEM/SOAR platform:" \
        "Microsoft Sentinel (Azure-native)" \
        "Splunk Enterprise Security" \
        "Elastic Security" \
        "Chronicle Security")
    
    gum spin --spinner pulse --title "Deploying $SIEM_PLATFORM..." -- sleep 3
    gum style --foreground 46 "✅ SIEM: $SIEM_PLATFORM"
    DEPLOYED_CONTROLS+=("SIEM:$SIEM_PLATFORM")
    update_security_score 12
    
    echo
    gum format -- "## Log Source Configuration"
    
    gum spin --spinner dot --title "Configuring log ingestion..." -- sleep 2
    
    gum style --foreground 46 "✅ Windows Event Logs (Security, System)"
    gum style --foreground 46 "✅ Azure AD sign-in logs"
    gum style --foreground 46 "✅ O365 audit logs"
    gum style --foreground 46 "✅ ADFS audit logs"
    gum style --foreground 46 "✅ Sysmon operational logs"
    gum style --foreground 46 "✅ EDR telemetry"
    gum style --foreground 46 "✅ Cloud resource logs"
    
    echo
    gum format -- "## APT29-Specific Detection Rules"
    
    if gum confirm "Deploy Sigma rules for APT29/Nobelium?"; then
        gum spin --spinner pulse --title "Converting Sigma rules to $SIEM_PLATFORM..." -- sleep 3
        
        track_detection "T1195.002" "Supply chain compromise detection"
        track_detection "T1606.002" "Golden SAML token abuse"
        track_detection "T1098.001" "Azure AD app manipulation"
        track_detection "T1528" "OAuth token theft"
        track_detection "T1078.004" "Cloud account abuse"
        track_detection "T1071.001" "HTTPS C2 beaconing"
        
        gum style --foreground 46 "✅ 32 Sigma rules deployed"
        gum style --foreground 46 "✅ APT29 TTP coverage: 85%"
        update_security_score 15
    fi
    
    echo
    gum format -- "## Behavioral Analytics"
    
    if gum confirm "Enable UEBA (User/Entity Behavior Analytics)?"; then
        track_detection "Anomalous Behavior" "UEBA"
        gum spin --spinner pulse --title "Training baseline models..." -- sleep 3
        gum style --foreground 46 "✅ UEBA: Anomalous cloud access"
        gum style --foreground 46 "✅ UEBA: Impossible travel detection"
        gum style --foreground 46 "✅ UEBA: Unusual data access patterns"
        DEPLOYED_CONTROLS+=("SIEM:UEBA")
        update_security_score 10
    fi
    
    echo
    gum format -- "## Threat Intelligence Integration"
    
    if gum confirm "Integrate APT29 threat intel feeds?"; then
        track_detection "IoC Matching" "Threat intel feeds"
        gum spin --spinner pulse --title "Ingesting threat intelligence..." -- sleep 2
        gum style --foreground 46 "✅ CISA APT29 IoCs"
        gum style --foreground 46 "✅ Microsoft Threat Intelligence"
        gum style --foreground 46 "✅ FireEye Nobelium indicators"
        DEPLOYED_CONTROLS+=("SIEM:ThreatIntel")
        update_security_score 8
    fi
    
    log_action "SIEM: $SIEM_PLATFORM with ${#DETECTION_RULES[@]} detection rules"
    
    gum confirm "Proceed to threat hunting?" || exit 0
}

# ============================================================================
# PHASE 5: PROACTIVE THREAT HUNTING
# ============================================================================
phase_threat_hunting() {
    phase_banner 5 "PROACTIVE THREAT HUNTING"
    
    gum format -- "## Threat Hunt Mission"
    gum format -- "Hypothesis: APT29 may have established persistence via supply chain"
    
    echo
    HUNT_HYPOTHESIS=$(gum choose --header "Select hunting hypothesis:" \
        "Search for SUNBURST/TEARDROP artifacts" \
        "Hunt for Golden SAML token abuse" \
        "Identify rogue Azure AD applications" \
        "Detect Cobalt Strike beacons" \
        "Find long-duration cloud sessions")
    
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
                    FINDING="Suspicious DLL: SolarWinds.Orion.Core.BusinessLayer.dll (hash mismatch)"
                    HOST="SRV-SOLARWINDS-01"
                    ;;
                1)
                    FINDING="Anomalous SAML token usage from impossible location"
                    HOST="ADFS01.domain.local"
                    ;;
                2)
                    FINDING="Rogue Azure AD app: 'Microsoft Substrate Management'"
                    HOST="AzureAD Tenant"
                    ;;
                3)
                    FINDING="Long-duration HTTPS session to avsvmcloud domain"
                    HOST="WKS-$(printf '%04d' $((RANDOM % 9999)))"
                    ;;
                4)
                    FINDING="Memory-only execution detected (TEARDROP signature)"
                    HOST="SRV-$(printf '%04d' $((RANDOM % 9999)))"
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
        gum write --height 5 --placeholder "Document hunt procedures and findings..." > /tmp/apt29-hunt-notes.txt
        gum style --foreground 46 "✅ Hunt notes saved to /tmp/apt29-hunt-notes.txt"
    fi
    
    log_action "THREAT HUNT: Complete - $SUSPICIOUS_FINDINGS findings"
    
    if [ $SUSPICIOUS_FINDINGS -eq 0 ]; then
        gum confirm "Proceed to incident response readiness?" || exit 0
    fi
}

# ============================================================================
# PHASE 6: INCIDENT RESPONSE (IF THREATS DETECTED)
# ============================================================================
phase_incident_response() {
    phase_banner 6 "INCIDENT RESPONSE - APT29 COMPROMISE"
    
    gum format -- "## Active Incident: APT29 (Nobelium) Activity Detected"
    gum style --foreground 196 --bold "🚨 SECURITY INCIDENT IN PROGRESS"
    
    echo
    gum format -- "### Detected Threats"
    for threat in "${DETECTED_THREATS[@]}"; do
        IFS='|' read -r host finding <<< "$threat"
        gum style --foreground 196 "  🎯 $host: $finding"
    done
    
    echo
    IR_LEAD=$(gum input --placeholder "Incident Response lead name" --value "SOC Lead $(whoami)")
    INCIDENT_ID="INC-APT29-$(date +%Y%m%d)-$((1000 + RANDOM % 9000))"
    
    log_action "INCIDENT DECLARED: $INCIDENT_ID by $IR_LEAD"
    
    gum style --foreground 11 "📋 Incident ID: $INCIDENT_ID"
    gum style --foreground 11 "👤 IR Lead: $IR_LEAD"
    gum style --foreground 11 "🎯 Threat Actor: APT29 (Cozy Bear / Nobelium)"
    
    echo
    gum format -- "## Containment Actions"
    
    # Isolate compromised systems
    if gum confirm "Isolate affected systems from network?"; then
        for threat in "${DETECTED_THREATS[@]}"; do
            IFS='|' read -r host finding <<< "$threat"
            
            if [[ "$host" != *"Azure"* ]]; then
                gum spin --spinner pulse --title "Isolating $host via EDR..." -- sleep 2
                gum style --foreground 46 "✅ $host isolated (network quarantine)"
                BLOCKED_ATTACKS+=("$host|Network isolation")
                ((INCIDENTS_CONTAINED++))
            fi
        done
        update_security_score 10
    fi
    
    echo
    # Revoke cloud tokens
    if gum confirm "Revoke all Azure AD refresh tokens (force re-auth)?"; then
        gum spin --spinner pulse --title "Revoking-AzureADUserAllRefreshToken..." -- sleep 3
        gum style --foreground 46 "✅ All user refresh tokens revoked"
        gum style --foreground 46 "✅ Force re-authentication with MFA"
        ((INCIDENTS_CONTAINED++))
        update_security_score 15
    fi
    
    echo
    # Remove rogue apps
    if gum confirm "Remove suspicious Azure AD applications?"; then
        gum spin --spinner pulse --title "Removing rogue Azure AD apps..." -- sleep 2
        gum style --foreground 46 "✅ Rogue application removed"
        gum style --foreground 46 "✅ Service principal credentials revoked"
        ((INCIDENTS_CONTAINED++))
        update_security_score 10
    fi
    
    echo
    # Reset ADFS
    if gum confirm "Rotate ADFS token-signing certificate (Golden SAML mitigation)?"; then
        gum spin --spinner pulse --title "Rotating ADFS certificates..." -- sleep 4
        gum style --foreground 46 --bold "✅ ADFS TOKEN-SIGNING CERT ROTATED"
        gum style --foreground 46 "✅ All existing SAML tokens invalidated"
        gum style --foreground 46 "✅ Golden SAML access eliminated"
        update_security_score 20
    fi
    
    echo
    gum format -- "## Eradication"
    
    if gum confirm "Remove malware and backdoors?"; then
        gum spin --spinner pulse --title "Scanning for APT29 malware..." -- sleep 3
        gum style --foreground 46 "✅ SUNBURST backdoor removed"
        gum style --foreground 46 "✅ TEARDROP dropper cleaned"
        gum style --foreground 46 "✅ GoldMax implant eradicated"
        gum style --foreground 46 "✅ Cobalt Strike beacons terminated"
        
        if gum confirm "Re-image compromised systems?"; then
            gum spin --spinner pulse --title "Re-imaging affected hosts..." -- sleep 4
            gum style --foreground 46 "✅ Clean OS deployment complete"
            update_security_score 15
        fi
    fi
    
    echo
    gum format -- "## Forensic Collection"
    
    if gum confirm "Collect forensic artifacts?"; then
        gum spin --spinner pulse --title "Collecting evidence..." -- sleep 3
        gum style --foreground 46 "✅ Memory dumps collected"
        gum style --foreground 46 "✅ Event logs preserved"
        gum style --foreground 46 "✅ Network PCAPs saved"
        gum style --foreground 46 "✅ Cloud audit logs exported"
        gum style --foreground 46 "✅ Chain of custody documented"
    fi
    
    echo
    gum format -- "## Recovery & Enhanced Monitoring"
    
    if gum confirm "Restore services with enhanced monitoring?"; then
        gum spin --spinner pulse --title "Restoring operations..." -- sleep 3
        gum style --foreground 46 "✅ Systems restored to production"
        gum style --foreground 46 "✅ Enhanced logging deployed"
        gum style --foreground 46 "✅ Continuous threat hunt scheduled"
    fi
    
    log_action "INCIDENT $INCIDENT_ID: Contained and eradicated"
    
    gum confirm "Continue to lessons learned?" || exit 0
}

# ============================================================================
# PHASE 7: SUPPLY CHAIN HARDENING (POST-INCIDENT)
# ============================================================================
phase_supply_chain_hardening() {
    phase_banner 7 "SUPPLY CHAIN HARDENING"
    
    gum format -- "## Enhanced Supply Chain Security"
    
    if gum confirm "Implement vendor security requirements?"; then
        gum spin --spinner pulse --title "Deploying vendor security program..." -- sleep 2
        track_mitigation "Supply Chain" "Vendor security requirements"
        gum style --foreground 46 "✅ Mandatory vendor security assessments"
        gum style --foreground 46 "✅ Code review requirements"
        gum style --foreground 46 "✅ Incident notification SLAs"
        DEPLOYED_CONTROLS+=("SupplyChain:VendorProgram")
        update_security_score 10
    fi
    
    echo
    if gum confirm "Deploy software composition analysis (SCA)?"; then
        track_detection "Vulnerable Components" "SCA scanning"
        gum spin --spinner pulse --title "Deploying SCA tools..." -- sleep 3
        gum style --foreground 46 "✅ Automated dependency scanning"
        gum style --foreground 46 "✅ Vulnerability alerting"
        gum style --foreground 46 "✅ License compliance"
        DEPLOYED_CONTROLS+=("SupplyChain:SCA")
        update_security_score 12
    fi
    
    echo
    if gum confirm "Implement binary transparency logging?"; then
        track_mitigation "Backdoored Updates" "Binary transparency"
        gum spin --spinner pulse --title "Configuring transparency logs..." -- sleep 2
        gum style --foreground 46 "✅ All binaries logged to immutable ledger"
        gum style --foreground 46 "✅ Tamper detection enabled"
        DEPLOYED_CONTROLS+=("SupplyChain:BinaryTransparency")
        update_security_score 15
    fi
    
    log_action "SUPPLY CHAIN: Enhanced security controls deployed"
    
    gum confirm "Proceed to final assessment?" || exit 0
}

# ============================================================================
# PHASE 8: RED TEAM VALIDATION
# ============================================================================
phase_red_team_validation() {
    phase_banner 8 "RED TEAM VALIDATION"
    
    gum format -- "## Purple Team Exercise"
    gum format -- "Simulate APT29 attack chain to test defenses"
    
    echo
    if gum confirm "Authorize APT29-style red team engagement?"; then
        
        SCOPE=$(gum choose --no-limit --header "Red team scope:" \
            "Supply chain compromise simulation" \
            "Cloud infrastructure testing" \
            "Golden SAML attack" \
            "Cobalt Strike C2 testing")
        
        gum spin --spinner pulse --title "Red team executing APT29 TTPs..." -- sleep 5
        
        gum format -- "### Red Team Results"
        
        DETECTION_RATE=$((60 + (SECURITY_SCORE / 3) + RANDOM % 15))
        if [ $DETECTION_RATE -gt 100 ]; then
            DETECTION_RATE=100
        fi
        
        DWELL_TIME=$((30 - (SECURITY_SCORE / 5)))
        if [ $DWELL_TIME -lt 1 ]; then
            DWELL_TIME=1
        fi
        
        gum style --foreground 46 "📊 Detection Rate: ${DETECTION_RATE}%"
        gum style --foreground 11 "⏱️  Mean Time to Detect: ${DWELL_TIME} hours"
        gum style --foreground 11 "🎯 Supply Chain Defense: $([ $DETECTION_RATE -gt 80 ] && echo "STRONG" || echo "NEEDS WORK")"
        
        if [ $DETECTION_RATE -ge 85 ]; then
            gum style --foreground 46 "✅ EXCELLENT: Strong APT29 defense posture"
            update_security_score 20
        elif [ $DETECTION_RATE -ge 70 ]; then
            gum style --foreground 11 "⚠️  GOOD: Some gaps in supply chain defense"
            update_security_score 10
        else
            gum style --foreground 196 "❌ CRITICAL GAPS: APT29 could succeed"
            update_security_score -5
        fi
        
        echo
        gum format -- "### Identified Gaps"
        gum style --foreground 11 "  - SAML token monitoring needs enhancement"
        gum style --foreground 11 "  - Cloud app consent flow bypass detected"
        gum style --foreground 46 "  + Supply chain compromise detected quickly"
        gum style --foreground 46 "  + Memory-only malware caught by EDR"
        
        if gum confirm "Conduct purple team debrief?"; then
            gum style --foreground 46 "✅ Purple team session complete"
            gum style --foreground 46 "✅ Detection rules enhanced based on findings"
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
        "APT29 (Cozy Bear) Defense Assessment"
    
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
    gum format -- "## Detection Coverage (APT29 TTPs)"
    
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
    gum format -- "## Key Recommendations"
    
    if [ $SECURITY_SCORE -lt 70 ]; then
        gum style --foreground 196 "### Critical Actions Required"
        echo "  1. Implement supply chain security program (SBOM, code signing)"
        echo "  2. Deploy EDR/XDR with APT29 signatures"
        echo "  3. Harden Azure AD (MFA, PIM, conditional access)"
        echo "  4. Rotate ADFS token-signing certificate"
        echo "  5. Deploy SIEM with APT29 detection rules"
    elif [ $SECURITY_SCORE -lt 85 ]; then
        gum style --foreground 11 "### Recommended Enhancements"
        echo "  1. Enhance cloud security monitoring (CASB)"
        echo "  2. Implement UEBA for anomaly detection"
        echo "  3. Deploy software composition analysis (SCA)"
        echo "  4. Conduct regular purple team exercises"
    else
        gum style --foreground 46 "### Maintain and Enhance"
        echo "  1. Continue proactive threat hunting"
        echo "  2. Regular APT29 TTP updates"
        echo "  3. Supply chain vendor assessments"
        echo "  4. Quarterly red team validation"
    fi
    
    echo
    gum style --foreground 240 "Detailed log: $LOG_FILE"
    
    echo
    if gum confirm "Generate formal assessment report?"; then
        REPORT_FILE="/tmp/apt29-defense-report-$(date +%Y%m%d-%H%M%S).txt"
        {
            echo "============================================"
            echo "APT29 (COZY BEAR) DEFENSE ASSESSMENT"
            echo "Supply Chain & Cloud Security Evaluation"
            echo "Generated: $(date)"
            echo "============================================"
            echo
            echo "EXECUTIVE SUMMARY:"
            echo "  Organization: $ORGANIZATION"
            echo "  Security Grade: $grade"
            echo "  Security Score: $SECURITY_SCORE/100"
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
                echo "  Organization vulnerable to APT29 supply chain attacks."
                echo "  Immediate action required."
            elif [ $SECURITY_SCORE -lt 85 ]; then
                echo "  Level: MODERATE"
                echo "  Baseline defenses present, gaps remain."
                echo "  Continue enhancement program."
            else
                echo "  Level: LOW"
                echo "  Strong defense against APT29 TTPs."
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
    phase_supply_chain
    phase_cloud_security
    phase_network_endpoint
    phase_siem_detection
    phase_threat_hunting
    
    # Conditional incident response
    if [ $INCIDENTS_DETECTED -gt 0 ]; then
        phase_incident_response
    fi
    
    phase_supply_chain_hardening
    phase_red_team_validation
    
    generate_report
    
    echo
    if [ $SECURITY_SCORE -ge 85 ]; then
        gum style --foreground 46 --bold "🛡️  Defense mission successful. Supply chain secured."
    else
        gum style --foreground 11 --bold "⚠️  Defense gaps identified. Continue hardening operations."
    fi
}

# Run main
main
