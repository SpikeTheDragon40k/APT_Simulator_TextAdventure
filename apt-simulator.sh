#!/bin/bash
# ============================================================================
# APT Cyber Killchain Simulator - TUI Launcher
# ============================================================================
# Simple menu to launch Red/Blue Team scripts
# ============================================================================

VERSION="1.0.0"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIALOG=${DIALOG=dialog}

# ============================================================================
# CHECK DIALOG
# ============================================================================
check_dialog() {
    if ! command -v dialog &> /dev/null; then
        echo "Installing dialog..."
        if command -v apt &> /dev/null; then
            sudo apt install -y dialog
        elif command -v brew &> /dev/null; then
            brew install dialog
        else
            echo "❌ Please install dialog: sudo apt install dialog"
            exit 1
        fi
    fi
}

# ============================================================================
# MAIN MENU
# ============================================================================
main_menu() {
    while true; do
        CHOICE=$(dialog --clear --backtitle "APT Simulator v$VERSION" \
            --title "[ MAIN MENU ]" \
            --menu "Choose operation:" 15 60 5 \
            1 "🔴 Red Team" \
            2 "🛡️  Blue Team" \
            3 "❌ Exit" \
            3>&1 1>&2 2>&3)
        
        case $? in
            0)
                case $CHOICE in
                    1) red_team_menu ;;
                    2) blue_team_menu ;;
                    3) clear; exit 0 ;;
                esac
                ;;
            *)
                clear
                exit 0
                ;;
        esac
    done
}

# ============================================================================
# RED TEAM MENU
# ============================================================================
red_team_menu() {
    CHOICE=$(dialog --clear --backtitle "APT Simulator - Red Team" \
        --title "[ SELECT APT GROUP ]" \
        --menu "Choose attack simulator:" 20 70 10 \
        1 "🇷🇺 APT28 (Fancy Bear)" \
        2 "🇷🇺 APT29 (Cozy Bear)" \
        3 "🇰🇵 Lazarus Group" \
        4 "🇨🇳 APT41 (Winnti)" \
        5 "🇷🇺 Sandworm" \
        6 "🇻🇳 APT32 (Ocean Lotus)" \
        7 "🇺🇸 Equation Group" \
        8 "🇷🇺 Turla" \
        9 "← Back" \
        3>&1 1>&2 2>&3)
    
    case $CHOICE in
        1) run_script "red-team/apt28-killchain.sh" ;;
        2) run_script "red-team/apt29-killchain.sh" ;;
        3) run_script "red-team/lazarus-killchain.sh" ;;
        4) run_script "red-team/apt41-killchain.sh" ;;
        5) run_script "red-team/sandworm-killchain.sh" ;;
        6) run_script "red-team/apt32-killchain.sh" ;;
        7) run_script "red-team/equation-killchain.sh" ;;
        8) run_script "red-team/turla-killchain.sh" ;;
        9) return ;;
    esac
}

# ============================================================================
# BLUE TEAM MENU
# ============================================================================
blue_team_menu() {
    CHOICE=$(dialog --clear --backtitle "APT Simulator - Blue Team" \
        --title "[ SELECT DEFENSE SCENARIO ]" \
        --menu "Choose defense simulator:" 20 70 10 \
        1 "🛡️  APT28 Defense" \
        2 "🛡️  APT29 Defense" \
        3 "🛡️  Lazarus Defense" \
        4 "🛡️  APT41 Defense" \
        5 "🛡️  Sandworm Defense" \
        6 "🛡️  APT32 Defense" \
        7 "🛡️  Equation Defense" \
        8 "🛡️  Turla Defense" \
        9 "← Back" \
        3>&1 1>&2 2>&3)
    
    case $CHOICE in
        1) run_script "blue-team/blueteam-apt28-defense.sh" ;;
        2) run_script "blue-team/blueteam-apt29-defense.sh" ;;
        3) run_script "blue-team/blueteam-lazarus-defense.sh" ;;
        4) run_script "blue-team/blueteam-apt41-defense.sh" ;;
        5) run_script "blue-team/blueteam-sandworm-defense.sh" ;;
        6) run_script "blue-team/blueteam-apt32-defense.sh" ;;
        7) run_script "blue-team/blueteam-equation-defense.sh" ;;
        8) run_script "blue-team/blueteam-turla-defense.sh" ;;
        9) return ;;
    esac
}

# ============================================================================
# RUN SCRIPT
# ============================================================================
run_script() {
    local script="$SCRIPTS_DIR/$1"
    
    if [ -f "$script" ]; then
        clear
        bash "$script"
        echo ""
        read -p "Press Enter to return to menu..."
    else
        dialog --title "[ NOT IMPLEMENTED ]" \
            --msgbox "Script not found:\n$script\n\nCreate it to enable this simulator!" 10 60
    fi
}

# ============================================================================
# MAIN
# ============================================================================
check_dialog
mkdir -p "$SCRIPTS_DIR/red-team" "$SCRIPTS_DIR/blue-team"
main_menu
