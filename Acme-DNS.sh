#!/bin/bash

# ==============================================================
# Script Name: Acme-DNS-Super
# Description: Advanced Acme.sh Management (Bilingual Edition)
# Version: 3.3
# Author: System Expert
# ==============================================================

# ==============================================================
# 0. Global Definitions / 全局定义
# ==============================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# Paths
CONFIG_FILE="$HOME/.acme_super_config"
ACME_DIR="$HOME/.acme.sh"
ACME_SH="$ACME_DIR/acme.sh"

# Root Check
[[ $EUID -ne 0 ]] && echo -e "${RED}Error: Root privileges required! / 错误: 必须使用 root 权限！${PLAIN}" && exit 1

# ==============================================================
# 1. Configuration & Language / 配置与语言
# ==============================================================

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        # Default Init
        CA_SERVER="letsencrypt"
        KEY_LENGTH="2048"
        USER_EMAIL=""
        LANG_SET="" 
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
CA_SERVER="$CA_SERVER"
KEY_LENGTH="$KEY_LENGTH"
USER_EMAIL="$USER_EMAIL"
LANG_SET="$LANG_SET"
EOF
}

# Set Language Strings
set_language_text() {
    if [ "$LANG_SET" == "en" ]; then
        TXT_TITLE="Acme-DNS-Super V3.3 | Auto Cert Manager"
        TXT_STATUS="Status"
        TXT_NOT_SET="Not Set"
        TXT_HINT_INSTALL=">> System detected acme.sh is NOT installed. Recommended: Run [1] first. <<"
        TXT_MENU_1="Init Environment (Install Deps, acme.sh & Account)"
        TXT_MENU_2="System Settings (Email / CA / Key Type)"
        TXT_MENU_3="Issue Cert - HTTP Mode (Single Domain)"
        TXT_MENU_4="Issue Cert - DNS API Mode (Wildcard Supported)"
        TXT_MENU_5="Install Cert to Service (Nginx/Apache/etc)"
        TXT_MENU_6="Cert Management (Renew / Revoke)"
        TXT_MENU_7="Uninstall Script"
        TXT_EXIT="Exit"
        TXT_SELECT="Please select [0-7]: "
        TXT_INVALID="Invalid selection."
        TXT_PRESS_ENTER="Press Enter to continue..."
        TXT_CHECK_DEP="Checking dependencies..."
        TXT_MISSING_DEP="Missing dependencies detected, updating..."
        TXT_INSTALLED="Installed"
        TXT_SYNC_ACC="Syncing CA Account info..."
        TXT_ENTER_EMAIL="Please enter Email for registration: "
        TXT_EMAIL_ERR="Invalid Email format."
        TXT_ACME_INSTALLED="acme.sh is already installed."
        TXT_ACME_INSTALLING="Installing acme.sh..."
        TXT_SUCCESS_INIT="Initialization completed!"
        TXT_WARN_NO_INIT="Please initialize environment first!"
        TXT_ENTER_DOMAIN="Enter Domain: "
        TXT_DOMAIN_EMPTY="Domain cannot be empty."
        TXT_CHOOSE_MODE="Choose Mode"
        TXT_ISSUE_SUCCESS="Issue Success! Proceed to [Install Cert] step."
        TXT_ISSUE_FAIL="Issue Failed."
        TXT_INSTALL_NOTE="Target paths (Leave empty if not needed):"
        TXT_INSTALL_SUCCESS="Cert installed & Auto-renew configured."
    else
        # Chinese (Default)
        TXT_TITLE="Acme-DNS-Super V3.3 | 自动化证书管理"
        TXT_STATUS="当前状态"
        TXT_NOT_SET="未设置"
        TXT_HINT_INSTALL=">> 检测到未安装 acme.sh，建议优先执行选项 [1] 初始化 <<"
        TXT_MENU_1="环境初始化 (依赖安装 & acme.sh & 账户注册)"
        TXT_MENU_2="系统设置 (修改邮箱 / 切换 CA / 密钥规格)"
        TXT_MENU_3="申请证书 - HTTP 模式 (单域名)"
        TXT_MENU_4="申请证书 - DNS API 模式 (支持泛域名)"
        TXT_MENU_5="安装证书到服务 (Nginx/Apache 等)"
        TXT_MENU_6="证书列表与维护 (续期/吊销)"
        TXT_MENU_7="脚本卸载"
        TXT_EXIT="退出"
        TXT_SELECT="请输入选项 [0-7]: "
        TXT_INVALID="无效选择"
        TXT_PRESS_ENTER="按回车键继续..."
        TXT_CHECK_DEP="正在检查系统核心依赖..."
        TXT_MISSING_DEP="检测到缺失依赖，正在更新源并补全..."
        TXT_INSTALLED="已安装"
        TXT_SYNC_ACC="正在同步 CA 账户注册信息..."
        TXT_ENTER_EMAIL="请输入用于注册的邮箱: "
        TXT_EMAIL_ERR="邮箱格式错误，请重试。"
        TXT_ACME_INSTALLED="acme.sh 已安装。"
        TXT_ACME_INSTALLING="正在安装 acme.sh..."
        TXT_SUCCESS_INIT="环境初始化配置完成！"
        TXT_WARN_NO_INIT="请先执行环境初始化！"
        TXT_ENTER_DOMAIN="请输入域名: "
        TXT_DOMAIN_EMPTY="域名不能为空"
        TXT_CHOOSE_MODE="请选择模式"
        TXT_ISSUE_SUCCESS="签发成功！请继续执行 [安装证书] 步骤。"
        TXT_ISSUE_FAIL="签发失败。"
        TXT_INSTALL_NOTE="配置目标路径 (不需要的项直接回车):"
        TXT_INSTALL_SUCCESS="安装成功，已配置自动续期。"
    fi
}

select_language_first() {
    if [ -z "$LANG_SET" ]; then
        clear
        echo -e "${BLUE}==============================================================${PLAIN}"
        echo -e "Please select language / 请选择语言"
        echo -e "${BLUE}==============================================================${PLAIN}"
        echo -e "1. 中文 (Chinese)"
        echo -e "2. English"
        echo -e "--------------------------------------------------------------"
        read -p "Select [1-2]: " lang_opt
        if [ "$lang_opt" == "2" ]; then
            LANG_SET="en"
        else
            LANG_SET="cn"
        fi
        save_config
    fi
    set_language_text
}

# ==============================================================
# 2. Core Functions / 核心功能
# ==============================================================

check_dependencies() {
    echo -e "${CYAN}${TXT_CHECK_DEP}${PLAIN}"
    
    local install_cmd=""
    local update_cmd=""

    if [[ -n $(command -v apt-get) ]]; then
        install_cmd="apt-get -y -q install"
        update_cmd="apt-get -q update"
    elif [[ -n $(command -v yum) ]]; then
        install_cmd="yum -y -q install"
        update_cmd="yum -q makecache"
    elif [[ -n $(command -v apk) ]]; then
        install_cmd="apk add"
        update_cmd="apk update"
    else
        echo -e "${RED}Error: No package manager found.${PLAIN}"
        return 1
    fi

    local dependencies=(curl wget socat tar openssl cron)
    local missing_dep=false

    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing_dep=true
            break
        fi
    done

    if [ "$missing_dep" = true ]; then
        echo -e "${YELLOW}${TXT_MISSING_DEP}${PLAIN}"
        $update_cmd
    fi

    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${YELLOW}Installing: $dep ...${PLAIN}"
            $install_cmd $dep
        fi
    done
    
    # Ensure Cron
    if [[ -n $(command -v systemctl) ]]; then
        if ! systemctl is-active --quiet cron && ! systemctl is-active --quiet crond; then
             systemctl start cron || systemctl start crond
        fi
    fi
}

register_accounts() {
    local email=$1
    if [ -z "$email" ]; then return; fi

    echo -e "${YELLOW}>>> ${TXT_SYNC_ACC} (Email: $email)${PLAIN}"
    
    # 1. Let's Encrypt
    "$ACME_SH" --register-account -m "$email" --server letsencrypt --output-insecure >/dev/null 2>&1
    # 2. ZeroSSL
    "$ACME_SH" --register-account -m "$email" --server zerossl --output-insecure >/dev/null 2>&1
}

install_acme_sh() {
    if [ -f "$ACME_SH" ]; then
        echo -e "${GREEN}${TXT_ACME_INSTALLED}${PLAIN}"
    else
        echo -e "${CYAN}${TXT_ACME_INSTALLING}${PLAIN}"
        
        while true; do
            if [ -z "$USER_EMAIL" ]; then
                read -p "${TXT_ENTER_EMAIL}" input_email
                USER_EMAIL="$input_email"
            fi
            
            if [[ "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                save_config
                break
            else
                echo -e "${RED}${TXT_EMAIL_ERR}${PLAIN}"
                USER_EMAIL=""
            fi
        done
        
        curl https://get.acme.sh | sh -s email="$USER_EMAIL"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Official install failed, trying git...${PLAIN}"
            ! command -v git &> /dev/null && echo "Please install git first" && return
            git clone https://github.com/acmesh-official/acme.sh.git ~/.acme.sh
            cd ~/.acme.sh || exit
            ./acme.sh --install -m "$USER_EMAIL"
            cd ..
        fi
    fi
    
    load_config
    register_accounts "$USER_EMAIL"
    "$ACME_SH" --set-default-ca --server "$CA_SERVER"
    "$ACME_SH" --upgrade --auto-upgrade
    save_config
    
    echo -e "${GREEN}${TXT_SUCCESS_INIT}${PLAIN}"
}

# ==============================================================
# 3. Issue & Install / 签发与部署
# ==============================================================

issue_http() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    
    echo -e "${YELLOW}>>> HTTP Mode (Single Domain, Port 80 required)${PLAIN}"
    read -p "${TXT_ENTER_DOMAIN}" DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}" && return

    echo -e "1. Standalone"
    echo -e "2. Nginx"
    echo -e "3. Apache"
    echo -e "4. Webroot"
    read -p "${TXT_SELECT}" MODE

    local cmd_flags=""
    case $MODE in
        1) cmd_flags="--standalone" ;;
        2) cmd_flags="--nginx" ;;
        3) cmd_flags="--apache" ;;
        4) 
            read -p "Webroot Path: " webroot
            cmd_flags="--webroot $webroot"
            ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; return ;;
    esac

    "$ACME_SH" --issue -d "$DOMAIN" $cmd_flags --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
    fi
}

issue_dns() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi

    echo -e "${YELLOW}>>> DNS API Mode (Wildcard Supported)${PLAIN}"
    read -p "${TXT_ENTER_DOMAIN}" DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}" && return

    echo -e "1. CloudFlare"
    echo -e "2. Tencent (DNSPod)"
    echo -e "3. Aliyun"
    echo -e "4. AWS Route53"
    echo -e "5. Custom ENV (Manual)"
    echo -e "0. Back"
    read -p "${TXT_SELECT}" DNS_OPT

    unset CF_Key CF_Email DP_Id DP_Key Ali_Key Ali_Secret AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

    local dns_type=""
    case $DNS_OPT in
        1)
            read -p "CF Global API Key: " CF_Key
            read -p "CF Email: " CF_Email
            export CF_Key="$CF_Key"
            export CF_Email="$CF_Email"
            dns_type="dns_cf"
            ;;
        2)
            read -p "DNSPod ID: " DP_Id
            read -p "DNSPod Token: " DP_Key
            export DP_Id="$DP_Id"
            export DP_Key="$DP_Key"
            dns_type="dns_dp"
            ;;
        3)
            read -p "Aliyun AccessKey: " Ali_Key
            read -p "Aliyun Secret: " Ali_Secret
            export Ali_Key="$Ali_Key"
            export Ali_Secret="$Ali_Secret"
            dns_type="dns_ali"
            ;;
        4)
            read -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID
            read -p "AWS Secret: " AWS_SECRET_ACCESS_KEY
            export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
            dns_type="dns_aws"
            ;;
        5)
            echo -e "${YELLOW}Input ENV variables (Format: Key=Value). Type 'end' to finish.${PLAIN}"
            while true; do
                read -p "ENV > " env_in
                [[ "$env_in" == "end" ]] && break
                export "$env_in"
            done
            read -p "Plugin Code (e.g., dns_cf): " dns_type
            ;;
        0) return ;;
        *) return ;;
    esac
    
    [ -z "$dns_type" ] && return

    "$ACME_SH" --issue --dns "$dns_type" -d "$DOMAIN" --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
    fi
}

install_cert_menu() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi

    local default_domain=$1
    echo -e "${YELLOW}>>> Install Cert${PLAIN}"
    
    if [ -z "$default_domain" ]; then
        read -p "${TXT_ENTER_DOMAIN}" DOMAIN
    else
        DOMAIN=$default_domain
    fi

    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}Cert not found.${PLAIN}"
        return
    fi

    echo -e "${CYAN}${TXT_INSTALL_NOTE}${PLAIN}"
    read -p "Cert Path (e.g. /etc/nginx/ssl/cert.pem): " CERT_PATH
    read -p "Key  Path (e.g. /etc/nginx/ssl/key.pem):  " KEY_PATH
    read -p "CA   Path (e.g. /etc/nginx/ssl/full.pem): " CA_PATH
    read -p "Reload Cmd (e.g. systemctl reload nginx): " RELOAD_CMD

    local cmd_build="$ACME_SH --install-cert -d $DOMAIN"
    [[ "$KEY_LENGTH" == "ec"* ]] && cmd_build="$cmd_build --ecc"

    [ -n "$CERT_PATH" ] && cmd_build="$cmd_build --cert-file $CERT_PATH"
    [ -n "$KEY_PATH" ] && cmd_build="$cmd_build --key-file $KEY_PATH"
    [ -n "$CA_PATH" ] && cmd_build="$cmd_build --fullchain-file $CA_PATH"
    [ -n "$RELOAD_CMD" ] && cmd_build="$cmd_build --reloadcmd \"$RELOAD_CMD\""

    eval "$cmd_build"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_INSTALL_SUCCESS}${PLAIN}"
    else
        echo -e "${RED}Install Failed.${PLAIN}"
    fi
}

# ==============================================================
# 4. Settings & Maintenance / 设置与维护
# ==============================================================

configure_settings() {
    while true; do
        echo -e "${CYAN}===== Settings =====${PLAIN}"
        echo -e "${TXT_STATUS}: CA[${GREEN}$CA_SERVER${PLAIN}] | Key[${GREEN}$KEY_LENGTH${PLAIN}] | Email[${GREEN}$USER_EMAIL${PLAIN}]"
        echo "------------------------"
        echo "1. Change Email & Sync Accounts"
        echo "2. Change Default CA"
        echo "3. Change Key Spec (RSA/ECC)"
        echo "4. Upgrade acme.sh"
        echo "0. Back"
        read -p "${TXT_SELECT}" choice
        
        case $choice in
            1)
                read -p "${TXT_ENTER_EMAIL}" new_email
                if [[ "$new_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    USER_EMAIL="$new_email"
                    save_config
                    register_accounts "$USER_EMAIL"
                else
                    echo -e "${RED}${TXT_EMAIL_ERR}${PLAIN}"
                fi
                ;;
            2)
                echo "1. Let's Encrypt (Default)"
                echo "2. ZeroSSL"
                read -p "Select CA: " ca_opt
                case $ca_opt in
                    1) CA_SERVER="letsencrypt" ;;
                    2) CA_SERVER="zerossl" ;;
                    *) CA_SERVER="letsencrypt" ;;
                esac
                "$ACME_SH" --set-default-ca --server "$CA_SERVER"
                save_config
                ;;
            3)
                echo "1. RSA-2048 (Default)"
                echo "2. ECC-256"
                read -p "Select Key: " key_opt
                case $key_opt in
                    1) KEY_LENGTH="2048" ;;
                    2) KEY_LENGTH="ec-256" ;;
                    *) KEY_LENGTH="2048" ;;
                esac
                save_config
                ;;
            4) "$ACME_SH" --upgrade ;;
            0) return ;;
        esac
    done
}

manage_certs() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    
    while true; do
        echo -e "${CYAN}===== Cert List =====${PLAIN}"
        "$ACME_SH" --list
        echo "------------------------"
        echo "1. Force Renew"
        echo "2. Revoke & Delete"
        echo "0. Back"
        read -p "${TXT_SELECT}" choice
        
        case $choice in
            1) 
                read -p "Domain: " d_renew
                [ -n "$d_renew" ] && "$ACME_SH" --renew -d "$d_renew" --force 
                ;;
            2)
                read -p "Domain: " d_del
                if [ -n "$d_del" ]; then
                     read -p "Confirm (y/n): " confirm
                     if [[ "$confirm" == "y" ]]; then
                        "$ACME_SH" --revoke -d "$d_del"
                        "$ACME_SH" --remove -d "$d_del"
                        rm -rf "$ACME_DIR/$d_del" "$ACME_DIR/${d_del}_ecc"
                        echo -e "${GREEN}Deleted.${PLAIN}"
                     fi
                fi
                ;;
            0) return ;;
        esac
    done
}

uninstall_menu() {
    echo -e "${RED}===== Uninstall =====${PLAIN}"
    echo "1. Remove Script Config"
    echo "2. Full Uninstall (acme.sh + Certs + Script)"
    read -p "Select [1-2]: " u_opt
    
    if [[ "$u_opt" == "1" ]]; then
        rm -f "$CONFIG_FILE"
        echo -e "${GREEN}Config removed.${PLAIN}"
    elif [[ "$u_opt" == "2" ]]; then
        read -p "Type 'DELETE' to confirm: " confirm
        if [[ "$confirm" == "DELETE" ]]; then
            [ -f "$ACME_SH" ] && "$ACME_SH" --uninstall
            rm -rf "$ACME_DIR" "$CONFIG_FILE" "$0"
            echo -e "${GREEN}Uninstalled.${PLAIN}"
            exit 0
        fi
    fi
}

# ==============================================================
# 5. Main Entry / 主入口
# ==============================================================

show_menu() {
    clear
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${BLUE}           ${TXT_TITLE}           ${PLAIN}"
    echo -e "${BLUE}==============================================================${PLAIN}"
    # 单行状态显示
    echo -e "${TXT_STATUS}: CA: ${GREEN}${CA_SERVER}${PLAIN} | Key: ${GREEN}${KEY_LENGTH}${PLAIN} | Email: ${GREEN}${USER_EMAIL:-${TXT_NOT_SET}}${PLAIN}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"

    # 柔性引导提示 (仅提示，不阻断)
    if [ ! -f "$ACME_SH" ]; then
        echo -e "${RED}${TXT_HINT_INSTALL}${PLAIN}"
    fi

    echo -e " 1. ${TXT_MENU_1}"
    echo -e " 2. ${TXT_MENU_2}"
    echo -e "--------------------------------------------------------------"
    echo -e " 3. ${TXT_MENU_3}"
    echo -e " 4. ${TXT_MENU_4}"
    echo -e " 5. ${TXT_MENU_5}"
    echo -e "--------------------------------------------------------------"
    echo -e " 6. ${TXT_MENU_6}"
    echo -e " 7. ${TXT_MENU_7}"
    echo -e " 0. ${TXT_EXIT}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"
    read -p " ${TXT_SELECT}" num

    case $num in
        1) check_dependencies && install_acme_sh ;;
        2) configure_settings ;;
        3) issue_http ;;
        4) issue_dns ;;
        5) install_cert_menu ;;
        6) manage_certs ;;
        7) uninstall_menu ;;
        0) exit 0 ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}" ;;
    esac
}

# Run
load_config
select_language_first

while true; do
    show_menu
    echo ""
    read -p "${TXT_PRESS_ENTER}"
done
