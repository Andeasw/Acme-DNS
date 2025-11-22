#!/bin/bash

# ==============================================================
# Script Name: Acme-DNS-Super
# Description: Advanced Acme.sh Manager (Bilingual & Shortcut Support)
# Version: 0.0.1 (Strict Logic Release)
# By Prince 2025.10
# ==============================================================

# ==============================================================
# 0. Global Definitions / 全局定义
# ==============================================================

set -u # 报错未定义变量

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

CONFIG_FILE="$HOME/.acme_super_config"
ACME_DIR="$HOME/.acme.sh"
ACME_SH="$ACME_DIR/acme.sh"

# 获取脚本真实路径（处理软链接和相对路径）
CURRENT_SCRIPT_PATH=""
if [ -f "$0" ]; then
    CURRENT_SCRIPT_PATH=$(readlink -f "$0")
fi

# Check Root
[[ $EUID -ne 0 ]] && echo -e "${RED}Error: Root privileges required! / 需要 Root 权限!${PLAIN}" && exit 1

# ==============================================================
# 1. Input Validation / 输入安全校验
# ==============================================================

check_valid_domain() {
    local domain="$1"
    # 允许字母、数字、点、连字符，禁止特殊字符防止注入
    if [[ ! "$domain" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo -e "${RED}Error: Invalid domain format! Contains illegal characters.${PLAIN}"
        return 1
    fi
    return 0
}

check_path_safety() {
    local path="$1"
    # 简单的路径检查，防止过分危险的输入
    if [[ "$path" == *"&"* ]] || [[ "$path" == *"|"* ]] || [[ "$path" == *";"* ]]; then
        echo -e "${RED}Error: Path contains illegal characters for security reasons.${PLAIN}"
        return 1
    fi
    return 0
}

# ==============================================================
# 2. Localization & Config / 本地化与配置
# ==============================================================

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        CA_SERVER="letsencrypt"
        KEY_LENGTH="2048"
        USER_EMAIL=""
        LANG_SET=""
        SHORTCUT_NAME=""
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
CA_SERVER="$CA_SERVER"
KEY_LENGTH="$KEY_LENGTH"
USER_EMAIL="$USER_EMAIL"
LANG_SET="$LANG_SET"
SHORTCUT_NAME="$SHORTCUT_NAME"
EOF
}

load_language_strings() {
    if [ "$LANG_SET" == "en" ]; then
        # --- English ---
        TXT_TITLE="Acme-DNS-Super V0.0.1 | Cert Manager By Prince"
        TXT_STATUS_LABEL="Status"
        TXT_EMAIL_LABEL="Email"
        TXT_NOT_SET="Not Set"
        TXT_HINT_INSTALL=">> Warning: acme.sh is NOT installed. Please run [1] first. <<"
        
        # Menus
        TXT_M_1="Init Environment (Install, Register & Shortcut)"
        TXT_M_2="Settings (Language / CA / Key / Shortcut)"
        TXT_M_3="Issue Cert - HTTP Mode (Single Domain)"
        TXT_M_4="Issue Cert - DNS API Mode (Wildcard Supported)"
        TXT_M_5="Install Cert to Service (Nginx/Apache)"
        TXT_M_6="Cert Maintenance (List / Renew / Revoke)"
        TXT_M_7="Uninstall Script"
        TXT_M_0="Exit"
        
        # Cert Manage Submenu
        TXT_M6_TITLE="Certificate Management"
        TXT_M6_RENEW="Force Renew (Renew specific domain)"
        TXT_M6_REVOKE="Revoke & Delete (Revoke from CA & Remove local)"
        TXT_M6_INPUT_RENEW="Enter domain to renew: "
        TXT_M6_INPUT_DEL="Enter domain to revoke & delete: "
        TXT_M6_CONFIRM_DEL="Are you sure you want to REVOKE & DELETE? (y/n): "
        TXT_M6_DELETED="Certificate revoked and deleted."
        TXT_M6_EMPTY="No certificates found."
        
        # Shortcut
        TXT_SC_CREATE="Creating shortcut..."
        TXT_SC_ASK="Enter shortcut name (Default: ssl): "
        TXT_SC_SUCCESS="Shortcut created! You can now run this script by typing: "
        TXT_SC_FAIL_ONLINE="Error: Online (Curl) mode detected."
        TXT_SC_FAIL_HINT="Please download the script locally using 'wget' to enable shortcuts."
        
        # Common
        TXT_SELECT="Please select [0-7]: "
        TXT_INVALID="Invalid selection."
        TXT_PRESS_ENTER="Press Enter to continue..."
        TXT_CHECK_DEP="Checking dependencies..."
        TXT_MISSING_DEP="Missing dependencies, updating..."
        TXT_INSTALLING_DEP="Installing: "
        TXT_ACME_EXIST="acme.sh is already installed."
        TXT_ACME_INSTALLING="Installing acme.sh..."
        TXT_INPUT_EMAIL="Enter valid Email (for Account Registration): "
        TXT_EMAIL_INVALID="Invalid Email format!"
        TXT_ACC_SYNC="Syncing Accounts (Let's Encrypt & ZeroSSL)..."
        TXT_INIT_SUCCESS="Initialization Completed!"
        TXT_WARN_NO_INIT="Please initialize environment first (Menu 1)!"
        
        # Issue
        TXT_INPUT_DOMAIN="Enter Domain (e.g., example.com): "
        TXT_DOMAIN_EMPTY="Domain cannot be empty."
        TXT_HTTP_MODE_SEL="Select Validation Mode:"
        TXT_HTTP_STANDALONE="1. Standalone (Needs Port 80 free)"
        TXT_HTTP_NGINX="2. Nginx (Auto Config)"
        TXT_HTTP_APACHE="3. Apache (Auto Config)"
        TXT_HTTP_WEBROOT="4. Webroot (Specify Path)"
        TXT_INPUT_WEBROOT="Enter Webroot Path: "
        TXT_PORT_80_WARN="Warning: Port 80 is in use. Standalone mode may fail."
        TXT_CONTINUE_ASK="Continue anyway? (y/n): "
        TXT_ISSUE_START="Starting Issue Process..."
        TXT_ISSUE_SUCCESS="Certificate Issued Successfully!"
        TXT_ISSUE_FAIL="Issue Failed. Check logs."
        
        # DNS
        TXT_DNS_SEL="Select DNS Provider:"
        TXT_DNS_MANUAL="Manual Input (ENV Variables)"
        TXT_DNS_KEY="API Key/Token: "
        TXT_DNS_EMAIL="Account Email: "
        
        # Install
        TXT_INS_DOMAIN="Enter Issued Domain: "
        TXT_INS_CERT_PATH="Cert Path (e.g. /etc/nginx/ssl/cert.pem): "
        TXT_INS_KEY_PATH="Key Path (e.g. /etc/nginx/ssl/key.pem): "
        TXT_INS_CA_PATH="CA Path (e.g. /etc/nginx/ssl/full.pem): "
        TXT_INS_RELOAD="Reload Command (e.g. systemctl reload nginx): "
        TXT_INS_SUCCESS="Install Success! Auto-renew configured."
        
        # Settings
        TXT_SET_TITLE="System Settings"
        TXT_SET_1="Change Email (Sync Accounts)"
        TXT_SET_2="Change Language (切换语言)"
        TXT_SET_3="Switch Default CA"
        TXT_SET_4="Switch Key Type"
        TXT_SET_5="Upgrade acme.sh"
        TXT_SET_6="Update/Repair Shortcut"
        TXT_SET_UPDATED="Settings Updated."
        
        # Uninstall
        TXT_UN_TITLE="Uninstall Options"
        TXT_UN_1="Remove Script Config & Shortcut"
        TXT_UN_2="Full Uninstall (acme.sh + Certs + Script)"
        TXT_UN_CONFIRM="Type 'DELETE' to confirm full uninstall: "
        TXT_UN_DONE="Uninstalled."

    else
        # --- Chinese (Default) ---
        TXT_TITLE="Acme-DNS-Super V0.0.1 | 证书管理大师 By Prince"
        TXT_STATUS_LABEL="当前状态"
        TXT_EMAIL_LABEL="注册邮箱"
        TXT_NOT_SET="未设置"
        TXT_HINT_INSTALL=">> 警告：检测到未安装 acme.sh，请优先执行选项 [1] <<"
        
        # Menus
        TXT_M_1="环境初始化 (安装、注册账户、配置快捷指令)"
        TXT_M_2="系统设置 (语言 / 邮箱 / CA / 密钥 / 快捷键)"
        TXT_M_3="签发证书 - HTTP 模式 (单域名)"
        TXT_M_4="签发证书 - DNS API 模式 (支持泛域名)"
        TXT_M_5="部署证书到服务 (Nginx/Apache 等)"
        TXT_M_6="证书维护 (查看列表 / 续期 / 吊销)"
        TXT_M_7="卸载脚本"
        TXT_M_0="退出"
        
        # Cert Manage Submenu
        TXT_M6_TITLE="证书管理列表"
        TXT_M6_RENEW="强制续期 (Force Renew)"
        TXT_M6_REVOKE="吊销并删除 (向 CA 吊销并清理本地文件)"
        TXT_M6_INPUT_RENEW="请输入要续期的域名: "
        TXT_M6_INPUT_DEL="请输入要吊销的域名: "
        TXT_M6_CONFIRM_DEL="确认执行 [吊销+删除] 吗? (y/n): "
        TXT_M6_DELETED="证书已吊销并彻底删除。"
        TXT_M6_EMPTY="未找到任何证书。"
        
        # Shortcut
        TXT_SC_CREATE="正在配置快捷启动..."
        TXT_SC_ASK="请输入快捷命令名称 (默认: ssl): "
        TXT_SC_SUCCESS="快捷方式已创建！以后在终端输入以下命令即可运行："
        TXT_SC_FAIL_ONLINE="错误：检测到脚本正在在线运行 (Curl/Pipe)。"
        TXT_SC_FAIL_HINT="快捷方式仅支持本地文件。请先使用 wget 下载脚本到本地后再运行。"

        # Common
        TXT_SELECT="请输入选项 [0-7]: "
        TXT_INVALID="无效的选择。"
        TXT_PRESS_ENTER="按回车键继续..."
        TXT_CHECK_DEP="正在检查系统依赖..."
        TXT_MISSING_DEP="检测到缺失依赖，正在更新源..."
        TXT_INSTALLING_DEP="正在安装: "
        TXT_ACME_EXIST="acme.sh 已安装。"
        TXT_ACME_INSTALLING="正在安装 acme.sh (官方源)..."
        TXT_INPUT_EMAIL="请输入有效邮箱 (用于账户注册): "
        TXT_EMAIL_INVALID="邮箱格式错误！"
        TXT_ACC_SYNC="正在同步账户 (Let's Encrypt 和 ZeroSSL)..."
        TXT_INIT_SUCCESS="环境初始化完成！"
        TXT_WARN_NO_INIT="请先执行环境初始化 (选项 1)！"
        
        # Issue
        TXT_INPUT_DOMAIN="请输入域名 (例: example.com): "
        TXT_DOMAIN_EMPTY="域名不能为空。"
        TXT_HTTP_MODE_SEL="选择验证模式:"
        TXT_HTTP_STANDALONE="1. Standalone (脚本模拟Web服务，需80端口空闲)"
        TXT_HTTP_NGINX="2. Nginx (自动读取/修改配置)"
        TXT_HTTP_APACHE="3. Apache (自动读取/修改配置)"
        TXT_HTTP_WEBROOT="4. Webroot (指定网站根目录)"
        TXT_INPUT_WEBROOT="请输入根目录路径: "
        TXT_PORT_80_WARN="警告: 80 端口被占用，Standalone 模式可能失败。"
        TXT_CONTINUE_ASK="是否强制继续? (y/n): "
        TXT_ISSUE_START="开始执行签发流程..."
        TXT_ISSUE_SUCCESS="证书签发成功！"
        TXT_ISSUE_FAIL="签发失败，请检查日志。"
        
        # DNS
        TXT_DNS_SEL="选择 DNS 服务商:"
        TXT_DNS_MANUAL="手动输入环境变量 (通用模式)"
        TXT_DNS_KEY="API 密钥 (Key/Token): "
        TXT_DNS_EMAIL="账户邮箱 (Email): "
        
        # Install
        TXT_INS_DOMAIN="请输入已签发的域名: "
        TXT_INS_CERT_PATH="Cert 文件路径 (例 /etc/nginx/ssl/cert.pem): "
        TXT_INS_KEY_PATH="Key  文件路径 (例 /etc/nginx/ssl/key.pem): "
        TXT_INS_CA_PATH="CA   文件路径 (例 /etc/nginx/ssl/full.pem): "
        TXT_INS_RELOAD="重载服务命令 (例 systemctl reload nginx): "
        TXT_INS_SUCCESS="部署成功！已添加自动续期钩子。"
        
        # Settings
        TXT_SET_TITLE="系统设置"
        TXT_SET_1="修改注册邮箱 (同步更新账户)"
        TXT_SET_2="切换语言 (Change Language)"
        TXT_SET_3="切换默认 CA"
        TXT_SET_4="切换密钥类型"
        TXT_SET_5="强制更新 acme.sh"
        TXT_SET_6="更新/修复 快捷启动命令"
        TXT_SET_UPDATED="设置已更新。"
        
        # Uninstall
        TXT_UN_TITLE="卸载选项"
        TXT_UN_1="仅删除脚本配置 & 快捷方式"
        TXT_UN_2="彻底卸载 (移除 acme.sh + 证书 + 本脚本)"
        TXT_UN_CONFIRM="输入 'DELETE' 确认彻底卸载: "
        TXT_UN_DONE="已卸载。"
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
        read -p "Input / 输入 [1-2]: " lang_opt
        if [ "$lang_opt" == "2" ]; then
            LANG_SET="en"
        else
            LANG_SET="cn"
        fi
        save_config
    fi
    load_language_strings
}

# ==============================================================
# 3. Core Functionality / 核心功能
# ==============================================================

setup_shortcut() {
    echo -e "${YELLOW}${TXT_SC_CREATE}${PLAIN}"
    
    # [优化逻辑] 检测是否为在线运行 (Curl模式下 $0 通常不是普通文件)
    if [ -z "$CURRENT_SCRIPT_PATH" ] || [ ! -f "$CURRENT_SCRIPT_PATH" ]; then
        echo -e "${RED}${TXT_SC_FAIL_ONLINE}${PLAIN}"
        echo -e "${YELLOW}${TXT_SC_FAIL_HINT}${PLAIN}"
        echo -e "Example: wget https://your-script-url.com/acme-super.sh && bash acme-super.sh"
        read -p "${TXT_PRESS_ENTER}"
        return
    fi

    # 清理旧快捷方式
    if [ -n "$SHORTCUT_NAME" ] && [ -f "/usr/bin/$SHORTCUT_NAME" ]; then
        rm -f "/usr/bin/$SHORTCUT_NAME"
    fi

    read -p "${TXT_SC_ASK}" input_name
    if [ -z "$input_name" ]; then
        SHORTCUT_NAME="ssl"
    else
        # 校验快捷键名称安全性
        if [[ ! "$input_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
             echo -e "${RED}Invalid name.${PLAIN}"
             return
        fi
        SHORTCUT_NAME="$input_name"
    fi

    # 创建快捷方式
    cat > "/usr/bin/$SHORTCUT_NAME" <<EOF
#!/bin/bash
bash "$CURRENT_SCRIPT_PATH"
EOF
    chmod +x "/usr/bin/$SHORTCUT_NAME"
    save_config
    
    echo -e "${GREEN}${TXT_SC_SUCCESS}${CYAN}$SHORTCUT_NAME${PLAIN}"
}

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
        echo -e "${RED}Error: Unknown Package Manager.${PLAIN}"
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
            echo -e "${YELLOW}${TXT_INSTALLING_DEP}$dep ...${PLAIN}"
            $install_cmd $dep
        fi
    done
    
    # 确保 cron 服务运行
    if [[ -n $(command -v systemctl) ]]; then
        if ! systemctl is-active --quiet cron && ! systemctl is-active --quiet crond; then
             systemctl start cron || systemctl start crond
        fi
    fi
}

register_accounts_logic() {
    local email=$1
    [ -z "$email" ] && return
    echo -e "${YELLOW}>>> ${TXT_ACC_SYNC}${PLAIN}"
    "$ACME_SH" --register-account -m "$email" --server letsencrypt --output-insecure >/dev/null 2>&1
    "$ACME_SH" --register-account -m "$email" --server zerossl --output-insecure >/dev/null 2>&1
}

install_acme_sh() {
    if [ -f "$ACME_SH" ]; then
        echo -e "${GREEN}${TXT_ACME_EXIST}${PLAIN}"
    else
        echo -e "${CYAN}${TXT_ACME_INSTALLING}${PLAIN}"
        
        while true; do
            if [ -z "$USER_EMAIL" ]; then
                read -p "${TXT_INPUT_EMAIL}" input_email
                USER_EMAIL="$input_email"
            fi
            
            if [[ "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                save_config
                break
            else
                echo -e "${RED}${TXT_EMAIL_INVALID}${PLAIN}"
                USER_EMAIL=""
            fi
        done
        
        curl https://get.acme.sh | sh -s email="$USER_EMAIL"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}Curl failed, trying git...${PLAIN}"
            ! command -v git &> /dev/null && echo "Error: Git not found." && return
            git clone https://github.com/acmesh-official/acme.sh.git ~/.acme.sh
            cd ~/.acme.sh || exit
            ./acme.sh --install -m "$USER_EMAIL"
            cd ..
        fi
    fi
    
    load_config
    register_accounts_logic "$USER_EMAIL"
    "$ACME_SH" --set-default-ca --server "$CA_SERVER"
    "$ACME_SH" --upgrade --auto-upgrade
    save_config
    
    # 引导创建快捷方式
    if [ -z "$SHORTCUT_NAME" ]; then
        setup_shortcut
    fi
    
    echo -e "${GREEN}${TXT_INIT_SUCCESS}${PLAIN}"
}

# ==============================================================
# 4. Issue & Install / 签发与部署
# ==============================================================

issue_http() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    
    echo -e "${YELLOW}>>> HTTP Mode${PLAIN}"
    read -p "${TXT_INPUT_DOMAIN}" DOMAIN
    check_valid_domain "$DOMAIN" || return

    echo -e "${TXT_HTTP_MODE_SEL}"
    echo -e "${TXT_HTTP_STANDALONE}"
    echo -e "${TXT_HTTP_NGINX}"
    echo -e "${TXT_HTTP_APACHE}"
    echo -e "${TXT_HTTP_WEBROOT}"
    read -p "${TXT_SELECT}" MODE

    local cmd_flags=""
    case $MODE in
        1) 
            if command -v netstat &>/dev/null && netstat -tuln | grep -q ":80 "; then
                echo -e "${RED}${TXT_PORT_80_WARN}${PLAIN}"
                read -p "${TXT_CONTINUE_ASK}" cont
                [[ "$cont" != "y" ]] && return
            fi
            cmd_flags="--standalone" 
            ;;
        2) cmd_flags="--nginx" ;;
        3) cmd_flags="--apache" ;;
        4) 
            read -p "${TXT_INPUT_WEBROOT}" webroot
            check_path_safety "$webroot" || return
            [ ! -d "$webroot" ] && echo -e "${RED}Path not found.${PLAIN}" && return
            cmd_flags="--webroot $webroot"
            ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; return ;;
    esac

    echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
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

    echo -e "${YELLOW}>>> DNS API Mode${PLAIN}"
    read -p "${TXT_INPUT_DOMAIN}" DOMAIN
    check_valid_domain "$DOMAIN" || return

    echo -e "${TXT_DNS_SEL}"
    echo -e "1. CloudFlare"
    echo -e "2. LuaDNS"
    echo -e "3. Hurricane Electric (he.net)"
    echo -e "4. ClouDNS"
    echo -e "5. PowerDNS"
    echo -e "6. 1984Hosting"
    echo -e "7. deSEC.io"
    echo -e "8. dynv6"
    echo -e "9. ${TXT_DNS_MANUAL}"
    echo -e "0. Back"
    read -p "${TXT_SELECT}" DNS_OPT

    # Clear ENV
    unset CF_Key CF_Email LUA_Key LUA_Email HE_Username HE_Password CLOUDNS_AUTH_ID CLOUDNS_SUB_AUTH_ID CLOUDNS_AUTH_PASSWORD PDNS_Url PDNS_ServerId PDNS_Token PDNS_Ttl One984_Username One984_Password DEDYN_TOKEN DYNV6_TOKEN

    local dns_type=""
    case $DNS_OPT in
        1)
            read -p "CloudFlare Global API Key: " CF_Key
            read -p "CloudFlare Email: " CF_Email
            export CF_Key="$CF_Key"
            export CF_Email="$CF_Email"
            dns_type="dns_cf"
            ;;
        2)
            read -p "LuaDNS API Key: " LUA_Key
            read -p "LuaDNS Email: " LUA_Email
            export LUA_Key="$LUA_Key"
            export LUA_Email="$LUA_Email"
            dns_type="dns_lua"
            ;;
        3)
            read -p "HE.net Username: " HE_Username
            read -p "HE.net Password: " HE_Password
            export HE_Username="$HE_Username"
            export HE_Password="$HE_Password"
            dns_type="dns_he"
            ;;
        4)
            read -p "ClouDNS Auth ID: " CLOUDNS_AUTH_ID
            read -p "ClouDNS Sub Auth ID (Opt): " CLOUDNS_SUB_AUTH_ID
            read -p "ClouDNS Password: " CLOUDNS_AUTH_PASSWORD
            export CLOUDNS_AUTH_ID="$CLOUDNS_AUTH_ID"
            export CLOUDNS_SUB_AUTH_ID="$CLOUDNS_SUB_AUTH_ID"
            export CLOUDNS_AUTH_PASSWORD="$CLOUDNS_AUTH_PASSWORD"
            dns_type="dns_cloudns"
            ;;
        5)
            read -p "PowerDNS URL: " PDNS_Url
            read -p "PowerDNS ServerId: " PDNS_ServerId
            read -p "PowerDNS Token: " PDNS_Token
            read -p "PowerDNS TTL (60): " PDNS_Ttl
            export PDNS_Url="$PDNS_Url"
            export PDNS_ServerId="$PDNS_ServerId"
            export PDNS_Token="$PDNS_Token"
            export PDNS_Ttl="${PDNS_Ttl:-60}"
            dns_type="dns_pdns"
            ;;
        6)
            read -p "1984Hosting Username: " One984_Username
            read -p "1984Hosting Password: " One984_Password
            export One984_Username="$One984_Username"
            export One984_Password="$One984_Password"
            dns_type="dns_1984hosting"
            ;;
        7)
            read -p "deSEC.io Token: " DEDYN_TOKEN
            export DEDYN_TOKEN="$DEDYN_TOKEN"
            dns_type="dns_desec"
            ;;
        8)
            read -p "dynv6 Token: " DYNV6_TOKEN
            export DYNV6_TOKEN="$DYNV6_TOKEN"
            dns_type="dns_dynv6"
            ;;
        9)
            echo -e "${YELLOW}ENV (Key=Value), type 'end' to finish.${PLAIN}"
            while true; do
                read -p "ENV > " env_in
                [[ "$env_in" == "end" ]] && break
                # 简单校验环境变量名
                if [[ "$env_in" =~ ^[a-zA-Z0-9_]+=[a-zA-Z0-9_.-]+$ ]]; then
                    export "$env_in"
                else
                     echo "Format ignored. Use KEY=VALUE"
                fi
            done
            read -p "Plugin Name (e.g. dns_ali): " dns_type
            ;;
        0) return ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; return ;;
    esac
    
    [ -z "$dns_type" ] && return

    echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
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
        read -p "${TXT_INS_DOMAIN}" DOMAIN
    else
        DOMAIN=$default_domain
    fi
    check_valid_domain "$DOMAIN" || return
    
    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}Error: Cert not found for $DOMAIN${PLAIN}"
        return
    fi

    read -p "${TXT_INS_CERT_PATH}" CERT_PATH
    read -p "${TXT_INS_KEY_PATH}" KEY_PATH
    read -p "${TXT_INS_CA_PATH}" CA_PATH
    read -p "${TXT_INS_RELOAD}" RELOAD_CMD

    check_path_safety "$CERT_PATH" || return
    check_path_safety "$KEY_PATH" || return
    check_path_safety "$CA_PATH" || return

    local cmd_build="$ACME_SH --install-cert -d $DOMAIN"
    [[ "$KEY_LENGTH" == "ec"* ]] && cmd_build="$cmd_build --ecc"

    [ -n "$CERT_PATH" ] && cmd_build="$cmd_build --cert-file $CERT_PATH"
    [ -n "$KEY_PATH" ] && cmd_build="$cmd_build --key-file $KEY_PATH"
    [ -n "$CA_PATH" ] && cmd_build="$cmd_build --fullchain-file $CA_PATH"
    [ -n "$RELOAD_CMD" ] && cmd_build="$cmd_build --reloadcmd \"$RELOAD_CMD\""

    eval "$cmd_build"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_INS_SUCCESS}${PLAIN}"
    else
        echo -e "${RED}Install Failed.${PLAIN}"
    fi
}

# ==============================================================
# 5. Settings & Maintenance / 设置与维护
# ==============================================================

settings_menu() {
    while true; do
        echo -e "${CYAN}===== ${TXT_SET_TITLE} =====${PLAIN}"
        echo "1. ${TXT_SET_1}"
        echo "2. ${TXT_SET_2}"
        echo "3. ${TXT_SET_3}"
        echo "4. ${TXT_SET_4}"
        echo "5. ${TXT_SET_5}"
        echo "6. ${TXT_SET_6}"
        echo "0. ${TXT_M_0}"
        read -p "${TXT_SELECT}" choice
        
        case $choice in
            1)
                read -p "${TXT_INPUT_EMAIL}" new_email
                if [[ "$new_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    USER_EMAIL="$new_email"
                    save_config
                    register_accounts_logic "$USER_EMAIL"
                else
                    echo -e "${RED}${TXT_EMAIL_INVALID}${PLAIN}"
                fi
                ;;
            2)
                if [ "$LANG_SET" == "cn" ]; then LANG_SET="en"; else LANG_SET="cn"; fi
                save_config
                load_language_strings
                ;;
            3)
                echo "1. Let's Encrypt"
                echo "2. ZeroSSL"
                read -p "${TXT_SELECT}" ca_opt
                case $ca_opt in
                    1) CA_SERVER="letsencrypt" ;;
                    2) CA_SERVER="zerossl" ;;
                    *) CA_SERVER="letsencrypt" ;;
                esac
                [ -f "$ACME_SH" ] && "$ACME_SH" --set-default-ca --server "$CA_SERVER"
                save_config
                ;;
            4)
                echo "1. RSA-2048"
                echo "2. ECC-256"
                read -p "${TXT_SELECT}" key_opt
                case $key_opt in
                    1) KEY_LENGTH="2048" ;;
                    2) KEY_LENGTH="ec-256" ;;
                    *) KEY_LENGTH="2048" ;;
                esac
                save_config
                ;;
            5) [ -f "$ACME_SH" ] && "$ACME_SH" --upgrade ;;
            6) setup_shortcut ;;
            0) return ;;
        esac
        echo -e "${GREEN}${TXT_SET_UPDATED}${PLAIN}"
    done
}

manage_certs() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    
    while true; do
        echo -e "${CYAN}===== ${TXT_M6_TITLE} =====${PLAIN}"
        
        # [优化逻辑] 捕获输出并替换表头为中文
        raw_output=$("$ACME_SH" --list)
        
        if [ "$LANG_SET" == "cn" ]; then
             if [[ -z "$raw_output" ]]; then
                echo -e "${YELLOW}${TXT_M6_EMPTY}${PLAIN}"
             else
                # 使用 sed 替换表头关键字
                # Main_Domain -> 主域名
                # KeyLength   -> 密钥长度
                # SAN_Domains -> SAN域名
                # Profile     -> 配置文件
                # CA          -> CA提供商
                # Created     -> 创建时间
                # Renew       -> 续期时间
                echo "$raw_output" | sed \
                    -e 's/Main_Domain/主域名/g' \
                    -e 's/KeyLength/密钥长度/g' \
                    -e 's/SAN_Domains/SAN域名/g' \
                    -e 's/Profile/配置文件/g' \
                    -e 's/CA /CA厂商 /g' \
                    -e 's/Created/创建时间/g' \
                    -e 's/Renew/续期时间/g' | \
                    awk 'BEGIN {OFS="\t"} {print $0}' # 简单格式化
             fi
        else
             echo "$raw_output"
        fi

        echo "------------------------"
        echo "1. ${TXT_M6_RENEW}"
        echo "2. ${TXT_M6_REVOKE}"
        echo "0. ${TXT_M_0}"
        read -p "${TXT_SELECT}" choice
        case $choice in
            1)
                read -p "${TXT_M6_INPUT_RENEW}" d
                check_valid_domain "$d" && "$ACME_SH" --renew -d "$d" --force
                ;;
            2)
                read -p "${TXT_M6_INPUT_DEL}" d
                if [ -n "$d" ]; then
                    check_valid_domain "$d" || continue
                    read -p "${TXT_M6_CONFIRM_DEL}" c
                    if [ "$c" == "y" ]; then
                        "$ACME_SH" --revoke -d "$d"
                        "$ACME_SH" --remove -d "$d"
                        rm -rf "$ACME_DIR/$d" "$ACME_DIR/${d}_ecc"
                        echo -e "${GREEN}${TXT_M6_DELETED}${PLAIN}"
                    fi
                fi
                ;;
            0) return ;;
        esac
    done
}

uninstall_menu() {
    echo -e "${RED}===== ${TXT_UN_TITLE} =====${PLAIN}"
    echo "1. ${TXT_UN_1}"
    echo "2. ${TXT_UN_2}"
    read -p "${TXT_SELECT}" opt
    
    if [ "$opt" == "1" ]; then
        # Delete Config & Shortcut
        rm -f "$CONFIG_FILE"
        [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
        echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"
        exit 0
    elif [ "$opt" == "2" ]; then
        read -p "${TXT_UN_CONFIRM}" confirm
        if [ "$confirm" == "DELETE" ]; then
            [ -f "$ACME_SH" ] && "$ACME_SH" --uninstall
            rm -rf "$ACME_DIR" "$CONFIG_FILE"
            # Self delete logic if local
            if [ -f "$CURRENT_SCRIPT_PATH" ]; then
                rm -f "$CURRENT_SCRIPT_PATH"
            fi
            [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
            echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"
            exit 0
        fi
    fi
}

# ==============================================================
# 6. Main Entry / 主入口
# ==============================================================

show_menu() {
    clear
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${BLUE}           ${TXT_TITLE}           ${PLAIN}"
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${TXT_STATUS_LABEL}: CA: ${GREEN}${CA_SERVER}${PLAIN} | Key: ${GREEN}${KEY_LENGTH}${PLAIN} | ${TXT_EMAIL_LABEL}: ${GREEN}${USER_EMAIL:-${TXT_NOT_SET}}${PLAIN}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"

    if [ ! -f "$ACME_SH" ]; then
        echo -e "${RED}${TXT_HINT_INSTALL}${PLAIN}"
    fi

    echo -e " 1. ${TXT_M_1}"
    echo -e " 2. ${TXT_M_2}"
    echo -e "--------------------------------------------------------------"
    echo -e " 3. ${TXT_M_3}"
    echo -e " 4. ${TXT_M_4}"
    echo -e " 5. ${TXT_M_5}"
    echo -e "--------------------------------------------------------------"
    echo -e " 6. ${TXT_M_6}"
    echo -e " 7. ${TXT_M_7}"
    echo -e " 0. ${TXT_M_0}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"
    read -p " ${TXT_SELECT}" num

    case $num in
        1) check_dependencies && install_acme_sh ;;
        2) settings_menu ;;
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
