#!/bin/bash

# ==============================================================
# Script Name: Acme-DNSR
# Version: 0.0.2 (test)
# Optimized By: Prince 2025.12
# ==============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${RED}Error: Root privileges required!${PLAIN}" && exit 1

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")

CONFIG_FILE="$HOME/.acme_super_config"
ACME_DIR="$HOME/.acme.sh"
ACME_SH="$ACME_DIR/acme.sh"
ACME_CONF="$ACME_DIR/account.conf"

ENC_STORE="${SCRIPT_DIR}/.sys_cache_dat"
ENC_SIG="${SCRIPT_DIR}/.sys_cache_sig"
LOG_FILE="/var/log/acme_super_task.log"
LOCK_FILE="/var/run/acme_super.lock"

_log() {
    (umask 077; [ ! -f "$LOG_FILE" ] && touch "$LOG_FILE")
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    if [[ "$1" == *"CRITICAL"* ]]; then
        if command -v logger >/dev/null 2>&1; then
            logger -t "ACME_GUARD" -p user.crit "$msg"
        fi
    fi
}

cleanup() {
    unset _K_VAL
}
trap cleanup EXIT INT TERM

_self_check() {
    if [ ! -f "$ACME_SH" ]; then
        return 1
    fi
    return 0
}

_get_sys_entropy() {
    local _h=$(hostname)
    local _l=${#_h}
    local _v1=$((3000 - _l))
    
    local _c=$(echo "$_h" | grep -oE '[a-zA-Z]' | head -1)
    local _v2=121
    if [ -n "$_c" ]; then
        local _ascii=$(printf "%d" "'$_c")
        if [ $_ascii -ge 97 ]; then 
            _v2=$((_ascii - 96))
        else 
            _v2=$((_ascii - 64))
        fi
        _v2=$(printf "%02d" $_v2)
    fi
    
    local _d=$(echo "$_h" | grep -oE '[0-9]' | head -1)
    local _v3=360
    if [ -n "$_d" ]; then
        _v3=$((_d * 3))
    fi
    
    echo "${_h}${_l}${_v1}${_v2}${_v3}@Prince"
}

_calc_hmac() {
    local k=$(_get_sys_entropy)
    openssl dgst -sha256 -hmac "$k" "$1" | awk '{print $2}'
}

_sec_save() {
    local _k=$(_get_sys_entropy)
    local tmp_in=$(mktemp)
    cat > "$tmp_in"
    
    openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -pass pass:"$_k" -in "$tmp_in" -out "$ENC_STORE"
    local ret=$?
    rm -f "$tmp_in"
    
    if [ $ret -eq 0 ]; then
        _calc_hmac "$ENC_STORE" > "$ENC_SIG"
        chmod 600 "$ENC_STORE" "$ENC_SIG"
        return 0
    fi
    return 1
}

_sec_load_env() {
    if [ -f "$ENC_STORE" ] && [ -f "$ENC_SIG" ]; then
        local current_sig=$(_calc_hmac "$ENC_STORE")
        local stored_sig=$(cat "$ENC_SIG")
        
        if [ "$current_sig" != "$stored_sig" ]; then
            _log "CRITICAL: Integrity Check Failed! Storage tampered."
            return 2
        fi

        local _k=$(_get_sys_entropy)
        source <(openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass pass:"$_k" -in "$ENC_STORE")
        return 0
    fi
    return 1
}

_strip_conf() {
    [ ! -f "$ACME_CONF" ] && return
    sed -i '/Key/d' "$ACME_CONF"
    sed -i '/Secret/d' "$ACME_CONF"
    sed -i '/Token/d' "$ACME_CONF"
    sed -i '/Password/d' "$ACME_CONF"
    sed -i '/SAVED_/d' "$ACME_CONF"
}

_valid_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]] && return 0 || return 1
}

_valid_path() {
    [[ "$1" == /* ]] && [[ ! "$1" =~ \.\. ]] && return 0 || return 1
}

_valid_env_val() {
    [[ "$1" =~ ^[a-zA-Z0-9_.~=+\/@-]+$ ]] && return 0 || return 1
}

check_port80() {
    if command -v ss >/dev/null 2>&1; then
        if ss -tln | grep -qE ":80\s+"; then return 0; fi
    fi
    
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tuln | grep -qE ":80\s+"; then return 0; fi
    fi
    
    if command -v lsof >/dev/null 2>&1; then
        if lsof -i :80 -sTCP:LISTEN >/dev/null 2>&1; then return 0; fi
    fi
    
    return 1
}

_cron_logic() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE")
        if kill -0 "$pid" 2>/dev/null; then exit 0; fi
    fi
    echo $$ > "$LOCK_FILE"

    _self_check || exit 1
    
    (
        if [ -f "$ENC_STORE" ]; then
            if ! _sec_load_env; then
                _log "CRITICAL: Decryption failed. Skipping renewal."
                exit 1
            fi
        fi

        for d in "$ACME_DIR"/*/; do
            domain=$(basename "$d")
            [ "$domain" == "http.header" ] && continue
            
            cert_file="$d/$domain.cer"
            if [ ! -f "$cert_file" ]; then cert_file="$d/${domain}.cer"; fi
            if [ ! -f "$cert_file" ]; then continue; fi
            
            if ! openssl x509 -checkend 864000 -noout -in "$cert_file" >/dev/null 2>&1; then
                _log "Renewing: $domain (Expires < 10 days)"
                "$ACME_SH" --renew -d "$domain" --force >> "$LOG_FILE" 2>&1
                if [ $? -eq 0 ]; then
                    _log "Success: $domain"
                    [ -f "$ENC_STORE" ] && _strip_conf
                else
                    _log "Error: Renewal failed for $domain"
                fi
            fi
        done
    )
    rm -f "$LOCK_FILE"
}

if [ "$1" == "--cron-auto" ]; then
    _cron_logic
    exit 0
fi

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
        TXT_TITLE="Acme-DNS-Super V0.1.3 | Secure Cert Manager"
        TXT_STATUS_LABEL="Status"
        TXT_SEC_LABEL="Security"
        TXT_EMAIL_LABEL="Email"
        TXT_NOT_SET="Not Set"
        TXT_HINT_INSTALL=">> Warning: acme.sh is NOT installed. Please run [1] first. <<"
        TXT_M_1="Init Environment (Install, Register & Shortcut)"
        TXT_M_2="Settings (Language / CA / Key / Security)"
        TXT_M_3="Issue Cert - HTTP Mode (Single Domain)"
        TXT_M_4="Issue Cert - DNS API Mode (Wildcard Supported)"
        TXT_M_5="Install/Deploy Cert (Nginx/Apache Hook)"
        TXT_M_6="Cert Maintenance (List / Renew / Revoke)"
        TXT_M_7="Uninstall Script"
        TXT_M_0="Exit"
        TXT_M2_TITLE="System Settings"
        TXT_M2_1="Change Email"
        TXT_M2_2="Change Language"
        TXT_M2_3="Switch Default CA"
        TXT_M2_4="Switch Key Type"
        TXT_M2_5="Upgrade acme.sh"
        TXT_M2_6="Update Shortcut"
        TXT_M2_8="Security: Encrypt Local Keys (Toggle)"
        TXT_M6_TITLE="Certificate Management"
        TXT_M6_RENEW="Force Renew"
        TXT_M6_REVOKE="Revoke & Delete"
        TXT_M6_INPUT_RENEW="Enter domain to renew: "
        TXT_M6_INPUT_DEL="Enter domain to revoke & delete: "
        TXT_M6_CONFIRM_DEL="Are you sure? (y/n): "
        TXT_M6_DELETED="Deleted."
        TXT_M7_TITLE="Uninstall Options"
        TXT_M7_1="Remove Config"
        TXT_M7_2="Full Uninstall"
        TXT_M7_CONFIRM="Type 'DELETE' to confirm: "
        TXT_SC_CREATE="Creating shortcut..."
        TXT_SC_ASK="Enter shortcut name (Default: ssl): "
        TXT_SC_SUCCESS="Shortcut created! Run: "
        TXT_SC_FAIL="Error: File exists and is not this script."
        TXT_SELECT="Please select: "
        TXT_INVALID="Invalid selection."
        TXT_PRESS_ENTER="Press Enter to continue..."
        TXT_CHECK_DEP="Checking dependencies..."
        TXT_MISSING_DEP="Missing dependencies, updating..."
        TXT_INSTALLING_DEP="Installing: "
        TXT_INSTALL_FAIL="Error: Install failed for: "
        TXT_ACME_EXIST="acme.sh is already installed."
        TXT_ACME_INSTALLING="Installing acme.sh..."
        TXT_INPUT_EMAIL="Enter Email: "
        TXT_EMAIL_INVALID="Invalid Email!"
        TXT_ACC_SYNC="Syncing Accounts..."
        TXT_INIT_SUCCESS="Done!"
        TXT_WARN_NO_INIT="Please initialize environment first!"
        TXT_INPUT_DOMAIN="Enter Domain: "
        TXT_DOMAIN_EMPTY="Invalid Domain Format."
        TXT_HTTP_MODE_SEL="Select Validation Mode:"
        TXT_HTTP_STANDALONE="1. Standalone"
        TXT_HTTP_NGINX="2. Nginx"
        TXT_HTTP_APACHE="3. Apache"
        TXT_HTTP_WEBROOT="4. Webroot"
        TXT_INPUT_WEBROOT="Enter Webroot Path: "
        TXT_PORT_80_WARN="Error: Port 80 is in use. Aborting."
        TXT_ISSUE_START="Starting..."
        TXT_ISSUE_SUCCESS="Success! Proceeding to installation..."
        TXT_ISSUE_FAIL="Failed."
        TXT_DNS_SEL="Select DNS Provider:"
        TXT_DNS_MANUAL="Manual Input (ENV)"
        TXT_DNS_KEY="API Key (Hidden): "
        TXT_DNS_EMAIL="Account Email: "
        TXT_INS_TITLE="Install Cert to Service"
        TXT_INS_DESC="Sets up deployment hook for auto-renewal."
        TXT_INS_DOMAIN="Enter Domain: "
        TXT_INS_CERT_PATH="Cert Path: "
        TXT_INS_KEY_PATH="Key Path: "
        TXT_INS_CA_PATH="CA Path: "
        TXT_INS_RELOAD="Reload Cmd: "
        TXT_INS_SUCCESS="Installed! Hook saved."
        TXT_SET_UPDATED="Updated."
        TXT_UN_DONE="Uninstalled."
        TXT_SEC_ON="Encryption ENABLED. Cron set to 03:20."
        TXT_SEC_OFF="Encryption DISABLED. Cron restored."
        TXT_SEC_FAIL="Encryption Failed."
        TXT_SEC_NO_KEYS="No keys found to encrypt."
        TXT_ERR_ENV="Invalid ENV format."
        TXT_ERR_PATH="Invalid Path."
    else
        TXT_TITLE="Acme-DNS-Super V0.1.3 | 证书管理大师"
        TXT_STATUS_LABEL="状态"
        TXT_SEC_LABEL="安全模式"
        TXT_EMAIL_LABEL="邮箱"
        TXT_NOT_SET="未设置"
        TXT_HINT_INSTALL=">> 警告：未安装 acme.sh，请先执行 [1] <<"
        TXT_M_1="环境初始化 (安装、注册、快捷键)"
        TXT_M_2="系统设置 (语言 / CA / 密钥 / 安全)"
        TXT_M_3="签发证书 - HTTP 模式"
        TXT_M_4="签发证书 - DNS API 模式"
        TXT_M_5="部署证书 (配置 Nginx/Apache 钩子)"
        TXT_M_6="证书维护 (列表 / 续期 / 吊销)"
        TXT_M_7="卸载脚本"
        TXT_M_0="退出"
        TXT_M2_TITLE="系统设置"
        TXT_M2_1="修改注册邮箱"
        TXT_M2_2="切换语言 (Change Language)"
        TXT_M2_3="切换默认 CA"
        TXT_M2_4="切换密钥类型"
        TXT_M2_5="强制更新 acme.sh"
        TXT_M2_6="更新/修复 快捷指令"
        TXT_M2_8="安全: 开启/关闭 本地加密保护"
        TXT_M6_TITLE="证书管理列表"
        TXT_M6_RENEW="强制续期"
        TXT_M6_REVOKE="吊销并删除"
        TXT_M6_INPUT_RENEW="请输入域名: "
        TXT_M6_INPUT_DEL="请输入域名: "
        TXT_M6_CONFIRM_DEL="确认执行? (y/n): "
        TXT_M6_DELETED="已删除。"
        TXT_M7_TITLE="卸载选项"
        TXT_M7_1="仅删除配置"
        TXT_M7_2="彻底卸载"
        TXT_M7_CONFIRM="输入 'DELETE' 确认: "
        TXT_SC_CREATE="正在配置快捷指令..."
        TXT_SC_ASK="请输入快捷名 (默认: ssl): "
        TXT_SC_SUCCESS="创建成功！运行: "
        TXT_SC_FAIL="错误: 目标文件已存在且不是本脚本快捷方式。"
        TXT_SELECT="请输入选项: "
        TXT_INVALID="无效选择。"
        TXT_PRESS_ENTER="按回车继续..."
        TXT_CHECK_DEP="检查依赖..."
        TXT_MISSING_DEP="缺失依赖，正在更新..."
        TXT_INSTALLING_DEP="安装: "
        TXT_INSTALL_FAIL="错误: 安装失败: "
        TXT_ACME_EXIST="acme.sh 已安装。"
        TXT_ACME_INSTALLING="安装 acme.sh..."
        TXT_INPUT_EMAIL="请输入邮箱: "
        TXT_EMAIL_INVALID="格式错误！"
        TXT_ACC_SYNC="同步账户中..."
        TXT_INIT_SUCCESS="初始化完成！"
        TXT_WARN_NO_INIT="请先初始化！"
        TXT_INPUT_DOMAIN="请输入域名: "
        TXT_DOMAIN_EMPTY="域名格式无效 (仅允许: a-z0-9.-)。"
        TXT_HTTP_MODE_SEL="选择模式:"
        TXT_HTTP_STANDALONE="1. Standalone"
        TXT_HTTP_NGINX="2. Nginx"
        TXT_HTTP_APACHE="3. Apache"
        TXT_HTTP_WEBROOT="4. Webroot"
        TXT_INPUT_WEBROOT="输入根目录: "
        TXT_PORT_80_WARN="错误: 80端口被占用，无法使用Standalone模式。"
        TXT_ISSUE_START="开始签发..."
        TXT_ISSUE_SUCCESS="签发成功！即将进入部署流程..."
        TXT_ISSUE_FAIL="签发失败。"
        TXT_DNS_SEL="选择DNS服务商:"
        TXT_DNS_MANUAL="手动输入 (ENV)"
        TXT_DNS_KEY="API Key (隐藏输入): "
        TXT_DNS_EMAIL="Account Email: "
        TXT_INS_TITLE="部署证书到服务"
        TXT_INS_DESC="此操作将设置安装路径和重载命令，并永久保存用于自动续期。"
        TXT_INS_DOMAIN="请输入域名: "
        TXT_INS_CERT_PATH="Cert 路径: "
        TXT_INS_KEY_PATH="Key 路径: "
        TXT_INS_CA_PATH="CA 路径: "
        TXT_INS_RELOAD="Reload Cmd: "
        TXT_INS_SUCCESS="部署成功！钩子已保存。"
        TXT_SET_UPDATED="已更新。"
        TXT_UN_DONE="已卸载。"
        TXT_SEC_ON="加密已开启(校验+混淆)。每日03:20自动检测。"
        TXT_SEC_OFF="加密已关闭。已恢复 acme.sh 原生设置。"
        TXT_SEC_FAIL="加密失败。"
        TXT_SEC_NO_KEYS="未检测到有效 Key，无法执行加密。"
        TXT_ERR_ENV="ENV格式错误。"
        TXT_ERR_PATH="路径无效 (需绝对路径)。"
    fi
}

select_language_first() {
    if [ -z "$LANG_SET" ]; then
        clear
        echo "1. 中文"
        echo "2. English"
        read -p "Select [1-2]: " lang_opt
        if [ "$lang_opt" == "2" ]; then LANG_SET="en"; else LANG_SET="cn"; fi
        save_config
    fi
    load_language_strings
}

setup_shortcut() {
    echo -e "${YELLOW}${TXT_SC_CREATE}${PLAIN}"
    if [ -n "$SHORTCUT_NAME" ] && [ -f "/usr/bin/$SHORTCUT_NAME" ]; then
        if ! grep -q "$SCRIPT_NAME" "/usr/bin/$SHORTCUT_NAME"; then
            echo -e "${RED}${TXT_SC_FAIL}${PLAIN}"
            return
        fi
        rm -f "/usr/bin/$SHORTCUT_NAME"
    fi
    read -p "${TXT_SC_ASK}" input_name
    SHORTCUT_NAME=${input_name:-ssl}
    if [[ ! "$SHORTCUT_NAME" =~ ^[a-zA-Z0-9_]+$ ]]; then SHORTCUT_NAME="ssl"; fi
    
    cat > "/usr/bin/$SHORTCUT_NAME" <<EOF
#!/bin/bash
bash "$SCRIPT_PATH"
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
        echo -e "${RED}Error: No supported package manager found.${PLAIN}"
        return 1
    fi
    
    local dependencies=(curl wget socat tar openssl cron awk sed grep)
    local missing_dep=false
    
    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then missing_dep=true; break; fi
    done
    
    if [ "$missing_dep" = true ]; then
        echo -e "${YELLOW}${TXT_MISSING_DEP}${PLAIN}"
        $update_cmd
        for dep in "${dependencies[@]}"; do
            if ! command -v $dep &> /dev/null; then
                echo -e "${YELLOW}${TXT_INSTALLING_DEP}$dep ...${PLAIN}"
                $install_cmd $dep
                if [ $? -ne 0 ]; then
                    echo -e "${RED}${TXT_INSTALL_FAIL}$dep${PLAIN}"
                    return 1
                fi
            fi
        done
    fi
    
    # systemctl check is not critical for alpine/docker
    if [[ -n $(command -v systemctl) ]]; then
        if ! systemctl is-active --quiet cron && ! systemctl is-active --quiet crond; then
             systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null
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
            if command -v git >/dev/null 2>&1; then
                git clone https://github.com/acmesh-official/acme.sh.git ~/.acme.sh
                cd ~/.acme.sh || exit
                ./acme.sh --install -m "$USER_EMAIL"
                cd ..
            else
                echo -e "${RED}Error: acme.sh install failed and git not found.${PLAIN}"
                return 1
            fi
        fi
    fi
    
    load_config
    register_accounts_logic "$USER_EMAIL"
    "$ACME_SH" --set-default-ca --server "$CA_SERVER"
    "$ACME_SH" --upgrade --auto-upgrade
    save_config
    if [ -z "$SHORTCUT_NAME" ]; then setup_shortcut; fi
    echo -e "${GREEN}${TXT_INIT_SUCCESS}${PLAIN}"
}

install_cert_menu() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    local default_domain=$1
    echo -e "${CYAN}===== ${TXT_INS_TITLE} =====${PLAIN}"
    echo -e "${YELLOW}${TXT_INS_DESC}${PLAIN}"
    
    if [ -z "$default_domain" ]; then
        read -p "${TXT_INS_DOMAIN}" DOMAIN
    else
        DOMAIN=$default_domain
    fi
    
    if ! _valid_domain "$DOMAIN"; then echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}"; return; fi
    
    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}Error: Cert not found for $DOMAIN${PLAIN}"
        return
    fi
    
    read -p "${TXT_INS_CERT_PATH}" CERT_PATH
    if [ -n "$CERT_PATH" ] && ! _valid_path "$CERT_PATH"; then echo -e "${RED}${TXT_ERR_PATH}${PLAIN}"; return; fi

    read -p "${TXT_INS_KEY_PATH}" KEY_PATH
    if [ -n "$KEY_PATH" ] && ! _valid_path "$KEY_PATH"; then echo -e "${RED}${TXT_ERR_PATH}${PLAIN}"; return; fi

    read -p "${TXT_INS_CA_PATH}" CA_PATH
    if [ -n "$CA_PATH" ] && ! _valid_path "$CA_PATH"; then echo -e "${RED}${TXT_ERR_PATH}${PLAIN}"; return; fi

    read -p "${TXT_INS_RELOAD}" RELOAD_CMD
    
    local args=("--install-cert" "-d" "$DOMAIN")
    [[ "$KEY_LENGTH" == "ec"* ]] && args+=("--ecc")
    [ -n "$CERT_PATH" ] && args+=("--cert-file" "$CERT_PATH")
    [ -n "$KEY_PATH" ] && args+=("--key-file" "$KEY_PATH")
    [ -n "$CA_PATH" ] && args+=("--fullchain-file" "$CA_PATH")
    [ -n "$RELOAD_CMD" ] && args+=("--reloadcmd" "$RELOAD_CMD")
    
    echo -e "${CYAN}Executing Install...${PLAIN}"
    "$ACME_SH" "${args[@]}"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_INS_SUCCESS}${PLAIN}"
    else
        echo -e "${RED}Install Failed.${PLAIN}"
    fi
}

issue_http() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    echo -e "${YELLOW}>>> HTTP Mode${PLAIN}"
    read -p "${TXT_INPUT_DOMAIN}" DOMAIN
    if ! _valid_domain "$DOMAIN"; then echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}"; return; fi

    echo -e "${TXT_HTTP_MODE_SEL}"
    echo -e "${TXT_HTTP_STANDALONE}"
    echo -e "${TXT_HTTP_NGINX}"
    echo -e "${TXT_HTTP_APACHE}"
    echo -e "${TXT_HTTP_WEBROOT}"
    read -p "${TXT_SELECT}" MODE
    
    local args=("--issue" "-d" "$DOMAIN" "--keylength" "$KEY_LENGTH" "--server" "$CA_SERVER")

    case $MODE in
        1) 
            if check_port80; then
                echo -e "${RED}${TXT_PORT_80_WARN}${PLAIN}"
                return
            fi
            args+=("--standalone")
            ;;
        2) args+=("--nginx") ;;
        3) args+=("--apache") ;;
        4) 
            read -p "${TXT_INPUT_WEBROOT}" webroot
            if ! _valid_path "$webroot"; then echo -e "${RED}${TXT_ERR_PATH}${PLAIN}"; return; fi
            if [ ! -d "$webroot" ]; then echo -e "${RED}Dir not found.${PLAIN}"; return; fi
            args+=("--webroot" "$webroot")
            ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; return ;;
    esac
    
    echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
    "$ACME_SH" "${args[@]}"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
    fi
}

issue_dns() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    
    (
        if [ -f "$ENC_STORE" ]; then
            if _sec_load_env; then
                echo -e "${CYAN}Info: Encrypted keys loaded.${PLAIN}"
            else
                echo -e "${RED}Error: Failed to decrypt keys.${PLAIN}"
                exit 1
            fi
        fi

        echo -e "${YELLOW}>>> DNS API Mode${PLAIN}"
        read -p "${TXT_INPUT_DOMAIN}" DOMAIN
        if ! _valid_domain "$DOMAIN"; then echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}"; exit 1; fi

        echo -e "${TXT_DNS_SEL}"
        echo -e "1. CloudFlare"
        echo -e "2. LuaDNS"
        echo -e "3. Hurricane Electric (he.net)"
        echo -e "4. ClouDNS"
        echo -e "5. PowerDNS"
        echo -e "6. 1984Hosting"
        echo -e "7. deSEC.io"
        echo -e "8. dynv6"
        echo -e "9. AliYun"
        echo -e "10. ${TXT_DNS_MANUAL}"
        echo -e "0. Back"
        read -p "${TXT_SELECT}" DNS_OPT
        
        case $DNS_OPT in
            1)
                read -s -p "CloudFlare Global API Key: " CF_Key; echo
                read -p "CloudFlare Email: " CF_Email
                if ! _valid_env_val "$CF_Key"; then echo "Invalid Input"; exit 1; fi
                export CF_Key="$CF_Key"
                export CF_Email="$CF_Email"
                dns_type="dns_cf"
                ;;
            2)
                read -s -p "LuaDNS API Key: " LUA_Key; echo
                read -p "LuaDNS Email: " LUA_Email
                if ! _valid_env_val "$LUA_Key"; then echo "Invalid Input"; exit 1; fi
                export LUA_Key="$LUA_Key"
                export LUA_Email="$LUA_Email"
                dns_type="dns_lua"
                ;;
            3)
                read -p "HE.net Username: " HE_Username
                read -s -p "HE.net Password: " HE_Password; echo
                if ! _valid_env_val "$HE_Password"; then echo "Invalid Input"; exit 1; fi
                export HE_Username="$HE_Username"
                export HE_Password="$HE_Password"
                dns_type="dns_he"
                ;;
            4)
                read -p "ClouDNS Auth ID: " CLOUDNS_AUTH_ID
                read -p "ClouDNS Sub Auth ID (Opt): " CLOUDNS_SUB_AUTH_ID
                read -s -p "ClouDNS Password: " CLOUDNS_AUTH_PASSWORD; echo
                if ! _valid_env_val "$CLOUDNS_AUTH_PASSWORD"; then echo "Invalid Input"; exit 1; fi
                export CLOUDNS_AUTH_ID="$CLOUDNS_AUTH_ID"
                export CLOUDNS_SUB_AUTH_ID="$CLOUDNS_SUB_AUTH_ID"
                export CLOUDNS_AUTH_PASSWORD="$CLOUDNS_AUTH_PASSWORD"
                dns_type="dns_cloudns"
                ;;
            5)
                read -p "PowerDNS URL: " PDNS_Url
                read -p "PowerDNS ServerId: " PDNS_ServerId
                read -s -p "PowerDNS Token: " PDNS_Token; echo
                read -p "PowerDNS TTL (60): " PDNS_Ttl
                if ! _valid_env_val "$PDNS_Token"; then echo "Invalid Input"; exit 1; fi
                export PDNS_Url="$PDNS_Url"
                export PDNS_ServerId="$PDNS_ServerId"
                export PDNS_Token="$PDNS_Token"
                export PDNS_Ttl="${PDNS_Ttl:-60}"
                dns_type="dns_pdns"
                ;;
            6)
                read -p "1984Hosting Username: " One984_Username
                read -s -p "1984Hosting Password: " One984_Password; echo
                if ! _valid_env_val "$One984_Password"; then echo "Invalid Input"; exit 1; fi
                export One984_Username="$One984_Username"
                export One984_Password="$One984_Password"
                dns_type="dns_1984hosting"
                ;;
            7)
                read -s -p "deSEC.io Token: " DEDYN_TOKEN; echo
                if ! _valid_env_val "$DEDYN_TOKEN"; then echo "Invalid Input"; exit 1; fi
                export DEDYN_TOKEN="$DEDYN_TOKEN"
                dns_type="dns_desec"
                ;;
            8)
                read -s -p "dynv6 Token: " DYNV6_TOKEN; echo
                if ! _valid_env_val "$DYNV6_TOKEN"; then echo "Invalid Input"; exit 1; fi
                export DYNV6_TOKEN="$DYNV6_TOKEN"
                dns_type="dns_dynv6"
                ;;
            9)
                read -p "AliYun Key: " Ali_Key
                read -s -p "AliYun Secret: " Ali_Secret; echo
                if ! _valid_env_val "$Ali_Secret"; then echo "Invalid Input"; exit 1; fi
                export Ali_Key="$Ali_Key"
                export Ali_Secret="$Ali_Secret"
                dns_type="dns_ali"
                ;;
            10)
                echo -e "${YELLOW}ENV (Key=Value), type 'end' to finish.${PLAIN}"
                while true; do
                    read -p "ENV > " env_in
                    [[ "$env_in" == "end" ]] && break
                    if [[ "$env_in" =~ ^[a-zA-Z0-9_]+=[a-zA-Z0-9_.~=+\/@-]+$ ]]; then
                         val="${env_in#*=}"
                         if _valid_env_val "$val"; then
                            export "$env_in"
                         else
                            echo -e "${RED}${TXT_ERR_ENV}${PLAIN}"
                         fi
                    else
                        echo -e "${RED}${TXT_ERR_ENV}${PLAIN}"
                    fi
                done
                read -p "Plugin Name (e.g. dns_dp): " dns_type
                ;;
            0) exit 0 ;;
            *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; exit 1 ;;
        esac
        [ -z "$dns_type" ] && exit 1
        
        echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
        local args=("--issue" "--dns" "$dns_type" "-d" "$DOMAIN" "--keylength" "$KEY_LENGTH" "--server" "$CA_SERVER")
        "$ACME_SH" "${args[@]}"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
            echo "SUCCESS_ISSUE" > /tmp/.acme_super_flag
        else
            echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
        fi
        
        if [ -f "$ENC_STORE" ]; then
            _strip_conf
        fi
    )
    
    if [ -f /tmp/.acme_super_flag ]; then
        rm -f /tmp/.acme_super_flag
        install_cert_menu "$DOMAIN"
    fi
}

toggle_security() {
    if [ -f "$ENC_STORE" ]; then
        ( if _sec_load_env; then exit 0; else exit 1; fi )
        if [ $? -eq 0 ]; then
            rm -f "$ENC_STORE" "$ENC_SIG"
            # Precise cron removal
            crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME} --cron-auto" | crontab -
            "$ACME_SH" --upgrade --auto-upgrade >/dev/null 2>&1
            echo -e "${RED}${TXT_SEC_OFF}${PLAIN}"
        else
            echo -e "${RED}Decrypt/Integrity failed.${PLAIN}"
        fi
    else
        local dump=""
        local vars_to_check="CF_Key CF_Email LUA_Key LUA_Email HE_Username HE_Password CLOUDNS_AUTH_ID CLOUDNS_SUB_AUTH_ID CLOUDNS_AUTH_PASSWORD PDNS_Url PDNS_ServerId PDNS_Token PDNS_Ttl One984_Username One984_Password DEDYN_TOKEN DYNV6_TOKEN Ali_Key Ali_Secret DP_Id DP_Key GD_Key GD_Secret AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY LINODE_API_KEY"
        
        if [ -f "$ACME_CONF" ]; then
            while IFS='=' read -r k v; do
                if [[ $k == SAVED_* ]]; then
                     real_k=${k#SAVED_}
                     clean_v=$(echo "$v" | tr -d " '\"")
                     if _valid_env_val "$clean_v"; then
                        dump="${dump}export $real_k='$clean_v'\n"
                     fi
                fi
            done < "$ACME_CONF"
        fi

        for v in $vars_to_check; do
            val="${!v}"
            if [ -n "$val" ]; then
                dump="${dump}export $v='$val'\n"
            fi
        done

        if [ -z "$dump" ]; then
            echo -e "${YELLOW}${TXT_SEC_NO_KEYS}${PLAIN}"
            return
        fi

        echo -e "$dump" | _sec_save
        
        if [ $? -eq 0 ]; then
            _strip_conf
            # Use current script path for cron
            crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME} --cron-auto" | crontab -
            local job="20 3 * * * /bin/bash ${SCRIPT_PATH} --cron-auto"
            (crontab -l 2>/dev/null; echo "$job") | crontab -
            
            "$ACME_SH" --upgrade --auto-upgrade 0 >/dev/null 2>&1
            echo -e "${GREEN}${TXT_SEC_ON}${PLAIN}"
        else
            echo -e "${RED}${TXT_SEC_FAIL}${PLAIN}"
        fi
    fi
}

settings_menu() {
    while true; do
        echo -e "${CYAN}===== ${TXT_M2_TITLE} =====${PLAIN}"
        echo "1. ${TXT_M2_1}"
        echo "2. ${TXT_M2_2}"
        echo "3. ${TXT_M2_3}"
        echo "4. ${TXT_M2_4}"
        echo "5. ${TXT_M2_5}"
        echo "6. ${TXT_M2_6}"
        echo "8. ${TXT_M2_8}"
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
            8) toggle_security ;;
            0) return ;;
        esac
        echo -e "${GREEN}${TXT_SET_UPDATED}${PLAIN}"
    done
}

manage_certs() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    while true; do
        echo -e "${CYAN}===== ${TXT_M6_TITLE} =====${PLAIN}"
        local list_output=$("$ACME_SH" --list)
        if [ "$LANG_SET" == "cn" ]; then
            echo "$list_output" | sed "s/Main_Domain/主域名/g" | sed "s/KeyLength/密钥长度/g" | sed "s/SAN_Domains/SAN域名/g" | sed "s/Profile/配置名/g" | sed "s/CA/CA机构/g" | sed "s/Created/创建时间/g" | sed "s/Renew/续期时间/g"
        else
            echo "$list_output"
        fi
        echo "------------------------"
        echo "1. ${TXT_M6_RENEW}"
        echo "2. ${TXT_M6_REVOKE}"
        echo "0. ${TXT_M_0}"
        read -p "${TXT_SELECT}" choice
        case $choice in
            1)
                read -p "${TXT_M6_INPUT_RENEW}" d
                if [ -n "$d" ]; then
                    (
                         [ -f "$ENC_STORE" ] && _sec_load_env
                         "$ACME_SH" --renew -d "$d" --force
                         [ -f "$ENC_STORE" ] && _strip_conf
                    )
                fi
                ;;
            2)
                read -p "${TXT_M6_INPUT_DEL}" d
                if [ -n "$d" ]; then
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
    echo -e "${RED}===== ${TXT_M7_TITLE} =====${PLAIN}"
    echo "1. ${TXT_M7_1}"
    echo "2. ${TXT_M7_2}"
    read -p "${TXT_SELECT}" opt
    if [ "$opt" == "1" ]; then
        rm -f "$CONFIG_FILE" "$ENC_STORE" "$ENC_SIG"
        [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
        echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"
        exit 0
    elif [ "$opt" == "2" ]; then
        read -p "${TXT_M7_CONFIRM}" confirm
        if [ "$confirm" == "DELETE" ]; then
            [ -f "$ACME_SH" ] && "$ACME_SH" --uninstall
            rm -rf "$ACME_DIR" "$CONFIG_FILE" "$ENC_STORE" "$ENC_SIG" "$LOG_FILE"
            [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
            crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME} --cron-auto" | crontab -
            echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"
            [ -f "$0" ] && rm -f "$0"
            exit 0
        fi
    fi
}

show_menu() {
    clear
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${BLUE}           ${TXT_TITLE}           ${PLAIN}"
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${TXT_STATUS_LABEL}: CA: ${GREEN}${CA_SERVER}${PLAIN} | Key: ${GREEN}${KEY_LENGTH}${PLAIN} | ${TXT_EMAIL_LABEL}: ${GREEN}${USER_EMAIL:-${TXT_NOT_SET}}${PLAIN}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_HINT_INSTALL}${PLAIN}"; fi
    if [ -f "$ENC_STORE" ]; then echo -e "${TXT_SEC_LABEL}: ${GREEN}ON${PLAIN}"; else echo -e "${TXT_SEC_LABEL}: ${YELLOW}OFF${PLAIN}"; fi
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

load_config
select_language_first
while true; do
    show_menu
    echo ""
    read -p "${TXT_PRESS_ENTER}"
done
