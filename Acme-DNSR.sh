#!/bin/bash

# ==============================================================
# Script Name: Acme-DNSR
# Version: 0.0.2 (test)
# Optimized By: Prince 2025.10
# ==============================================================

# ==========================================
# Config & Globals
# ==========================================
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

# ==========================================
# Core Utilities
# ==========================================
_log() {
    (umask 077; [ ! -f "$LOG_FILE" ] && touch "$LOG_FILE")
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
    [[ "$1" == *"CRITICAL"* ]] && command -v logger >/dev/null 2>&1 && logger -t "ACME_GUARD" -p user.crit "$msg"
}

cleanup() { unset _K_VAL; }
trap cleanup EXIT INT TERM

_self_check() { [ -f "$ACME_SH" ]; }

_check_cmd() { command -v "$1" >/dev/null 2>&1; }

_ask_input() {
    local var_name="$1" prompt="$2" validator="$3" secure="$4"
    local input_val
    while true; do
        if [ "$secure" == "-s" ]; then read -s -p "${prompt} " input_val; echo; else read -p "${prompt} " input_val; fi
        if [ -n "$validator" ]; then
            if $validator "$input_val"; then eval "$var_name=\"$input_val\""; break; else echo -e "${RED}Invalid format.${PLAIN}"; fi
        else
            eval "$var_name=\"$input_val\""; break
        fi
    done
}

_ask_and_export() {
    local var="$1" prompt="$2" validator="${3:-_valid_env_val}" secure="$4"
    local val
    _ask_input val "$prompt" "$validator" "$secure"
    export $var="$val"
}

# ==========================================
# Security Logic
# ==========================================
_get_sys_entropy() {
    local _h=$(hostname) _l=${#_h} _v1=$((3000 - _l))
    local _c=$(echo "$_h" | grep -oE '[a-zA-Z]' | head -1)
    local _v2=121
    if [ -n "$_c" ]; then
        local _ascii=$(printf "%d" "'$_c")
        [ $_ascii -ge 97 ] && _v2=$((_ascii - 96)) || _v2=$((_ascii - 64))
        _v2=$(printf "%02d" $_v2)
    fi
    local _d=$(echo "$_h" | grep -oE '[0-9]' | head -1)
    local _v3=$(( ${_d:-0} * 3 + 360 ))
    echo "${_h}${_l}${_v1}${_v2}${_v3}@Prince"
}

_calc_hmac() { openssl dgst -sha256 -hmac "$(_get_sys_entropy)" "$1" | awk '{print $2}'; }

_sec_save() {
    local _k=$(_get_sys_entropy) tmp_in=$(mktemp)
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
        local cur_sig=$(_calc_hmac "$ENC_STORE")
        [ "$cur_sig" != "$(cat "$ENC_SIG")" ] && _log "CRITICAL: Integrity Check Failed!" && return 2
        local _k=$(_get_sys_entropy)
        source <(openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass pass:"$_k" -in "$ENC_STORE")
        return 0
    fi
    return 1
}

_strip_conf() {
    [ ! -f "$ACME_CONF" ] && return
    sed -i '/Key/d;/Secret/d;/Token/d;/Password/d;/SAVED_/d' "$ACME_CONF"
}

# ==========================================
# Validation & Checkers
# ==========================================
_valid_domain() { [[ "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; }
_valid_path() { [[ "$1" == /* ]] && [[ ! "$1" =~ \.\. ]]; }
_valid_env_val() { [[ "$1" =~ ^[a-zA-Z0-9_.~=+\/@-]+$ ]]; }

_port80_in_use() {
    _check_cmd ss && ss -tln | grep -qE ":80\s+" && return 0
    _check_cmd netstat && netstat -tuln | grep -qE ":80\s+" && return 0
    _check_cmd lsof && lsof -i :80 -sTCP:LISTEN >/dev/null 2>&1 && return 0
    return 1
}

check_dependencies() {
    echo -e "${CYAN}${TXT_CHECK_DEP}${PLAIN}"
    
    # 1. 确定包管理器并设置更新/安装命令
    local pm="" install_cmd="" update_cmd=""
    if _check_cmd apt-get; then
        pm="apt"; install_cmd="apt-get -y -q install"; update_cmd="apt-get -q update"
    elif _check_cmd yum; then
        pm="yum"; install_cmd="yum -y -q install"; update_cmd="yum -q makecache"
    elif _check_cmd apk; then
        pm="apk"; install_cmd="apk add --no-cache"; update_cmd="apk update"
    else
        echo -e "${RED}Error: No supported package manager (apt/yum/apk).${PLAIN}"; return 1
    fi

    # 2. 定义必须存在的二进制命令 (crontab 代表 cron 服务)
    local bin_deps=("curl" "wget" "socat" "tar" "openssl" "crontab" "awk" "sed" "grep")
    local missing_bin=false
    for bin in "${bin_deps[@]}"; do
        if ! _check_cmd "$bin"; then missing_bin=true; break; fi
    done

    # 3. 如果缺失，根据包管理器选择正确的包名进行安装
    if [ "$missing_bin" = true ]; then
        echo -e "${YELLOW}${TXT_MISSING_DEP}${PLAIN}"
        $update_cmd >/dev/null 2>&1
        
        # 定义需要安装的包列表 (根据发行版区分名称)
        local pkgs_to_install=("curl" "wget" "socat" "tar" "openssl" "sed" "grep")
        
        case $pm in
            apt)
                pkgs_to_install+=("cron" "gawk")
                ;;
            yum)
                # CentOS 需要 epel-release 才能装 socat
                if ! _check_cmd socat; then $install_cmd epel-release >/dev/null 2>&1; fi
                pkgs_to_install+=("cronie" "gawk")
                ;;
            apk)
                pkgs_to_install+=("dcron" "gawk")
                ;;
        esac
        
        echo -e "${CYAN}${TXT_INSTALLING_DEP}${pkgs_to_install[*]}...${PLAIN}"
        $install_cmd "${pkgs_to_install[@]}"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}${TXT_INSTALL_FAIL}Package installation error.${PLAIN}"
            return 1
        fi
    fi

    # 4. 再次检查，确保所有依赖已就绪
    for bin in "${bin_deps[@]}"; do
        if ! _check_cmd "$bin"; then
            echo -e "${RED}${TXT_INSTALL_FAIL}Command '$bin' not found after install.${PLAIN}"
            return 1
        fi
    done

    # 5. 确保 cron 服务启动
    if _check_cmd systemctl; then
        if ! systemctl is-active --quiet cron && ! systemctl is-active --quiet crond; then
             systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null
             systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null
        fi
    elif _check_cmd service; then
        service cron start 2>/dev/null || service crond start 2>/dev/null
    elif _check_cmd rc-service; then # Alpine
        rc-service crond start 2>/dev/null
    fi
    
    return 0
}

# ==========================================
# Cron Logic
# ==========================================
_cron_logic() {
    if [ -f "$LOCK_FILE" ] && kill -0 "$(cat "$LOCK_FILE")" 2>/dev/null; then exit 0; fi
    echo $$ > "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
    _self_check || exit 1
    
    (
        if [ -f "$ENC_STORE" ] && ! _sec_load_env; then
            _log "CRITICAL: Decryption failed. Skipping."
            exit 1
        fi

        for d in "$ACME_DIR"/*/; do
            domain=$(basename "$d")
            [ "$domain" == "http.header" ] && continue
            cert_file="$d/$domain.cer"; [ ! -f "$cert_file" ] && cert_file="$d/${domain}.cer"
            [ ! -f "$cert_file" ] && continue
            
            if ! openssl x509 -checkend 864000 -noout -in "$cert_file" >/dev/null 2>&1; then
                _log "Renewing: $domain"
                "$ACME_SH" --renew -d "$domain" --force >> "$LOG_FILE" 2>&1
                if [ $? -eq 0 ]; then
                    _log "Success: $domain"; [ -f "$ENC_STORE" ] && _strip_conf
                else
                    _log "Error: Renewal failed for $domain"
                fi
            fi
        done
    )
}

if [ "$1" == "--cron-auto" ]; then _cron_logic; exit 0; fi

# ==========================================
# Main Logic: Install & Config
# ==========================================
load_config() {
    if [ -f "$CONFIG_FILE" ]; then source "$CONFIG_FILE"; else
        CA_SERVER="letsencrypt"; KEY_LENGTH="2048"; USER_EMAIL=""; LANG_SET=""; SHORTCUT_NAME=""
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

setup_shortcut() {
    echo -e "${YELLOW}${TXT_SC_CREATE}${PLAIN}"
    [ -n "$SHORTCUT_NAME" ] && [ -f "/usr/bin/$SHORTCUT_NAME" ] && grep -vq "$SCRIPT_NAME" "/usr/bin/$SHORTCUT_NAME" && echo -e "${RED}${TXT_SC_FAIL}${PLAIN}" && return
    _ask_input SHORTCUT_NAME "${TXT_SC_ASK} (Default: ssl)" ""
    SHORTCUT_NAME=${SHORTCUT_NAME:-ssl}
    [[ ! "$SHORTCUT_NAME" =~ ^[a-zA-Z0-9_]+$ ]] && SHORTCUT_NAME="ssl"
    echo -e "#!/bin/bash\nbash \"$SCRIPT_PATH\"" > "/usr/bin/$SHORTCUT_NAME" && chmod +x "/usr/bin/$SHORTCUT_NAME"
    save_config
    echo -e "${GREEN}${TXT_SC_SUCCESS}${CYAN}$SHORTCUT_NAME${PLAIN}"
}

install_acme_sh() {
    [ -f "$ACME_SH" ] && echo -e "${GREEN}${TXT_ACME_EXIST}${PLAIN}" && return
    echo -e "${CYAN}${TXT_ACME_INSTALLING}${PLAIN}"
    
    while [[ ! "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
        read -p "${TXT_INPUT_EMAIL}" USER_EMAIL
    done
    
    # 尝试 curl 安装
    if ! curl https://get.acme.sh | sh -s email="$USER_EMAIL"; then
        # 如果 curl 失败，尝试 git 安装
        if _check_cmd git; then
            git clone https://github.com/acmesh-official/acme.sh.git ~/.acme.sh && cd ~/.acme.sh && ./acme.sh --install -m "$USER_EMAIL" && cd ..
        else
            echo -e "${RED}Error: Install failed (curl error) & git not found.${PLAIN}"
            return 1
        fi
    fi
    
    # 检查是否安装成功
    if [ ! -f "$ACME_SH" ]; then
         echo -e "${RED}Error: acme.sh install failed (File not found).${PLAIN}"
         return 1
    fi
    
    load_config; save_config
    echo -e "${YELLOW}>>> ${TXT_ACC_SYNC}${PLAIN}"
    "$ACME_SH" --register-account -m "$USER_EMAIL" --server letsencrypt --output-insecure >/dev/null 2>&1
    "$ACME_SH" --register-account -m "$USER_EMAIL" --server zerossl --output-insecure >/dev/null 2>&1
    "$ACME_SH" --set-default-ca --server "$CA_SERVER"
    "$ACME_SH" --upgrade --auto-upgrade
    [ -z "$SHORTCUT_NAME" ] && setup_shortcut
    echo -e "${GREEN}${TXT_INIT_SUCCESS}${PLAIN}"
}

_post_issue_install() {
    local domain=$1
    echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
    install_cert_menu "$domain"
}

_post_issue_cleanup() {
    [ -f "$ENC_STORE" ] && _strip_conf
}

# ==========================================
# Operations: Issue & Deploy
# ==========================================
install_cert_menu() {
    [ ! -f "$ACME_SH" ] && echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}" && return
    local DOMAIN=$1
    echo -e "${CYAN}===== ${TXT_INS_TITLE} =====${PLAIN}\n${YELLOW}${TXT_INS_DESC}${PLAIN}"
    
    [ -z "$DOMAIN" ] && _ask_input DOMAIN "${TXT_INS_DOMAIN}" "_valid_domain"
    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}Error: Cert not found for $DOMAIN${PLAIN}"; return
    fi
    
    local cert_p key_p ca_p reload_cmd
    _ask_input cert_p "${TXT_INS_CERT_PATH}" "_valid_path"
    _ask_input key_p "${TXT_INS_KEY_PATH}" "_valid_path"
    _ask_input ca_p "${TXT_INS_CA_PATH}" "_valid_path"
    read -p "${TXT_INS_RELOAD}" reload_cmd
    
    local args=("--install-cert" "-d" "$DOMAIN")
    [[ "$KEY_LENGTH" == "ec"* ]] && args+=("--ecc")
    [ -n "$cert_p" ] && args+=("--cert-file" "$cert_p")
    [ -n "$key_p" ] && args+=("--key-file" "$key_p")
    [ -n "$ca_p" ] && args+=("--fullchain-file" "$ca_p")
    [ -n "$reload_cmd" ] && args+=("--reloadcmd" "$reload_cmd")
    
    echo -e "${CYAN}Executing Install...${PLAIN}"
    "$ACME_SH" "${args[@]}" && echo -e "${GREEN}${TXT_INS_SUCCESS}${PLAIN}" || echo -e "${RED}Install Failed.${PLAIN}"
}

issue_http() {
    [ ! -f "$ACME_SH" ] && echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}" && return
    echo -e "${YELLOW}>>> HTTP Mode${PLAIN}"
    _ask_input DOMAIN "${TXT_INPUT_DOMAIN}" "_valid_domain"

    echo -e "${TXT_HTTP_MODE_SEL}\n${TXT_HTTP_STANDALONE}\n${TXT_HTTP_NGINX}\n${TXT_HTTP_APACHE}\n${TXT_HTTP_WEBROOT}"
    read -p "${TXT_SELECT}" MODE
    
    if ! [[ "$MODE" =~ ^[1-4]$ ]]; then echo -e "${RED}${TXT_INVALID}${PLAIN}"; return; fi

    local MODE_ARGS=("" "--standalone" "--nginx" "--apache" "--webroot")
    local extra_arg=""
    
    if [ "$MODE" == "1" ]; then
        _port80_in_use && echo -e "${RED}${TXT_PORT_80_WARN}${PLAIN}" && return
    elif [ "$MODE" == "4" ]; then
        _ask_input extra_arg "${TXT_INPUT_WEBROOT}" "_valid_path"
        [ ! -d "$extra_arg" ] && echo -e "${RED}Dir not found.${PLAIN}" && return
    fi
    
    local args=("--issue" "-d" "$DOMAIN" "--keylength" "$KEY_LENGTH" "--server" "$CA_SERVER" "${MODE_ARGS[$MODE]}")
    [ -n "$extra_arg" ] && args+=("$extra_arg")
    
    echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
    "$ACME_SH" "${args[@]}" && _post_issue_install "$DOMAIN" || echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
}

_manual_env_loop() {
    echo -e "${YELLOW}ENV (Key=Value), type 'end' to finish.${PLAIN}"
    while true; do
        read -p "ENV > " env_in
        [[ "$env_in" == "end" ]] && break
        if [[ "$env_in" =~ ^[a-zA-Z0-9_]+=[a-zA-Z0-9_.~=+\/@-]+$ ]]; then
             export "$env_in"
        else
            echo -e "${RED}${TXT_ERR_ENV}${PLAIN}"
        fi
    done
}

issue_dns() {
    [ ! -f "$ACME_SH" ] && echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}" && return
    
    if [ -f "$ENC_STORE" ]; then
        _sec_load_env || { echo -e "${RED}Decrypt failed.${PLAIN}"; return; }
        echo -e "${CYAN}Info: Keys loaded.${PLAIN}"
    fi
    
    echo -e "${YELLOW}>>> DNS API Mode${PLAIN}"
    _ask_input DOMAIN "${TXT_INPUT_DOMAIN}" "_valid_domain"

    echo -e "${TXT_DNS_SEL}\n1. CloudFlare\n2. LuaDNS\n3. HE.net\n4. ClouDNS\n5. PowerDNS\n6. 1984Hosting\n7. deSEC.io\n8. dynv6\n9. AliYun\n10. ${TXT_DNS_MANUAL}\n0. Back"
    read -p "${TXT_SELECT}" opt
    local dns_type=""
    
    case $opt in
        1) _ask_and_export "CF_Key" "CloudFlare API Key" "" "-s"; _ask_and_export "CF_Email" "CloudFlare Email"; dns_type="dns_cf" ;;
        2) _ask_and_export "LUA_Key" "LuaDNS API Key" "" "-s"; _ask_and_export "LUA_Email" "LuaDNS Email"; dns_type="dns_lua" ;;
        3) _ask_and_export "HE_Username" "HE.net Username"; _ask_and_export "HE_Password" "HE.net Password" "" "-s"; dns_type="dns_he" ;;
        4) _ask_and_export "CLOUDNS_AUTH_ID" "Auth ID"; _ask_and_export "CLOUDNS_SUB_AUTH_ID" "Sub Auth ID (Opt)"; _ask_and_export "CLOUDNS_AUTH_PASSWORD" "Password" "" "-s"; dns_type="dns_cloudns" ;;
        5) _ask_and_export "PDNS_Url" "URL"; _ask_and_export "PDNS_ServerId" "ServerId"; _ask_and_export "PDNS_Token" "Token" "" "-s"; _ask_and_export "PDNS_Ttl" "TTL (60)"; dns_type="dns_pdns" ;;
        6) _ask_and_export "One984_Username" "Username"; _ask_and_export "One984_Password" "Password" "" "-s"; dns_type="dns_1984hosting" ;;
        7) _ask_and_export "DEDYN_TOKEN" "Token" "" "-s"; dns_type="dns_desec" ;;
        8) _ask_and_export "DYNV6_TOKEN" "Token" "" "-s"; dns_type="dns_dynv6" ;;
        9) _ask_and_export "Ali_Key" "Access Key"; _ask_and_export "Ali_Secret" "Access Secret" "" "-s"; dns_type="dns_ali" ;;
        10) _manual_env_loop; read -p "Plugin Name (e.g. dns_dp): " dns_type ;;
        0) return ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; return ;;
    esac
    
    [ -z "$dns_type" ] && return
    echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
    "$ACME_SH" --issue --dns "$dns_type" -d "$DOMAIN" --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    if [ $? -eq 0 ]; then
         _post_issue_cleanup
         _post_issue_install "$DOMAIN"
    else
         echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
    fi
}

toggle_security() {
    if [ -f "$ENC_STORE" ]; then
        ( _sec_load_env || exit 1 ) && {
            rm -f "$ENC_STORE" "$ENC_SIG"
            crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME} --cron-auto" | crontab -
            "$ACME_SH" --upgrade --auto-upgrade >/dev/null 2>&1
            echo -e "${RED}${TXT_SEC_OFF}${PLAIN}"
        } || echo -e "${RED}Decrypt failed.${PLAIN}"
    else
        local dump="" keys="CF_Key CF_Email LUA_Key LUA_Email HE_Username HE_Password CLOUDNS_AUTH_ID CLOUDNS_SUB_AUTH_ID CLOUDNS_AUTH_PASSWORD PDNS_Url PDNS_ServerId PDNS_Token PDNS_Ttl One984_Username One984_Password DEDYN_TOKEN DYNV6_TOKEN Ali_Key Ali_Secret DP_Id DP_Key GD_Key GD_Secret AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY LINODE_API_KEY"
        
        [ -f "$ACME_CONF" ] && while IFS='=' read -r k v; do
            [[ $k == SAVED_* ]] && _valid_env_val "${v//[\'\"]/}" && dump="${dump}export ${k#SAVED_}='${v//[\'\"]/}'\n"
        done < "$ACME_CONF"

        for v in $keys; do [ -n "${!v}" ] && dump="${dump}export $v='${!v}'\n"; done
        [ -z "$dump" ] && echo -e "${YELLOW}${TXT_SEC_NO_KEYS}${PLAIN}" && return

        echo -e "$dump" | _sec_save
        if [ $? -eq 0 ]; then
            _strip_conf
            (crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME} --cron-auto"; echo "20 3 * * * /bin/bash ${SCRIPT_PATH} --cron-auto") | crontab -
            "$ACME_SH" --upgrade --auto-upgrade 0 >/dev/null 2>&1
            echo -e "${GREEN}${TXT_SEC_ON}${PLAIN}"
        else
            echo -e "${RED}${TXT_SEC_FAIL}${PLAIN}"
        fi
    fi
}

# ==========================================
# UI & Menu
# ==========================================
settings_menu() {
    while true; do
        echo -e "${CYAN}===== ${TXT_M2_TITLE} =====${PLAIN}\n1. ${TXT_M2_1}\n2. ${TXT_M2_2}\n3. ${TXT_M2_3}\n4. ${TXT_M2_4}\n5. ${TXT_M2_5}\n6. ${TXT_M2_6}\n8. ${TXT_M2_8}\n0. ${TXT_M_0}"
        read -p "${TXT_SELECT}" choice
        case $choice in
            1) _ask_input USER_EMAIL "${TXT_INPUT_EMAIL}"; save_config; "$ACME_SH" --register-account -m "$USER_EMAIL" --server letsencrypt ;;
            2) [ "$LANG_SET" == "cn" ] && LANG_SET="en" || LANG_SET="cn"; save_config; load_language_strings ;;
            3) read -p "1. Let's Encrypt / 2. ZeroSSL: " c; [ "$c" == "2" ] && CA_SERVER="zerossl" || CA_SERVER="letsencrypt"; "$ACME_SH" --set-default-ca --server "$CA_SERVER"; save_config ;;
            4) read -p "1. RSA-2048 / 2. ECC-256: " c; [ "$c" == "2" ] && KEY_LENGTH="ec-256" || KEY_LENGTH="2048"; save_config ;;
            5) "$ACME_SH" --upgrade ;;
            6) setup_shortcut ;;
            8) toggle_security ;;
            0) return ;;
        esac
        echo -e "${GREEN}${TXT_SET_UPDATED}${PLAIN}"
    done
}

manage_certs() {
    [ ! -f "$ACME_SH" ] && echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}" && return
    while true; do
        echo -e "${CYAN}===== ${TXT_M6_TITLE} =====${PLAIN}"
        local out=$("$ACME_SH" --list)
        [ "$LANG_SET" == "cn" ] && out=$(echo "$out" | sed "s/Main_Domain/主域名/g;s/KeyLength/密钥/g;s/SAN_Domains/SAN/g;s/Created/创建/g;s/Renew/续期/g")
        echo "$out"; echo "------------------------"; echo -e "1. ${TXT_M6_RENEW}\n2. ${TXT_M6_REVOKE}\n0. ${TXT_M_0}"
        read -p "${TXT_SELECT}" c
        case $c in
            1) read -p "${TXT_M6_INPUT_RENEW}" d; [ -n "$d" ] && ( [ -f "$ENC_STORE" ] && _sec_load_env; "$ACME_SH" --renew -d "$d" --force; _post_issue_cleanup ) ;;
            2) read -p "${TXT_M6_INPUT_DEL}" d; [ -n "$d" ] && { read -p "${TXT_M6_CONFIRM_DEL}" y; [ "$y" == "y" ] && "$ACME_SH" --revoke -d "$d" && "$ACME_SH" --remove -d "$d" && rm -rf "$ACME_DIR/$d" "$ACME_DIR/${d}_ecc" && echo -e "${GREEN}${TXT_M6_DELETED}${PLAIN}"; } ;;
            0) return ;;
        esac
    done
}

uninstall_menu() {
    echo -e "${RED}===== ${TXT_M7_TITLE} =====${PLAIN}\n1. ${TXT_M7_1}\n2. ${TXT_M7_2}"
    read -p "${TXT_SELECT}" opt
    if [ "$opt" == "1" ]; then
        rm -f "$CONFIG_FILE" "$ENC_STORE" "$ENC_SIG"; [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
        echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"; exit 0
    elif [ "$opt" == "2" ]; then
        read -p "${TXT_M7_CONFIRM}" c
        [ "$c" == "DELETE" ] && { [ -f "$ACME_SH" ] && "$ACME_SH" --uninstall; rm -rf "$ACME_DIR" "$CONFIG_FILE" "$ENC_STORE" "$ENC_SIG" "$LOG_FILE"; [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"; crontab -l 2>/dev/null | grep -v "${SCRIPT_NAME} --cron-auto" | crontab -; echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"; rm -f "$0"; exit 0; }
    fi
}

load_language_strings() {
    if [ "$LANG_SET" == "en" ]; then
        TXT_TITLE="Acme-DNS-Super V0.1.4 | Secure Cert Manager"
        TXT_STATUS_LABEL="Status"; TXT_SEC_LABEL="Security"; TXT_EMAIL_LABEL="Email"; TXT_NOT_SET="Not Set"
        TXT_HINT_INSTALL=">> Warning: acme.sh is NOT installed. Please run [1] first. <<"
        TXT_M_1="Init Environment (Install, Register & Shortcut)"
        TXT_M_2="Settings (Language / CA / Key / Security)"
        TXT_M_3="Issue Cert - HTTP Mode (Single Domain)"
        TXT_M_4="Issue Cert - DNS API Mode (Wildcard Supported)"
        TXT_M_5="Install/Deploy Cert (Nginx/Apache Hook)"
        TXT_M_6="Cert Maintenance (List / Renew / Revoke)"
        TXT_M_7="Uninstall Script"; TXT_M_0="Exit"
        TXT_M2_TITLE="System Settings"; TXT_M2_1="Change Email"; TXT_M2_2="Change Language"; TXT_M2_3="Switch Default CA"
        TXT_M2_4="Switch Key Type"; TXT_M2_5="Upgrade acme.sh"; TXT_M2_6="Update Shortcut"; TXT_M2_8="Security: Encrypt Local Keys (Toggle)"
        TXT_M6_TITLE="Certificate Management"; TXT_M6_RENEW="Force Renew"; TXT_M6_REVOKE="Revoke & Delete"
        TXT_M6_INPUT_RENEW="Enter domain to renew: "; TXT_M6_INPUT_DEL="Enter domain to revoke & delete: "
        TXT_M6_CONFIRM_DEL="Are you sure? (y/n): "; TXT_M6_DELETED="Deleted."
        TXT_M7_TITLE="Uninstall Options"; TXT_M7_1="Remove Config"; TXT_M7_2="Full Uninstall"; TXT_M7_CONFIRM="Type 'DELETE' to confirm: "
        TXT_SC_CREATE="Creating shortcut..."; TXT_SC_ASK="Enter shortcut name (Default: ssl): "; TXT_SC_SUCCESS="Shortcut created! Run: "; TXT_SC_FAIL="Error: File exists."
        TXT_SELECT="Please select: "; TXT_INVALID="Invalid selection."; TXT_PRESS_ENTER="Press Enter to continue..."
        TXT_CHECK_DEP="Checking dependencies..."; TXT_MISSING_DEP="Missing dependencies, updating..."
        TXT_INSTALLING_DEP="Installing: "; TXT_INSTALL_FAIL="Error: Install failed for: "
        TXT_ACME_EXIST="acme.sh is already installed."; TXT_ACME_INSTALLING="Installing acme.sh..."
        TXT_INPUT_EMAIL="Enter Email: "; TXT_EMAIL_INVALID="Invalid Email!"; TXT_ACC_SYNC="Syncing Accounts..."; TXT_INIT_SUCCESS="Done!"
        TXT_WARN_NO_INIT="Please initialize environment first!"; TXT_INPUT_DOMAIN="Enter Domain: "; TXT_DOMAIN_EMPTY="Invalid Domain Format."
        TXT_HTTP_MODE_SEL="Select Validation Mode:"; TXT_HTTP_STANDALONE="1. Standalone"; TXT_HTTP_NGINX="2. Nginx"; TXT_HTTP_APACHE="3. Apache"; TXT_HTTP_WEBROOT="4. Webroot"
        TXT_INPUT_WEBROOT="Enter Webroot Path: "; TXT_PORT_80_WARN="Error: Port 80 is in use. Aborting."
        TXT_ISSUE_START="Starting..."; TXT_ISSUE_SUCCESS="Success! Proceeding to installation..."; TXT_ISSUE_FAIL="Failed."
        TXT_DNS_SEL="Select DNS Provider:"; TXT_DNS_MANUAL="Manual Input (ENV)"; TXT_DNS_KEY="API Key (Hidden): "; TXT_DNS_EMAIL="Account Email: "
        TXT_INS_TITLE="Install Cert to Service"; TXT_INS_DESC="Sets up deployment hook for auto-renewal."
        TXT_INS_DOMAIN="Enter Domain: "; TXT_INS_CERT_PATH="Cert Path: "; TXT_INS_KEY_PATH="Key Path: "; TXT_INS_CA_PATH="CA Path: "; TXT_INS_RELOAD="Reload Cmd: "
        TXT_INS_SUCCESS="Installed! Hook saved."; TXT_SET_UPDATED="Updated."; TXT_UN_DONE="Uninstalled."
        TXT_SEC_ON="Encryption ENABLED. Cron set to 03:20."; TXT_SEC_OFF="Encryption DISABLED. Cron restored."
        TXT_SEC_FAIL="Encryption Failed."; TXT_SEC_NO_KEYS="No keys found to encrypt."; TXT_ERR_ENV="Invalid ENV format."; TXT_ERR_PATH="Invalid Path."
    else
        TXT_TITLE="Acme-DNS-Super V0.1.4 | 证书管理大师"
        TXT_STATUS_LABEL="状态"; TXT_SEC_LABEL="安全模式"; TXT_EMAIL_LABEL="邮箱"; TXT_NOT_SET="未设置"
        TXT_HINT_INSTALL=">> 警告：未安装 acme.sh，请先执行 [1] <<"
        TXT_M_1="环境初始化 (安装、注册、快捷键)"
        TXT_M_2="系统设置 (语言 / CA / 密钥 / 安全)"
        TXT_M_3="签发证书 - HTTP 模式"; TXT_M_4="签发证书 - DNS API 模式"; TXT_M_5="部署证书 (配置 Nginx/Apache 钩子)"
        TXT_M_6="证书维护 (列表 / 续期 / 吊销)"; TXT_M_7="卸载脚本"; TXT_M_0="退出"
        TXT_M2_TITLE="系统设置"; TXT_M2_1="修改注册邮箱"; TXT_M2_2="切换语言 (Change Language)"; TXT_M2_3="切换默认 CA"
        TXT_M2_4="切换密钥类型"; TXT_M2_5="强制更新 acme.sh"; TXT_M2_6="更新/修复 快捷指令"; TXT_M2_8="安全: 开启/关闭 本地加密保护"
        TXT_M6_TITLE="证书管理列表"; TXT_M6_RENEW="强制续期"; TXT_M6_REVOKE="吊销并删除"
        TXT_M6_INPUT_RENEW="请输入域名: "; TXT_M6_INPUT_DEL="请输入域名: "; TXT_M6_CONFIRM_DEL="确认执行? (y/n): "; TXT_M6_DELETED="已删除。"
        TXT_M7_TITLE="卸载选项"; TXT_M7_1="仅删除配置"; TXT_M7_2="彻底卸载"; TXT_M7_CONFIRM="输入 'DELETE' 确认: "
        TXT_SC_CREATE="正在配置快捷指令..."; TXT_SC_ASK="请输入快捷名 (默认: ssl): "; TXT_SC_SUCCESS="创建成功！运行: "; TXT_SC_FAIL="错误: 目标文件已存在。"
        TXT_SELECT="请输入选项: "; TXT_INVALID="无效选择。"; TXT_PRESS_ENTER="按回车继续..."
        TXT_CHECK_DEP="检查依赖..."; TXT_MISSING_DEP="缺失依赖，正在更新..."; TXT_INSTALLING_DEP="安装: "; TXT_INSTALL_FAIL="错误: 安装失败: "
        TXT_ACME_EXIST="acme.sh 已安装。"; TXT_ACME_INSTALLING="安装 acme.sh..."; TXT_INPUT_EMAIL="请输入邮箱: "; TXT_EMAIL_INVALID="格式错误！"
        TXT_ACC_SYNC="同步账户中..."; TXT_INIT_SUCCESS="初始化完成！"; TXT_WARN_NO_INIT="请先初始化！"
        TXT_INPUT_DOMAIN="请输入域名: "; TXT_DOMAIN_EMPTY="域名格式无效 (仅允许: a-z0-9.-)。"
        TXT_HTTP_MODE_SEL="选择模式:"; TXT_HTTP_STANDALONE="1. Standalone"; TXT_HTTP_NGINX="2. Nginx"; TXT_HTTP_APACHE="3. Apache"; TXT_HTTP_WEBROOT="4. Webroot"
        TXT_INPUT_WEBROOT="输入根目录: "; TXT_PORT_80_WARN="错误: 80端口被占用，无法使用Standalone模式。"
        TXT_ISSUE_START="开始签发..."; TXT_ISSUE_SUCCESS="签发成功！即将进入部署流程..."; TXT_ISSUE_FAIL="签发失败。"
        TXT_DNS_SEL="选择DNS服务商:"; TXT_DNS_MANUAL="手动输入 (ENV)"; TXT_DNS_KEY="API Key (隐藏输入): "; TXT_DNS_EMAIL="Account Email: "
        TXT_INS_TITLE="部署证书到服务"; TXT_INS_DESC="此操作将设置安装路径和重载命令，并永久保存用于自动续期。"
        TXT_INS_DOMAIN="请输入域名: "; TXT_INS_CERT_PATH="Cert 路径: "; TXT_INS_KEY_PATH="Key 路径: "; TXT_INS_CA_PATH="CA 路径: "; TXT_INS_RELOAD="Reload Cmd: "
        TXT_INS_SUCCESS="部署成功！钩子已保存。"; TXT_SET_UPDATED="已更新。"; TXT_UN_DONE="已卸载。"
        TXT_SEC_ON="加密已开启(校验+混淆)。每日03:20自动检测。"; TXT_SEC_OFF="加密已关闭。已恢复 acme.sh 原生设置。"
        TXT_SEC_FAIL="加密失败。"; TXT_SEC_NO_KEYS="未检测到有效 Key，无法执行加密。"; TXT_ERR_ENV="ENV格式错误。"; TXT_ERR_PATH="路径无效 (需绝对路径)。"
    fi
}

select_language_first() {
    if [ -z "$LANG_SET" ]; then
        clear; echo -e "1. 中文\n2. English"; read -p "Select [1-2]: " lang_opt
        [ "$lang_opt" == "2" ] && LANG_SET="en" || LANG_SET="cn"; save_config
    fi
    load_language_strings
}

show_menu() {
    clear
    echo -e "${BLUE}==============================================================${PLAIN}\n${BLUE}           ${TXT_TITLE}           ${PLAIN}\n${BLUE}==============================================================${PLAIN}"
    echo -e "${TXT_STATUS_LABEL}: CA: ${GREEN}${CA_SERVER}${PLAIN} | Key: ${GREEN}${KEY_LENGTH}${PLAIN} | ${TXT_EMAIL_LABEL}: ${GREEN}${USER_EMAIL:-${TXT_NOT_SET}}${PLAIN}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"
    [ ! -f "$ACME_SH" ] && echo -e "${RED}${TXT_HINT_INSTALL}${PLAIN}"
    echo -e "${TXT_SEC_LABEL}: $([ -f "$ENC_STORE" ] && echo -e "${GREEN}ON${PLAIN}" || echo -e "${YELLOW}OFF${PLAIN}")"
    echo -e " 1. ${TXT_M_1}\n 2. ${TXT_M_2}\n--------------------------------------------------------------\n 3. ${TXT_M_3}\n 4. ${TXT_M_4}\n 5. ${TXT_M_5}\n--------------------------------------------------------------\n 6. ${TXT_M_6}\n 7. ${TXT_M_7}\n 0. ${TXT_M_0}\n${BLUE}--------------------------------------------------------------${PLAIN}"
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

load_config; select_language_first
while true; do show_menu; echo ""; read -p "${TXT_PRESS_ENTER}"; done
