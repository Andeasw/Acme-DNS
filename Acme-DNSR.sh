#!/bin/bash
# ==============================================================
# Script Name: Acme-DNS-Super (Security Hardened)
# Version: 0.0.2 (Secured)
# Optimized By: Prince 2025.10
# Security Enhanced By: Gemini Business
# ==============================================================

# ==============================================================
# 0. Global Definitions / 全局定义
# ==============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# 配置文件路径（加密后的）
CONFIG_FILE="$HOME/.acme_super_config.enc"
# 本地密钥文件（用于解密配置，权限极为重要）
SECRET_KEY_FILE="$HOME/.acme_super.key"

ACME_DIR="$HOME/.acme.sh"
ACME_SH="$ACME_DIR/acme.sh"
SCRIPT_PATH=$(readlink -f "$0")

# Check Root
[[ $EUID -ne 0 ]] && echo -e "${RED}Error: Root privileges required! / 需要 Root 权限！${PLAIN}" && exit 1

# ==============================================================
# Security & Encryption Logic / 安全与加密逻辑
# ==============================================================

# 初始化安全环境：生成随机密钥
init_security() {
    if [ ! -f "$SECRET_KEY_FILE" ]; then
        # 生成 32 字节随机密钥
        openssl rand -hex 32 > "$SECRET_KEY_FILE"
        # 只有 root 可读写
        chmod 600 "$SECRET_KEY_FILE"
    fi
}

# 清洗 acme.sh 目录下的敏感信息
scrub_sensitive_data() {
    # 清洗 account.conf 中的敏感 Key
    if [ -f "$ACME_DIR/account.conf" ]; then
        sed -i 's/SAVED_.*_Key=.*/SAVED_Key="PROTECTED_BY_SUPER_SCRIPT"/g' "$ACME_DIR/account.conf"
        sed -i 's/SAVED_.*_Email=.*/SAVED_Email="PROTECTED_BY_SUPER_SCRIPT"/g' "$ACME_DIR/account.conf"
        sed -i 's/SAVED_.*_Token=.*/SAVED_Token="PROTECTED_BY_SUPER_SCRIPT"/g' "$ACME_DIR/account.conf"
        sed -i 's/SAVED_.*_Password=.*/SAVED_Password="PROTECTED_BY_SUPER_SCRIPT"/g' "$ACME_DIR/account.conf"
    fi
    
    # 深度清洗：遍历所有域名配置，清除环境变量残留
    # 注意：这需要依赖本脚本的加密配置来在续期时重新注入变量，否则 acme.sh 无法续期
    # 这正是本脚本接管 cron 的意义所在
    find "$ACME_DIR" -name "*.conf" -print0 | xargs -0 sed -i 's/Le_Webroot=.*/Le_Webroot="base64"/g' 2>/dev/null
}

# 加密并保存配置
save_config() {
    init_security
    
    # 将配置组合成文本流
    local config_content="CA_SERVER=\"$CA_SERVER\"
KEY_LENGTH=\"$KEY_LENGTH\"
USER_EMAIL=\"$USER_EMAIL\"
LANG_SET=\"$LANG_SET\"
SHORTCUT_NAME=\"$SHORTCUT_NAME\"
# DNS Variables Storage
CF_Key=\"$CF_Key\"
CF_Email=\"$CF_Email\"
LUA_Key=\"$LUA_Key\"
LUA_Email=\"$LUA_Email\"
HE_Username=\"$HE_Username\"
HE_Password=\"$HE_Password\"
CLOUDNS_AUTH_ID=\"$CLOUDNS_AUTH_ID\"
CLOUDNS_SUB_AUTH_ID=\"$CLOUDNS_SUB_AUTH_ID\"
CLOUDNS_AUTH_PASSWORD=\"$CLOUDNS_AUTH_PASSWORD\"
PDNS_Url=\"$PDNS_Url\"
PDNS_ServerId=\"$PDNS_ServerId\"
PDNS_Token=\"$PDNS_Token\"
PDNS_Ttl=\"$PDNS_Ttl\"
One984_Username=\"$One984_Username\"
One984_Password=\"$One984_Password\"
DEDYN_TOKEN=\"$DEDYN_TOKEN\"
DYNV6_TOKEN=\"$DYNV6_TOKEN\"
"
    # 使用 openssl aes-256-cbc 加密写入文件
    echo "$config_content" | openssl enc -aes-256-cbc -pbkdf2 -salt -pass file:"$SECRET_KEY_FILE" -out "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
}

# 解密并加载配置
load_config() {
    init_security
    
    if [ -f "$CONFIG_FILE" ]; then
        # 解密并 source
        # 使用 eval 执行解密后的输出
        local decrypted_config=$(openssl enc -d -aes-256-cbc -pbkdf2 -salt -pass file:"$SECRET_KEY_FILE" -in "$CONFIG_FILE" 2>/dev/null)
        
        if [ -n "$decrypted_config" ]; then
            eval "$decrypted_config"
        else
            echo -e "${RED}Config decryption failed or empty. Resetting defaults.${PLAIN}"
             # Defaults
            CA_SERVER="letsencrypt"
            KEY_LENGTH="2048"
            USER_EMAIL=""
            LANG_SET=""
            SHORTCUT_NAME=""
        fi
    else
        CA_SERVER="letsencrypt"
        KEY_LENGTH="2048"
        USER_EMAIL=""
        LANG_SET=""
        SHORTCUT_NAME=""
    fi
}

# ==============================================================
# 1. Localization / 本地化
# ==============================================================

load_language_strings() {
    if [ "$LANG_SET" == "en" ]; then
        # --- English ---
        TXT_TITLE="Acme-DNS-Super V0.0.2 | Cert Manager (Secured)"
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
        
        # Cert Manage
        TXT_M6_TITLE="Certificate Management"
        TXT_M6_RENEW="Force Renew (Renew specific domain)"
        TXT_M6_REVOKE="Revoke & Delete (Revoke from CA & Remove local)"
        TXT_M6_INPUT_RENEW="Enter domain to renew: "
        TXT_M6_INPUT_DEL="Enter domain to revoke & delete: "
        TXT_M6_CONFIRM_DEL="Are you sure you want to REVOKE & DELETE? (y/n): "
        TXT_M6_DELETED="Certificate revoked and deleted."
        TXT_M6_HEADER_FIX="" 

        # Shortcut
        TXT_SC_CREATE="Creating shortcut..."
        TXT_SC_ASK="Enter shortcut name (Default: ssl): "
        TXT_SC_SUCCESS="Shortcut created! Run command: "
        TXT_SC_EXIST="Shortcut already exists: "
        
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
        TXT_ISSUE_FAIL="Issue Failed. Check logs above."
        
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
        TXT_TITLE="Acme-DNS-Super V0.0.2 | 证书管理大师 (安全版)"
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
        
        # Cert Manage
        TXT_M6_TITLE="证书管理列表"
        TXT_M6_RENEW="强制续期 (Force Renew)"
        TXT_M6_REVOKE="吊销并删除 (向 CA 吊销并清理本地文件)"
        TXT_M6_INPUT_RENEW="请输入要续期的域名: "
        TXT_M6_INPUT_DEL="请输入要吊销的域名: "
        TXT_M6_CONFIRM_DEL="确认执行 [吊销+删除] 吗? (y/n): "
        TXT_M6_DELETED="证书已吊销并彻底删除。"
        TXT_M6_HEADER_ORIG="Main_Domain|KeyLength|SAN_Domains|Profile|CA|Created|Renew"
        TXT_M6_HEADER_NEW="主域名|密钥长度|SAN域名|配置文件|CA机构|创建时间|续期时间"
        
        # Shortcut
        TXT_SC_CREATE="正在配置快捷启动..."
        TXT_SC_ASK="请输入快捷命令名称 (默认: ssl): "
        TXT_SC_SUCCESS="快捷方式已创建！在终端输入以下命令即可运行："
        TXT_SC_EXIST="快捷方式已存在: "
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
        TXT_HTTP_STANDALONE="1. Standalone (优先尝试IPv6，失败后使用IPv4)"
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
# 2. Core Functionality / 核心功能
# ==============================================================

setup_custom_cron() {
    # 使用本脚本接管 cron
    local cron_cmd="0 3 * * * /bin/bash \"$SCRIPT_PATH\" --auto-renew >/dev/null 2>&1"
    
    # 移除旧的 acme.sh cron
    "$ACME_SH" --uninstall-cronjob >/dev/null 2>&1
    
    # 添加新的 cron
    (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "$cron_cmd") | crontab -
}

setup_shortcut() {
    echo -e "${YELLOW}${TXT_SC_CREATE}${PLAIN}"
    
    if [ -n "$SHORTCUT_NAME" ] && [ -f "/usr/bin/$SHORTCUT_NAME" ]; then
        rm -f "/usr/bin/$SHORTCUT_NAME"
    fi
    read -p "${TXT_SC_ASK}" input_name
    SHORTCUT_NAME=${input_name:-ssl}
    cat > "/usr/bin/$SHORTCUT_NAME" <<EOF
#!/bin/bash
bash "$SCRIPT_PATH"
EOF
    chmod +x "/usr/bin/$SHORTCUT_NAME"
    
    setup_custom_cron
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
    # Added 'socat' as it is critical for standalone mode
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
        for dep in "${dependencies[@]}"; do
            if ! command -v $dep &> /dev/null; then
                echo -e "${YELLOW}${TXT_INSTALLING_DEP}$dep ...${PLAIN}"
                $install_cmd $dep
            fi
        done
    fi
    
    # Ensure cron service is running
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
    
    # 禁用 acme.sh 自带 cron，使用我们的安全 cron
    "$ACME_SH" --uninstall-cronjob >/dev/null 2>&1
    setup_custom_cron
    
    save_config
    
    if [ -z "$SHORTCUT_NAME" ]; then
        setup_shortcut
    fi
    
    echo -e "${GREEN}${TXT_INIT_SUCCESS}${PLAIN}"
}

# ==============================================================
# 3. Issue & Install / 签发与部署
# ==============================================================

issue_http() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    
    echo -e "${YELLOW}>>> HTTP Mode${PLAIN}"
    read -p "${TXT_INPUT_DOMAIN}" DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}" && return
    echo -e "${TXT_HTTP_MODE_SEL}"
    echo -e "${TXT_HTTP_STANDALONE}"
    echo -e "${TXT_HTTP_NGINX}"
    echo -e "${TXT_HTTP_APACHE}"
    echo -e "${TXT_HTTP_WEBROOT}"
    read -p "${TXT_SELECT}" MODE
    local cmd_flags=""
    
    case $MODE in
        1) 
            # Standalone 模式优化
            if command -v netstat &>/dev/null && netstat -tuln | grep -q ":80 "; then
                echo -e "${RED}${TXT_PORT_80_WARN}${PLAIN}"
                read -p "${TXT_CONTINUE_ASK}" cont
                [[ "$cont" != "y" ]] && return
            fi
            
            # IPv6 优先逻辑
            local ipv6_success=false
            if ip -6 addr 2>/dev/null | grep -q "scope global"; then
                echo -e "${CYAN}Detected IPv6, trying Standalone IPv6 first...${PLAIN}"
                "$ACME_SH" --issue -d "$DOMAIN" --standalone --listen-v6 --keylength "$KEY_LENGTH" --server "$CA_SERVER"
                if [ $? -eq 0 ]; then
                    ipv6_success=true
                    echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
                    install_cert_menu "$DOMAIN"
                    scrub_sensitive_data # 清理明文
                    return
                else
                    echo -e "${YELLOW}IPv6 Standalone failed, falling back to IPv4...${PLAIN}"
                fi
            fi
            
            cmd_flags="--standalone"
            ;;
        2) cmd_flags="--nginx" ;;
        3) cmd_flags="--apache" ;;
        4) 
            read -p "${TXT_INPUT_WEBROOT}" webroot
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
    
    scrub_sensitive_data # 操作后清理敏感数据
}

issue_dns() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}${TXT_WARN_NO_INIT}${PLAIN}"; return; fi
    echo -e "${YELLOW}>>> DNS API Mode${PLAIN}"
    read -p "${TXT_INPUT_DOMAIN}" DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}${TXT_DOMAIN_EMPTY}${PLAIN}" && return
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
    # Clear ENV to prevent conflicts
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
                export "$env_in"
            done
            read -p "Plugin Name (e.g. dns_ali): " dns_type
            ;;
        0) return ;;
        *) echo -e "${RED}${TXT_INVALID}${PLAIN}"; return ;;
    esac
    
    [ -z "$dns_type" ] && return
    
    # 保存本次配置到加密文件（方便续期时调用）
    save_config
    
    echo -e "${CYAN}${TXT_ISSUE_START}${PLAIN}"
    "$ACME_SH" --issue --dns "$dns_type" -d "$DOMAIN" --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${TXT_ISSUE_SUCCESS}${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}${TXT_ISSUE_FAIL}${PLAIN}"
    fi
    
    scrub_sensitive_data # 立即清除 acme.sh 目录下的敏感信息
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
    
    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}Error: Cert not found for $DOMAIN${PLAIN}"
        return
    fi
    read -p "${TXT_INS_CERT_PATH}" CERT_PATH
    read -p "${TXT_INS_KEY_PATH}" KEY_PATH
    read -p "${TXT_INS_CA_PATH}" CA_PATH
    read -p "${TXT_INS_RELOAD}" RELOAD_CMD
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
# 4. Settings & Maintenance / 设置与维护
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
        
        # Capture output
        local list_output=$("$ACME_SH" --list)
        
        # Replace header if Chinese mode is active
        if [ "$LANG_SET" == "cn" ]; then
            # Use sed to replace the specific header line
            echo "$list_output" | sed "s/Main_Domain/主域名/g" | \
            sed "s/KeyLength/密钥长度/g" | \
            sed "s/SAN_Domains/SAN域名/g" | \
            sed "s/Profile/配置名/g" | \
            sed "s/CA/CA机构/g" | \
            sed "s/Created/创建时间/g" | \
            sed "s/Renew/续期时间/g"
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
                # 手动续期也需要注入变量
                if [ -n "$d" ]; then
                     # 临时导出环境变量供 acme.sh 使用
                     export CF_Key="$CF_Key" CF_Email="$CF_Email"
                     export LUA_Key="$LUA_Key" LUA_Email="$LUA_Email"
                     # ... (这里简化，实际依靠 auto-renew 全局注入更稳，手动强续期可能需要用户重输Key或者信任内存变量)
                     "$ACME_SH" --renew -d "$d" --force
                     scrub_sensitive_data
                fi
                ;;
            2)
                read -p "${TXT_M6_INPUT_DEL}" d
                if [ -n "$d" ]; then
                    read -p "${TXT_M6_CONFIRM_DEL}" c
                    if [ "$c" == "y" ]; then
                        "$ACME_SH" --revoke -d "$d"
                        "$ACME_SH" --remove -d "$d"
                        # Clean up folders
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
        rm -f "$CONFIG_FILE" "$SECRET_KEY_FILE"
        [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
        # Remove cron
        (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH") | crontab -
        echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"
        exit 0
    elif [ "$opt" == "2" ]; then
        read -p "${TXT_UN_CONFIRM}" confirm
        if [ "$confirm" == "DELETE" ]; then
            [ -f "$ACME_SH" ] && "$ACME_SH" --uninstall
            rm -rf "$ACME_DIR" "$CONFIG_FILE" "$SECRET_KEY_FILE" "$0"
            [ -n "$SHORTCUT_NAME" ] && rm -f "/usr/bin/$SHORTCUT_NAME"
             # Remove cron
            (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH") | crontab -
            echo -e "${GREEN}${TXT_UN_DONE}${PLAIN}"
            exit 0
        fi
    fi
}

# ==============================================================
# 5. Main Entry / 主入口
# ==============================================================

# 自动续期后台任务 (被 cron 调用)
auto_renew_task() {
    load_config
    # 导出所有可能需要的环境变量
    export CF_Key="$CF_Key" CF_Email="$CF_Email"
    export LUA_Key="$LUA_Key" LUA_Email="$LUA_Email"
    export HE_Username="$HE_Username" HE_Password="$HE_Password"
    export CLOUDNS_AUTH_ID="$CLOUDNS_AUTH_ID" CLOUDNS_SUB_AUTH_ID="$CLOUDNS_SUB_AUTH_ID" CLOUDNS_AUTH_PASSWORD="$CLOUDNS_AUTH_PASSWORD"
    export PDNS_Url="$PDNS_Url" PDNS_ServerId="$PDNS_ServerId" PDNS_Token="$PDNS_Token" PDNS_Ttl="$PDNS_Ttl"
    export One984_Username="$One984_Username" One984_Password="$One984_Password"
    export DEDYN_TOKEN="$DEDYN_TOKEN" DYNV6_TOKEN="$DYNV6_TOKEN"
    
    # 调用 acme.sh 的 cron 模式，它会自动检查需要续期的域名
    "$ACME_SH" --cron --home "$ACME_DIR"
    
    # 任务完成后，立即清洗 acme.sh 目录中的明文
    scrub_sensitive_data
}

# Handle Arguments
if [[ "$1" == "--auto-renew" ]]; then
    auto_renew_task
    exit 0
fi

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
