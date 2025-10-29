#!/bin/bash
# ===========================================
# RSA 2048 证书管理脚本 (acme.sh + 多DNS提供商支持)
# 支持的DNS提供商: CloudFlare/LuaDNS/Hurricane Electric/ClouDNS/PowerDNS/1984Hosting/deSEC/dynv6
# 支持 Debian、Alpine 和 FreeBSD 系统
# 支持证书申请、续期、管理和卸载
# 支持 DNS、HTTP-80、TLS-443 验证方式
# 支持多密钥类型：RSA-2048/4096, EC-256/384/521
# By Prince 2025.10
# ===========================================

set -Eeuo pipefail
trap 'echo "错误发生于第 $LINENO 行" >&2' ERR

# 配置参数（支持环境变量覆盖）
DOMAIN="${DOMAIN:-}"
WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-}"
CERT_PATH="${CERT_PATH:-}"
KEY_PATH="${KEY_PATH:-}"
EMAIL="${EMAIL:-}"

# DNS 提供商配置
DNS_PROVIDER="${DNS_PROVIDER:-}"  # cloudflare, luadns, he 或 cloudns

# CloudFlare 配置
CF_Token="${CF_Token:-}"
CF_Zone_ID="${CF_Zone_ID:-}"
CF_Account_ID="${CF_Account_ID:-}"
CF_Key="${CF_Key:-}"  # 不推荐全局 API Key
CF_Email="${CF_Email:-}"  # 不推荐邮箱

# LuaDNS 配置
LUA_KEY="${LUA_KEY:-}"
LUA_EMAIL="${LUA_EMAIL:-}"

# Hurricane Electric 配置
HE_USERNAME="${HE_USERNAME:-}"
HE_PASSWORD="${HE_PASSWORD:-}"

# ClouDNS 配置
CLOUDNS_AUTH_ID="${CLOUDNS_AUTH_ID:-}"
CLOUDNS_SUB_AUTH_ID="${CLOUDNS_SUB_AUTH_ID:-}"
CLOUDNS_AUTH_PASSWORD="${CLOUDNS_AUTH_PASSWORD:-}"

# PowerDNS 配置
PDNS_Url="${PDNS_Url:-}"
PDNS_ServerId="${PDNS_ServerId:-localhost}"
PDNS_Token="${PDNS_Token:-}"
PDNS_Ttl="${PDNS_Ttl:-60}"

# 1984Hosting 配置
One984HOSTING_Username="${One984HOSTING_Username:-}"
One984HOSTING_Password="${One984HOSTING_Password:-}"

# deSEC.io 配置
DEDYN_TOKEN="${DEDYN_TOKEN:-}"

# dynv6 配置
DYNV6_TOKEN="${DYNV6_TOKEN:-}"
DYNV6_KEY="${DYNV6_KEY:-}"

# ACME 配置
ACME_SERVER="${ACME_SERVER:-letsencrypt}"

# 验证方式配置
VALIDATION_METHOD="${VALIDATION_METHOD:-dns}"  # dns, http, tls
HTTP_PORT="${HTTP_PORT:-80}"  # HTTP 验证端口
TLS_PORT="${TLS_PORT:-443}"   # TLS 验证端口
SKIP_PORT_CHECK="${SKIP_PORT_CHECK:-false}"  # 跳过端口检查
WEBROOT_PATH="${WEBROOT_PATH:-}"            # Webroot 路径（可选，用于HTTP验证）

# 密钥类型配置
KEY_TYPE="${KEY_TYPE:-rsa-2048}"  # rsa-2048, rsa-4096, ec-256, ec-384, ec-521
KEY_TYPE_SELECTED="${KEY_TYPE_SELECTED:-false}"

# 客户端与CA源配置
ACME_CLIENT="${ACME_CLIENT:-acme.sh}"       # acme.sh 或 certbot
ACME_CA_LIST="${ACME_CA_LIST:-letsencrypt,zerossl}"  # 多CA回退顺序
ACME_ACCOUNT_POOL="${ACME_ACCOUNT_POOL:-}"
ACME_REGISTER_TIMEOUT="${ACME_REGISTER_TIMEOUT:-30}"
ACME_CURL_CONNECT_TIMEOUT="${ACME_CURL_CONNECT_TIMEOUT:-5}"
ACME_CURL_MAX_TIME="${ACME_CURL_MAX_TIME:-40}"
ACME_CURL_RETRIES="${ACME_CURL_RETRIES:-2}"
ACME_CURL_RETRY_DELAY="${ACME_CURL_RETRY_DELAY:-2}"
ACME_RETRY_DELAY="${ACME_RETRY_DELAY:-3}"

# 状态缓存
DNS_PROVIDER_READY="false"
ACME_NETWORK_TUNING_APPLIED="false"
ACME_EXISTING_ACCOUNT_EMAIL=""

# 日志与运行时配置
LOG_FILE="${LOG_FILE:-/tmp/acme-manager.log}"
LOG_MAX_SIZE_KB="${LOG_MAX_SIZE_KB:-1024}"
SILENT_MODE="${SILENT_MODE:-false}"
LOCK_FILE="${LOCK_FILE:-/tmp/acme-manager.lock}"
ENV_FILE="${ENV_FILE:-.env}"
RENEW_THRESHOLD_DAYS="${RENEW_THRESHOLD_DAYS:-30}"
LOG_LEVEL="${LOG_LEVEL:-info}"

# 同步与部署配置
CERT_SYNC_DIR="${CERT_SYNC_DIR:-}"          # 若设置，将证书同步到该目录（如 /etc/nginx/ssl）
SERVICE_RELOAD_CMD="${SERVICE_RELOAD_CMD:-}" # 证书更新后自定义重载命令（可与 POST_SCRIPT 配合）

# 后续脚本命令
POST_SCRIPT_CMD="${POST_SCRIPT_CMD:-}"
POST_SCRIPT_ENABLED="${POST_SCRIPT_ENABLED:-false}"

# 通知配置
NOTIFY_ENABLED="${NOTIFY_ENABLED:-false}"
NOTIFY_ON_SUCCESS="${NOTIFY_ON_SUCCESS:-false}"
NOTIFY_ON_FAILURE="${NOTIFY_ON_FAILURE:-true}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
WEBHOOK_URL="${WEBHOOK_URL:-}"
MAIL_TO="${MAIL_TO:-}"
MAIL_SUBJECT_PREFIX="${MAIL_SUBJECT_PREFIX:-[Acme-DNS]}"

# 系统检测
OS_TYPE=""
PKG_MANAGER=""
PKG_INSTALL=""
PKG_UPDATE=""
ACME_HOME="$HOME/.acme.sh"
LOG_FILE="/tmp/acme-manager.log"
SERVICE_TO_RESTART=""
PORT_CHECK_TIMEOUT=10
CURRENT_OPERATION=""

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# 生成随机字符串
generate_random_string() {
    local length="${1:-8}"
    local prefix="${2:-}"
    local random_str=$(openssl rand -hex $((length/2)) 2>/dev/null || 
                      cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1)
    echo "${prefix}${random_str}"
}

# 生成默认域名
generate_default_domain() {
    local random_part=$(generate_random_string 6 "domain")
    echo "${random_part}.local"
}

# 生成默认邮箱
generate_default_email() {
    local domain="${1:-}"
    if [ -z "$domain" ]; then
        domain=$(generate_default_domain)
    fi
    local random_part=$(generate_random_string 4 "admin")
    echo "${random_part}@${domain}"
}

# 路径解析工具
resolve_path() {
    local target="$1"

    if [ -z "$target" ]; then
        return 1
    fi

    local resolved=""

    if command -v readlink >/dev/null 2>&1; then
        resolved=$(readlink -f "$target" 2>/dev/null || true)
    fi

    if [ -z "$resolved" ] && command -v realpath >/dev/null 2>&1; then
        resolved=$(realpath "$target" 2>/dev/null || true)
    fi

    if [ -z "$resolved" ]; then
        local dir
        dir=$(cd "$(dirname "$target")" 2>/dev/null && pwd -P 2>/dev/null) || return 1
        resolved="$dir/$(basename "$target")"
    fi

    printf '%s\n' "$resolved"
}

# 检测是否可无密码使用 sudo
can_use_passwordless_sudo() {
    if command -v sudo >/dev/null 2>&1; then
        if sudo -n true >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# 日志函数
_now() { date '+%Y-%m-%d %H:%M:%S'; }
log() {
    local level="${1:-INFO}"
    if [ "$#" -gt 0 ]; then
        shift
    fi
    local msg="${*:-}"

    if [ "$level" = "DEBUG" ] && [ "$LOG_LEVEL" != "debug" ]; then
        return 0
    fi

    local line="[$(_now)] [$level] $msg"
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    if [ -n "$LOG_FILE" ]; then
        if [ -f "$LOG_FILE" ]; then
            local size_kb
            size_kb=$(du -k "$LOG_FILE" 2>/dev/null | awk '{print $1}')
            if [ "${size_kb:-0}" -gt "$LOG_MAX_SIZE_KB" ]; then
                : > "$LOG_FILE"
            fi
        fi
        printf '%s\n' "$line" >> "$LOG_FILE"
    fi

    if [ "$SILENT_MODE" != "true" ]; then
        case "$level" in
            ERROR) printf '%b[错误] %s%b\n' "$RED" "$msg" "$NC" >&2 ;;
            WARN) printf '%b[警告] %s%b\n' "$YELLOW" "$msg" "$NC" >&2 ;;
            INFO) printf '%b[信息] %s%b\n' "$BLUE" "$msg" "$NC" >&2 ;;
            SUCCESS) printf '%b[成功] %s%b\n' "$GREEN" "$msg" "$NC" >&2 ;;
            STEP) printf '%b[步骤] %s%b\n' "$CYAN" "$msg" "$NC" >&2 ;;
            DEBUG) if [ "$LOG_LEVEL" = "debug" ]; then printf '%b[调试] %s%b\n' "$MAGENTA" "$msg" "$NC" >&2; fi ;;
            *) printf '%s\n' "$msg" ;;
        esac
    fi
}
log_write() { log "$@"; }
error() { log ERROR "$@"; }
warn() { log WARN "$@"; }
info() { log INFO "$@"; }
success() { log SUCCESS "$@"; }
fatal() {
    local message="$*"
    log ERROR "$message"
    if [ -n "$CURRENT_OPERATION" ]; then
        send_notification "failure" "${CURRENT_OPERATION} 失败" "${message}
请查看日志: ${LOG_FILE}"
    fi
    exit 1
}
step() { log STEP "$@"; }
debug() { log DEBUG "$@"; }

# 快速启动配置
QUICK_START_FLAG_FILE="$HOME/.acme-dns-quick-start"

CONFIG_ENCRYPTION_VERSION_DEFAULT="1"
CONFIG_ENCRYPTION_VERSION="${CONFIG_ENCRYPTION_VERSION:-$CONFIG_ENCRYPTION_VERSION_DEFAULT}"
MASTER_PASSWORD_HASH="${MASTER_PASSWORD_HASH:-}"
MASTER_PASSWORD_SECRET="${MASTER_PASSWORD_SECRET:-}"
declare -a SENSITIVE_CONFIG_VARS=(
    "CF_Token"
    "CF_Key"
    "LUA_KEY"
    "HE_PASSWORD"
    "CLOUDNS_AUTH_PASSWORD"
    "PDNS_Token"
    "One984HOSTING_Password"
    "DEDYN_TOKEN"
    "DYNV6_TOKEN"
    "DYNV6_KEY"
    "TELEGRAM_BOT_TOKEN"
    "WEBHOOK_URL"
)

hash_password_secure() {
    local password="$1"
    if [ -z "$password" ]; then
        return 1
    fi

    local hashed=""
    if ! hashed=$(PASS="$password" python3 - <<'PY' 2>/dev/null
import crypt
import os
import sys

password = os.environ.get("PASS", "")
if not password:
    sys.exit(1)

method = None
if hasattr(crypt, "METHOD_ARGON2ID"):
    method = crypt.METHOD_ARGON2ID
elif hasattr(crypt, "METHOD_BLOWFISH"):
    method = crypt.METHOD_BLOWFISH
else:
    sys.exit(2)

print(crypt.crypt(password, crypt.mksalt(method)))
PY
    ); then
        return 1
    fi

    printf '%s\n' "$hashed"
}

verify_password_secure() {
    local password="$1"
    local hashed="$2"
    if [ -z "$password" ] || [ -z "$hashed" ]; then
        return 1
    fi

    PASS="$password" HASH="$hashed" python3 - <<'PY' >/dev/null 2>&1
import crypt
import os
import sys

password = os.environ.get("PASS", "")
hashed = os.environ.get("HASH", "")

if not password or not hashed:
    sys.exit(1)

if crypt.crypt(password, hashed) == hashed:
    sys.exit(0)
sys.exit(1)
PY
}

prompt_new_master_password() {
    local env_pass="${MASTER_PASSWORD:-}"
    local pass1=""
    local pass2=""

    if [ -n "$env_pass" ]; then
        if [ ${#env_pass} -lt 8 ]; then
            error "MASTER_PASSWORD 环境变量长度不足 8 位，无法作为配置加密密码"
            return 1
        fi
        pass1="$env_pass"
    else
        while true; do
            echo -ne "${CYAN}请设置配置加密密码(至少8位): ${NC}"
            read -rs pass1
            echo
            if [ ${#pass1} -lt 8 ]; then
                warn "密码长度不足 8 位，请重新输入"
                pass1=""
                continue
            fi
            echo -ne "${CYAN}请再次输入以确认: ${NC}"
            read -rs pass2
            echo
            if [ "$pass1" != "$pass2" ]; then
                warn "两次输入的密码不一致，请重新输入"
                pass1=""
                pass2=""
                continue
            fi
            break
        done
    fi

    local hashed
    if ! hashed=$(hash_password_secure "$pass1"); then
        error "生成配置密码哈希失败，请确保已安装 python3 并支持 bcrypt/argon2"
        return 1
    fi

    MASTER_PASSWORD_SECRET="$pass1"
    MASTER_PASSWORD_HASH="$hashed"
    CONFIG_ENCRYPTION_VERSION="$CONFIG_ENCRYPTION_VERSION_DEFAULT"

    unset pass1 pass2 env_pass hashed
    return 0
}

prompt_master_password_verify() {
    local attempt=""
    local tries=0
    local max_tries=3

    while [ $tries -lt $max_tries ]; do
        if [ -n "${MASTER_PASSWORD:-}" ] && [ $tries -eq 0 ]; then
            attempt="$MASTER_PASSWORD"
        else
            echo -ne "${CYAN}请输入配置加密密码: ${NC}"
            read -rs attempt
            echo
        fi

        if [ -z "$attempt" ]; then
            warn "密码不能为空"
        elif verify_password_secure "$attempt" "$MASTER_PASSWORD_HASH"; then
            MASTER_PASSWORD_SECRET="$attempt"
            return 0
        else
            warn "配置加密密码验证失败"
        fi

        attempt=""
        tries=$((tries + 1))
    done

    return 1
}

ensure_master_password_loaded() {
    if [ -n "${MASTER_PASSWORD_SECRET:-}" ]; then
        return 0
    fi
    if [ -z "${MASTER_PASSWORD_HASH:-}" ]; then
        return 1
    fi
    if prompt_master_password_verify; then
        return 0
    fi
    return 1
}

ensure_master_password_for_encryption() {
    if [ -n "${MASTER_PASSWORD_HASH:-}" ]; then
        if ensure_master_password_loaded; then
            return 0
        fi
        error "配置加密密码验证失败，无法继续保存配置"
        return 1
    fi

    if prompt_new_master_password; then
        return 0
    fi
    return 1
}

encrypt_sensitive_value() {
    local plaintext="$1"
    local password="$2"

    if [ -z "$plaintext" ]; then
        printf '%s' ""
        return 0
    fi
    if [ -z "$password" ]; then
        return 1
    fi

    local ciphertext=""
    if ! ciphertext=$(printf '%s' "$plaintext" | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:"$password" 2>/dev/null | tr -d '\n'); then
        return 1
    fi
    printf '%s\n' "$ciphertext"
}

decrypt_sensitive_value() {
    local ciphertext="$1"
    local password="$2"

    if [ -z "$ciphertext" ]; then
        printf '%s' ""
        return 0
    fi
    if [ -z "$password" ]; then
        return 1
    fi

    local plaintext=""
    if ! plaintext=$(printf '%s' "$ciphertext" | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -d -pass pass:"$password" 2>/dev/null); then
        return 1
    fi
    printf '%s\n' "$plaintext"
}

restore_sensitive_variables_from_config() {
    if [ -z "${MASTER_PASSWORD_SECRET:-}" ]; then
        return 1
    fi

    local var=""
    for var in "${SENSITIVE_CONFIG_VARS[@]}"; do
        local enc_var="${var}_ENC"
        local enc_value="${!enc_var:-}"
        if [ -n "$enc_value" ]; then
            local decrypted=""
            if decrypted=$(decrypt_sensitive_value "$enc_value" "$MASTER_PASSWORD_SECRET"); then
                eval "$var=\"\$decrypted\""
            else
                warn "无法解密配置中的 $var，已跳过"
            fi
        fi
    done

    return 0
}

sanitize_account_conf_secure() {
    local account_conf="$ACME_HOME/account.conf"
    mkdir -p "$ACME_HOME" 2>/dev/null || true
    if [ ! -f "$account_conf" ]; then
        touch "$account_conf" 2>/dev/null || true
    fi

    ensure_master_password_loaded || true

    local tmp_file="${account_conf}.secure"
    : > "$tmp_file"

    local line=""
    while IFS= read -r line || [ -n "$line" ]; do
        local keep=true
        local sensitive_var=""
        for sensitive_var in "${SENSITIVE_CONFIG_VARS[@]}"; do
            if [[ "$line" == ${sensitive_var}=* ]] || [[ "$line" == ${sensitive_var}_ENC=* ]]; then
                keep=false
                break
            fi
        done
        if [ "$keep" = true ]; then
            printf '%s\n' "$line" >> "$tmp_file"
        fi
    done < "$account_conf"

    if [ -n "${MASTER_PASSWORD_SECRET:-}" ]; then
        local sensitive_var=""
        for sensitive_var in "${SENSITIVE_CONFIG_VARS[@]}"; do
            local value="${!sensitive_var:-}"
            if [ -n "$value" ]; then
                local enc_value=""
                if enc_value=$(encrypt_sensitive_value "$value" "$MASTER_PASSWORD_SECRET"); then
                    printf '%s_ENC="%s"\n' "$sensitive_var" "$enc_value" >> "$tmp_file"
                else
                    warn "无法将 $sensitive_var 写入加密存储"
                fi
            fi
        done
    fi

    mv "$tmp_file" "$account_conf" 2>/dev/null || cp "$tmp_file" "$account_conf"
    chmod 600 "$account_conf" 2>/dev/null || true
}

# DNS传播等待倒计时显示
show_dns_propagation_countdown() {
    local wait_seconds="${1:-120}"

    if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
        info "跳过DNS传播等待"
        return 0
    fi

    if [ "$wait_seconds" -le 0 ]; then
        info "跳过DNS传播等待"
        return 0
    fi

    info "等待DNS记录传播 (${wait_seconds}秒)..."

    if [ "$SILENT_MODE" = "true" ] || [ ! -t 1 ]; then
        sleep "$wait_seconds"
        info "DNS记录传播等待完成 (共${wait_seconds}秒)"
        return 0
    fi

    local remaining=$wait_seconds
    local progress_template="[等待] DNS传播中... 剩余时间: %3d 秒"
    local finished_template="[完成] DNS记录传播等待完成 (共%3d秒)"
    local width=${#progress_template}

    if [ ${#finished_template} -gt "$width" ]; then
        width=${#finished_template}
    fi

    while [ $remaining -gt 0 ]; do
        local msg
        printf -v msg "$progress_template" "$remaining"
        printf '\r%b%-*s%b' "$CYAN" "$width" "$msg" "$NC"
        sleep 1
        remaining=$((remaining - 1))
    done

    local final_msg
    printf -v final_msg "$finished_template" "$wait_seconds"
    printf '\r%b%-*s%b\n' "$GREEN" "$width" "$final_msg" "$NC"
}

ensure_quick_launch_directory() {
    local target="$1"

    if [ -z "$target" ]; then
        return 1
    fi

    local dir
    dir=$(dirname "$target")

    if [ -d "$dir" ]; then
        return 0
    fi

    if mkdir -p "$dir" 2>/dev/null; then
        return 0
    fi

    return 1
}

select_quick_launch_path() {
    local candidate=""
    for candidate in "$HOME/bin/ssl" "$HOME/.local/bin/ssl"; do
        if ensure_quick_launch_directory "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    printf '%s\n' ""
    return 1
}

ensure_quick_launch_path_exported() {
    local target="$1"
    if [ -z "$target" ]; then
        return 0
    fi

    local quick_dir
    quick_dir=$(dirname "$target")
    if [ -z "$quick_dir" ]; then
        return 0
    fi

    if [[ ":$PATH:" != *":$quick_dir:"* ]]; then
        export PATH="$quick_dir:$PATH"
        warn "PATH 中未包含 $quick_dir，已临时添加到当前会话"
        local shell_rc=""
        if [ -n "${BASH_VERSION:-}" ] && [ -f "$HOME/.bashrc" ]; then
            shell_rc="$HOME/.bashrc"
        elif [ -n "${ZSH_VERSION:-}" ] && [ -f "$HOME/.zshrc" ]; then
            shell_rc="$HOME/.zshrc"
        elif [ -f "$HOME/.bashrc" ]; then
            shell_rc="$HOME/.bashrc"
        elif [ -f "$HOME/.zshrc" ]; then
            shell_rc="$HOME/.zshrc"
        fi

        if [ -n "$shell_rc" ] && prompt_yesno "是否将 $quick_dir 写入 $shell_rc 以便下次登录自动生效?" "y"; then
            local export_line="export PATH=\"$quick_dir:\$PATH\""
            if ! grep -Fq "$export_line" "$shell_rc" 2>/dev/null; then
                printf '\n%s\n' "$export_line" >> "$shell_rc"
                info "已将 $quick_dir 添加到 $shell_rc"
                info "执行 \"source $shell_rc\" 或重新登录以使 PATH 生效"
            else
                info "$shell_rc 已包含 $quick_dir 配置"
            fi
        else
            info "请手动确保 PATH 中包含: $quick_dir (示例: export PATH=\"$quick_dir:\$PATH\")"
        fi
    fi

    hash -r 2>/dev/null || true
    return 0
}

# 设置快速启动
setup_quick_start() {
    local invocation="${1:-auto}"
    local allow_multiple="false"

    if [ "$invocation" != "auto" ]; then
        allow_multiple="true"
        title "快捷启动设置"
    fi

    local quick_flag_path="$QUICK_START_FLAG_FILE"
    local stored_target=""
    if [ -f "$quick_flag_path" ]; then
        stored_target=$(cat "$quick_flag_path" 2>/dev/null || echo "")
    fi

    local current_target=""
    if type -P ssl >/dev/null 2>&1; then
        current_target=$(type -P ssl)
    elif [ -n "$stored_target" ]; then
        current_target="$stored_target"
    fi

    if [ "$invocation" = "auto" ]; then
        if [ -n "$current_target" ] && [ -x "$current_target" ]; then
            info "快速启动已配置: ssl -> $current_target"
            return 0
        fi
        if ! prompt_yesno "是否设置快捷命令 'ssl' 以便下次快速启动?" "n"; then
            return 0
        fi
    fi

    while true; do
        echo
        if [ -n "$current_target" ] && [ -f "$current_target" ]; then
            info "当前快捷命令: ssl -> $current_target"
        else
            info "当前尚未配置快捷命令 'ssl'"
        fi

        echo -e "${CYAN}请选择操作:${NC}"
        echo "  1) 创建快捷命令 (在线脚本)"
        echo "  2) 创建快捷命令 (使用当前脚本)"
        echo "  3) 创建快捷命令 (自定义本地脚本)"
        echo "  4) 移除快捷命令"
        echo "  0) 返回"
        echo -e "${CYAN}请选择 [0-4]: ${NC}"
        read -r quick_choice

        local completed=false

        case "$quick_choice" in
            0)
                break
                ;;
            1)
                local target_path=""
                target_path=$(select_quick_launch_path) || target_path=""
                if [ -z "$target_path" ]; then
                    warn "无法确定快捷命令保存路径"
                    continue
                fi
                if [ -f "$target_path" ] && ! prompt_yesno "检测到已存在快捷命令 ($target_path)，是否覆盖?" "y"; then
                    continue
                fi
                if ! ensure_quick_launch_directory "$target_path"; then
                    warn "无法创建目录: $(dirname "$target_path")"
                    continue
                fi
                if ! cat <<'EOF' > "$target_path"; then
#!/bin/bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
    echo "curl 未安装，无法下载在线脚本" >&2
    exit 1
fi

exec bash <(curl -fsSL https://raw.githubusercontent.com/227575/Acme-DNS/main/Acme-DNS.sh) "$@"
EOF
                    warn "写入快捷命令失败: $target_path"
                    continue
                fi
                chmod +x "$target_path" 2>/dev/null || true
                current_target="$target_path"
                printf '%s\n' "$current_target" > "$quick_flag_path" 2>/dev/null || true
                ensure_quick_launch_path_exported "$current_target"
                success "已创建快捷命令: ssl (在线脚本)"
                info "现在可以在任何目录直接运行: ssl"
                completed=true
                ;;
            2)
                local target_path=""
                target_path=$(select_quick_launch_path) || target_path=""
                if [ -z "$target_path" ]; then
                    warn "无法确定快捷命令保存路径"
                    continue
                fi
                if [ -f "$target_path" ] && ! prompt_yesno "检测到已存在快捷命令 ($target_path)，是否覆盖?" "y"; then
                    continue
                fi
                if ! ensure_quick_launch_directory "$target_path"; then
                    warn "无法创建目录: $(dirname "$target_path")"
                    continue
                fi
                local script_real_path=""
                script_real_path=$(resolve_path "$0" 2>/dev/null || true)
                if [ -z "$script_real_path" ]; then
                    script_real_path="$0"
                fi
                if [ ! -f "$script_real_path" ]; then
                    warn "未找到当前脚本路径: $script_real_path"
                    continue
                fi
                if ! cat <<EOF > "$target_path"; then
#!/bin/bash
set -euo pipefail
SCRIPT_PATH="$script_real_path"

if [ ! -f "\$SCRIPT_PATH" ]; then
    echo "未找到本地脚本: \$SCRIPT_PATH" >&2
    exit 1
fi

exec "\$SCRIPT_PATH" "\$@"
EOF
                    warn "写入快捷命令失败: $target_path"
                    continue
                fi
                chmod +x "$target_path" 2>/dev/null || true
                current_target="$target_path"
                printf '%s\n' "$current_target" > "$quick_flag_path" 2>/dev/null || true
                ensure_quick_launch_path_exported "$current_target"
                success "已创建快捷命令: ssl (当前脚本)"
                info "现在可以在任何目录直接运行: ssl"
                completed=true
                ;;
            3)
                local custom_path=""
                echo -e "${CYAN}请输入本地脚本绝对路径:${NC}"
                read -r custom_path
                custom_path=$(trim_spaces "$custom_path")
                if [ -z "$custom_path" ]; then
                    warn "路径不能为空"
                    continue
                fi
                local resolved_path=""
                resolved_path=$(resolve_path "$custom_path" 2>/dev/null || true)
                if [ -n "$resolved_path" ]; then
                    custom_path="$resolved_path"
                fi
                if [ ! -f "$custom_path" ]; then
                    warn "指定的脚本不存在: $custom_path"
                    continue
                fi
                local target_path=""
                target_path=$(select_quick_launch_path) || target_path=""
                if [ -z "$target_path" ]; then
                    warn "无法确定快捷命令保存路径"
                    continue
                fi
                if [ -f "$target_path" ] && ! prompt_yesno "检测到已存在快捷命令 ($target_path)，是否覆盖?" "y"; then
                    continue
                fi
                if ! ensure_quick_launch_directory "$target_path"; then
                    warn "无法创建目录: $(dirname "$target_path")"
                    continue
                fi
                if ! cat <<EOF > "$target_path"; then
#!/bin/bash
set -euo pipefail
SCRIPT_PATH="$custom_path"

if [ ! -f "\$SCRIPT_PATH" ]; then
    echo "未找到本地脚本: \$SCRIPT_PATH" >&2
    exit 1
fi

exec "\$SCRIPT_PATH" "\$@"
EOF
                    warn "写入快捷命令失败: $target_path"
                    continue
                fi
                chmod +x "$target_path" 2>/dev/null || true
                current_target="$target_path"
                printf '%s\n' "$current_target" > "$quick_flag_path" 2>/dev/null || true
                ensure_quick_launch_path_exported "$current_target"
                success "已创建快捷命令: ssl (本地脚本)"
                info "快捷命令将执行: $custom_path"
                completed=true
                ;;
            4)
                if ! prompt_yesno "确认移除快捷命令 'ssl' ?" "y"; then
                    continue
                fi
                local removed=false
                local candidate_path=""
                for candidate_path in "$current_target" "$HOME/bin/ssl" "$HOME/.local/bin/ssl"; do
                    if [ -n "$candidate_path" ] && [ -f "$candidate_path" ]; then
                        if [[ "$candidate_path" == "$HOME/"* ]]; then
                            if rm -f "$candidate_path" 2>/dev/null; then
                                removed=true
                            fi
                        fi
                    fi
                done
                if [ "$removed" = true ]; then
                    rm -f "$quick_flag_path" 2>/dev/null || true
                    hash -r 2>/dev/null || true
                    current_target=""
                    success "已移除快捷命令 'ssl'"
                    completed=true
                else
                    warn "未找到可移除的快捷命令文件 (仅移除位于 $HOME/bin 或 $HOME/.local/bin 的文件)"
                fi
                ;;
            *)
                error "无效选择，请输入 0-4 之间的数字"
                ;;
        esac

        if [ "$completed" = true ]; then
            if [ "$allow_multiple" = "true" ]; then
                if prompt_yesno "是否继续配置快捷命令?" "n"; then
                    continue
                fi
            fi
            break
        fi
    done

    return 0
}

run_acme() {
    local use_tee="true"
    local monitor_dns_wait="false"

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --no-tee)
                use_tee="false"
                shift
                ;;
            --monitor-dns-wait)
                monitor_dns_wait="true"
                shift
                ;;
            *)
                break
                ;;
        esac
    done

    local acme_bin="$ACME_HOME/acme.sh"
    if [ ! -x "$acme_bin" ]; then
        fatal "未找到 acme.sh，请先安装"
    fi

    local exit_status=0

    if [ "$monitor_dns_wait" = "true" ]; then
        local line=""
        local wait_seconds=""
        if [ "$use_tee" = "true" ]; then
            "$acme_bin" "$@" 2>&1 | tee -a "$LOG_FILE" | while IFS= read -r line || [ -n "$line" ]; do
                if [[ "$line" =~ Sleeping\ for\ ([0-9]+)\ seconds ]]; then
                    wait_seconds="${BASH_REMATCH[1]}"
                    show_dns_propagation_countdown "$wait_seconds"
                fi
            done
            exit_status=${PIPESTATUS[0]}
        else
            "$acme_bin" "$@" 2>&1 | while IFS= read -r line || [ -n "$line" ]; do
                printf '%s\n' "$line"
                if [ -n "$LOG_FILE" ]; then
                    printf '%s\n' "$line" >> "$LOG_FILE"
                fi
                if [[ "$line" =~ Sleeping\ for\ ([0-9]+)\ seconds ]]; then
                    wait_seconds="${BASH_REMATCH[1]}"
                    show_dns_propagation_countdown "$wait_seconds"
                fi
            done
            exit_status=${PIPESTATUS[0]}
        fi
        sanitize_account_conf_secure
        return $exit_status
    fi

    if [ "$use_tee" = "true" ]; then
        "$acme_bin" "$@" 2>&1 | tee -a "$LOG_FILE"
        exit_status=${PIPESTATUS[0]}
    else
        "$acme_bin" "$@"
        exit_status=$?
    fi

    sanitize_account_conf_secure
    return $exit_status
}

trim_spaces() {
    local value="${1:-}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    echo "$value"
}

ensure_acme_network_tuning() {
    if [ "$ACME_NETWORK_TUNING_APPLIED" = "true" ]; then
        return 0
    fi

    if [ -z "${ACME_CURL_OPTS:-}" ]; then
        ACME_CURL_OPTS="--connect-timeout $ACME_CURL_CONNECT_TIMEOUT --max-time $ACME_CURL_MAX_TIME --retry $ACME_CURL_RETRIES --retry-delay $ACME_CURL_RETRY_DELAY"
        info "应用 ACME 网络优化: connect-timeout=${ACME_CURL_CONNECT_TIMEOUT}s, max-time=${ACME_CURL_MAX_TIME}s, retry=${ACME_CURL_RETRIES}"
    else
        info "使用自定义 ACME 网络参数: $ACME_CURL_OPTS"
    fi

    export ACME_CURL_OPTS
    ACME_NETWORK_TUNING_APPLIED="true"
    return 0
}

get_account_conf_value() {
    local key="$1"
    local file="$2"
    local line=""

    if [ -f "$file" ]; then
        line=$(grep -E "^${key}=" "$file" 2>/dev/null | tail -n1)
    fi

    if [ -z "$line" ]; then
        echo ""
        return 0
    fi

    line="${line#*=}"
    line="${line#\'}"
    line="${line#\"}"
    line="${line%\'}"
    line="${line%\"}"
    echo "$line"
    return 0
}

build_account_candidates() {
    local server="$1"
    local fallback_domain="${2:-${DOMAIN:-$(generate_default_domain)}}"
    local candidates=()
    local extras=()
    local candidate=""
    local server_slug

    server_slug=$(echo "${server:-acme}" | tr '[:upper:]' '[:lower:]')

    if [ -n "${EMAIL:-}" ]; then
        local should_add=true
        for existing in "${candidates[@]}"; do
            if [ "$existing" = "$EMAIL" ]; then
                should_add=false
                break
            fi
        done
        if [ "$should_add" = true ]; then
            candidates+=("$EMAIL")
        fi
    fi

    if [ -n "$ACME_ACCOUNT_POOL" ]; then
        IFS=',' read -r -a extras <<< "$ACME_ACCOUNT_POOL"
        for candidate in "${extras[@]}"; do
            candidate=$(trim_spaces "$candidate")
            if [ -z "$candidate" ]; then
                continue
            fi
            local should_add=true
            for existing in "${candidates[@]}"; do
                if [ "$existing" = "$candidate" ]; then
                    should_add=false
                    break
                fi
            done
            if [ "$should_add" = true ]; then
                candidates+=("$candidate")
            fi
        done
    fi

    while [ ${#candidates[@]} -lt 3 ]; do
        local random_local
        random_local=$(generate_random_string 6 "${server_slug}-")
        candidate="${random_local}@${fallback_domain}"
        local should_add=true
        for existing in "${candidates[@]}"; do
            if [ "$existing" = "$candidate" ]; then
                should_add=false
                break
            fi
        done
        if [ "$should_add" = true ]; then
            candidates+=("$candidate")
        fi
    done

    if [ ${#candidates[@]} -lt 4 ]; then
        local alt_domain
        alt_domain=$(generate_default_domain)
        local random_local
        random_local=$(generate_random_string 6 "auto")
        candidate="${random_local}@${alt_domain}"
        local should_add=true
        for existing in "${candidates[@]}"; do
            if [ "$existing" = "$candidate" ]; then
                should_add=false
                break
            fi
        done
        if [ "$should_add" = true ]; then
            candidates+=("$candidate")
        fi
    fi

    for candidate in "${candidates[@]}"; do
        printf '%s\n' "$candidate"
    done
}

get_dns_api_name() {
    case "$DNS_PROVIDER" in
        cloudflare) echo "dns_cf" ;;
        luadns) echo "dns_lua" ;;
        he) echo "dns_he" ;;
        cloudns) echo "dns_cloudns" ;;
        powerdns) echo "dns_pdns" ;;
        1984hosting) echo "dns_1984hosting" ;;
        desec) echo "dns_desec" ;;
        dynv6) echo "dns_dynv6" ;;
        *) echo "" ;;
    esac
}

# 运行时初始化与环境加载
load_env_file() {
    local file_candidates=("${ENV_FILE}" "$(pwd)/${ENV_FILE}" "$(dirname "$0")/${ENV_FILE}")
    for f in "${file_candidates[@]}"; do
        if [ -f "$f" ]; then
            step "加载环境文件: $f"
            set -a
            . "$f"
            set +a
            success "环境变量已加载"
            return 0
        fi
    done
    return 1
}

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local oldpid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
        warn "检测到另一个实例正在运行 (PID: ${oldpid:-unknown})，若确认无其它实例，请删除 $LOCK_FILE"
        fatal "已退出以避免重复执行"
    fi
    : > "$LOCK_FILE" 2>/dev/null || touch "$LOCK_FILE" 2>/dev/null || true
}

release_lock() {
    rm -f "$LOCK_FILE" 2>/dev/null || true
}

cleanup() {
    # 恢复可能暂停的服务、释放锁、清理临时文件
    restore_standalone_ports 2>/dev/null || true
    release_lock
}

init_runtime() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    load_env_file || true
    trap cleanup EXIT INT TERM
    acquire_lock
}

# 进度指示器
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# 分隔线
separator() {
    echo -e "${CYAN}==================================================${NC}"
}

# 标题
title() {
    echo
    separator
    echo -e "${CYAN}  $1${NC}"
    separator
    echo
}

# 检测操作系统和包管理器
os_detect() {
    step "检测操作系统和包管理器..."
    
    if [ -f /etc/alpine-release ]; then
        OS_TYPE="alpine"
        PKG_MANAGER="apk"
        PKG_INSTALL="apk add --no-cache"
        PKG_UPDATE="apk update"
    elif [ -f /etc/debian_version ]; then
        OS_TYPE="debian"
        PKG_MANAGER="apt-get"
        PKG_INSTALL="apt-get install -y"
        PKG_UPDATE="apt-get update"
    elif [ -f /etc/freebsd-update.conf ]; then
        OS_TYPE="freebsd"
        PKG_MANAGER="pkg"
        PKG_INSTALL="pkg install -y"
        PKG_UPDATE="pkg update"
    else
        OS_TYPE="unknown"
        warn "未知操作系统，尝试继续运行..."
        # 尝试检测可用的包管理器
        if command -v apt-get >/dev/null 2>&1; then
            PKG_MANAGER="apt-get"
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update"
        elif command -v apk >/dev/null 2>&1; then
            PKG_MANAGER="apk"
            PKG_INSTALL="apk add --no-cache"
            PKG_UPDATE="apk update"
        elif command -v pkg >/dev/null 2>&1; then
            PKG_MANAGER="pkg"
            PKG_INSTALL="pkg install -y"
            PKG_UPDATE="pkg update"
        elif command -v yum >/dev/null 2>&1; then
            PKG_MANAGER="yum"
            PKG_INSTALL="yum install -y"
            PKG_UPDATE="yum check-update"
        fi
    fi
    
    info "检测到系统: $OS_TYPE, 包管理器: $PKG_MANAGER"
}

detect_os() { os_detect "$@"; }

# 检查端口占用
check_port_usage() {
    local port=$1
    local protocol=${2:-tcp}
    
    # 检查端口是否被占用
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tuln 2>/dev/null | grep -q ":${port} "; then
            return 0  # 端口被占用
        fi
    elif command -v ss >/dev/null 2>&1; then
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            return 0  # 端口被占用
        fi
    elif command -v sockstat >/dev/null 2>&1; then
        if sockstat -l 2>/dev/null | grep -q ":${port} "; then
            return 0  # 端口被占用
        fi
    fi
    
    return 1  # 端口空闲
}

# 检查端口可访问性
check_port_accessibility() {
    local port=$1
    local timeout=3
    
    # 尝试绑定端口测试
    if command -v nc >/dev/null 2>&1; then
        if nc -z 127.0.0.1 $port >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # 简单的telnet测试
    if command -v telnet >/dev/null 2>&1; then
        if (echo "quit" | telnet 127.0.0.1 $port 2>/dev/null | grep -q "Connected"); then
            return 0
        fi
    fi
    
    return 1
}

# 根据端口获取占用该端口的服务名称
get_service_using_port() {
    local port="$1"
    local pid=""
    local service_name=""
    
    if command -v lsof >/dev/null 2>&1; then
        pid=$(lsof -ti:"$port" 2>/dev/null | head -1)
    elif command -v fuser >/dev/null 2>&1; then
        pid=$(fuser "$port/tcp" 2>/dev/null | awk '{print $1}')
    elif command -v ss >/dev/null 2>&1; then
        pid=$(ss -lntp 2>/dev/null | awk -v port=":$port" '$4 ~ port {print $6}' | cut -d= -f2 | cut -d, -f1 | head -1)
    elif command -v netstat >/dev/null 2>&1; then
        pid=$(netstat -lntp 2>/dev/null | awk -v port=":$port" '$4 ~ port {print $7}' | cut -d'/' -f1 | head -1)
    fi
    
    if [ -n "$pid" ]; then
        service_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
        echo "$service_name"
        return 0
    fi
    
    echo ""
    return 1
}

# 获取服务管理命令
get_service_management_command() {
    local service="$1"
    local action="$2"
    
    if command -v systemctl >/dev/null 2>&1; then
        echo "systemctl $action $service"
    elif command -v service >/dev/null 2>&1; then
        echo "service $service $action"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "rc-service $service $action"
    else
        echo ""
    fi
}

# 管理服务（启动/停止）
manage_service() {
    local service="$1"
    local action="$2"
    local manage_cmd=""
    
    manage_cmd=$(get_service_management_command "$service" "$action")
    
    if [ -z "$manage_cmd" ]; then
        error "无法找到服务管理命令，请手动${action}服务: $service"
        return 1
    fi
    
    info "执行: $manage_cmd"
    if eval "$manage_cmd" &> "$LOG_FILE"; then
        success "服务 $service ${action}成功"
        return 0
    else
        error "服务 $service ${action}失败"
        return 1
    fi
}

# 备份服务原始状态
backup_service_state() {
    local service="$1"
    local manage_cmd=""
    
    manage_cmd=$(get_service_management_command "$service" "status")
    
    if [ -n "$manage_cmd" ]; then
        if eval "$manage_cmd" >/dev/null 2>&1; then
            echo "running"
        else
            echo "stopped"
        fi
    else
        echo "unknown"
    fi
}

# 恢复服务到原始状态
restore_service_state() {
    local service="$1"
    local original_state="$2"
    
    case "$original_state" in
        running)
            info "恢复服务 $service 到运行状态"
            manage_service "$service" "start"
            ;;
        stopped)
            info "服务 $service 原本已停止，保持停止状态"
            manage_service "$service" "stop"
            ;;
        *)
            warn "无法确定服务 $service 的原始状态，请手动检查"
            ;;
    esac
}

# 在使用HTTP/TLS验证前尝试释放端口
setup_standalone_ports() {
    local port="$1"
    local service_name="$2"
    
    step "设置独立验证模式 (端口: $port)"
    
    # 如果端口空闲则无需处理
    if ! check_port_usage "$port"; then
        success "端口 $port 可用"
        return 0
    fi
    
    # 端口被占用，尝试检测服务
    if [ -z "$service_name" ] || [ "$service_name" = "unknown" ]; then
        service_name=$(get_service_using_port "$port")
    fi
    
    if [ -n "$service_name" ] && [ "$service_name" != "unknown" ]; then
        info "检测到服务 '$service_name' 正在使用端口 $port"
        if prompt_yesno "是否授权临时停止 '$service_name' 以完成验证?" "y"; then
            local original_state
            original_state=$(backup_service_state "$service_name")
            SERVICE_TO_RESTART="$service_name:$original_state"
            
            if manage_service "$service_name" "stop"; then
                sleep 2
                if ! check_port_usage "$port"; then
                    success "端口 $port 现在可用"
                    return 0
                else
                    error "端口 $port 仍被占用"
                    return 1
                fi
            else
                error "无法停止服务 '$service_name'"
                return 1
            fi
        else
            info "用户取消操作"
            return 1
        fi
    else
        error "端口 $port 被占用，但无法确定具体服务"
        if prompt_yesno "是否强制继续? (可能失败)" "n"; then
            warn "强制继续，验证可能失败"
            return 0
        else
            return 1
        fi
    fi
}

# 恢复之前临时停止的服务
restore_standalone_ports() {
    if [ -n "$SERVICE_TO_RESTART" ]; then
        step "恢复服务状态"
        local service_name="${SERVICE_TO_RESTART%:*}"
        local original_state="${SERVICE_TO_RESTART#*:}"
        restore_service_state "$service_name" "$original_state"
        SERVICE_TO_RESTART=""
    fi
}

# 将证书同步到指定目录（可选）
sync_certificate_to_dir() {
    if [ -n "$CERT_SYNC_DIR" ]; then
        mkdir -p "$CERT_SYNC_DIR" 2>/dev/null || true
        local cert_dest="$CERT_SYNC_DIR/${DOMAIN}.fullchain.pem"
        local key_dest="$CERT_SYNC_DIR/${DOMAIN}.key"
        cp -f "$CERT_PATH" "$cert_dest" 2>/dev/null || true
        cp -f "$KEY_PATH" "$key_dest" 2>/dev/null || true
        chmod 600 "$key_dest" 2>/dev/null || true
        chmod 644 "$cert_dest" 2>/dev/null || true
        info "证书已同步到目录: $CERT_SYNC_DIR"
    fi
}

notify() {
    return 0
}

# CA 可用性检测
ca_directory_url() {
    case "$1" in
        letsencrypt) echo "https://acme-v02.api.letsencrypt.org/directory" ;;
        zerossl) echo "https://acme.zerossl.com/v2/DV90" ;;
        *) echo "" ;;
    esac
}

ca_is_available() {
    local ca="$1"
    local url="$(ca_directory_url "$ca")"
    if [ -z "$url" ]; then
        return 1
    fi
    curl -fsS -m 5 "$url" >/dev/null 2>&1
}

# 检查并安装依赖
check_deps() {
    step "检查系统依赖"
    
    local deps=""
    local missing_deps=()
    
    # 检测必需的命令
    local required_cmds="curl openssl python3"
    local recommended_cmds="socat cron lsof"
    
    # 根据验证方式调整依赖
    if [ "${VALIDATION_METHOD:-dns}" = "http" ] || [ "${VALIDATION_METHOD:-dns}" = "tls" ]; then
        recommended_cmds="$recommended_cmds nc"
    fi
    
    for cmd in $required_cmds; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    # 检测推荐但不强制的命令
    local missing_recommended=()
    for cmd in $recommended_cmds; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_recommended+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ] && [ ${#missing_recommended[@]} -eq 0 ]; then
        success "所有依赖已安装"
        return 0
    fi
    
    # 安装缺失的必需依赖
    if [ ${#missing_deps[@]} -gt 0 ]; then
        warn "缺少必需依赖: ${missing_deps[*]}"
        echo
        info "将尝试自动安装缺失的依赖..."
        
        if [ -z "$PKG_MANAGER" ]; then
            fatal "未检测到可用的包管理器，请手动安装: ${missing_deps[*]}"
        fi
        
        # 更新包列表
        info "更新包列表..."
        if ! $PKG_UPDATE > /dev/null 2>&1; then
            warn "包列表更新失败，尝试继续安装..."
        fi
        
        # 安装依赖
        for dep in "${missing_deps[@]}"; do
            info "安装 $dep..."
            local pkg_name="$dep"
            
            # 包名映射
            case "$dep" in
                cron)
                    if [ "$OS_TYPE" = "alpine" ]; then
                        pkg_name="dcron"
                    elif [ "$OS_TYPE" = "freebsd" ]; then
                        pkg_name="cronie"
                    fi
                    ;;
            esac
            
            if $PKG_INSTALL "$pkg_name" > /dev/null 2>&1; then
                success "$dep 安装成功"
            else
                fatal "$dep 安装失败，请手动安装后重试"
            fi
        done
    fi
    
    # 提示推荐依赖
    if [ ${#missing_recommended[@]} -gt 0 ]; then
        warn "缺少推荐依赖: ${missing_recommended[*]}"
        echo
        echo -e "${YELLOW}建议安装这些依赖以获得完整功能:${NC}"
        echo -e "${YELLOW}  - socat: 用于 standalone 模式验证${NC}"
        echo -e "${YELLOW}  - cron: 用于自动证书续期${NC}"
        if [ "$VALIDATION_METHOD" = "http" ] || [ "$VALIDATION_METHOD" = "tls" ]; then
            echo -e "${YELLOW}  - nc (netcat): 用于端口检查${NC}"
        fi
        echo
        
        if [ -n "$PKG_MANAGER" ]; then
            if prompt_yesno "是否立即安装推荐依赖?" "y"; then
                for dep in "${missing_recommended[@]}"; do
                    info "安装 $dep..."
                    local pkg_name="$dep"
                    
                    case "$dep" in
                        cron)
                            if [ "$OS_TYPE" = "alpine" ]; then
                                pkg_name="dcron"
                            elif [ "$OS_TYPE" = "freebsd" ]; then
                                pkg_name="cronie"
                            fi
                            ;;
                        nc)
                            if [ "$OS_TYPE" = "alpine" ]; then
                                pkg_name="netcat-openbsd"
                            elif [ "$OS_TYPE" = "debian" ]; then
                                pkg_name="netcat"
                            elif [ "$OS_TYPE" = "freebsd" ]; then
                                pkg_name="netcat"
                            fi
                            ;;
                    esac
                    
                    if $PKG_INSTALL "$pkg_name" > /dev/null 2>&1; then
                        success "$dep 安装成功"
                    else
                        warn "$dep 安装失败，但可以继续运行"
                    fi
                done
            fi
        else
            warn "未检测到包管理器，请手动安装推荐依赖"
        fi
    fi
    
    success "依赖检查完成"
}

check_dependencies() { check_deps "$@"; }

# 用户输入函数
prompt_input() {
    local prompt="$1"
    local var_name="$2"
    local default_value="$3"
    local allow_empty="${4:-false}"
    local input_value=""
    
    # 如果有当前值或默认值，显示提示
    if [ -n "${!var_name}" ]; then
        echo -e "${CYAN}请输入 $prompt [当前: ${!var_name}]: ${NC}"
    elif [ -n "$default_value" ]; then
        echo -e "${CYAN}请输入 $prompt [默认: $default_value]: ${NC}"
    else
        echo -e "${CYAN}请输入 $prompt: ${NC}"
    fi
    
    read -r input_value
    
    # 处理输入
    if [ -z "$input_value" ]; then
        if [ -n "${!var_name}" ]; then
            # 使用当前值，不做修改
            info "使用当前值: ${!var_name}"
        elif [ -n "$default_value" ]; then
            # 使用默认值
            eval "$var_name=\"$default_value\""
            info "使用默认值: $default_value"
        elif [ "$allow_empty" = "true" ]; then
            # 允许空值
            eval "$var_name=\"\""
        else
            error "输入不能为空，请重新输入"
            return 1
        fi
    else
        eval "$var_name=\"$input_value\""
    fi
    
    return 0
}

prompt_password() {
    local prompt="$1"
    local var_name="$2"
    local default_value="$3"
    local input_value=""
    
    if [ -n "${!var_name}" ]; then
        echo -e "${CYAN}请输入 $prompt [当前: ***]: ${NC}"
    elif [ -n "$default_value" ]; then
        echo -e "${CYAN}请输入 $prompt [默认: ***]: ${NC}"
    else
        echo -e "${CYAN}请输入 $prompt: ${NC}"
    fi
    
    read -rs input_value
    echo
    
    if [ -z "$input_value" ]; then
        if [ -n "${!var_name}" ]; then
            info "使用当前密码"
        elif [ -n "$default_value" ]; then
            eval "$var_name=\"$default_value\""
            info "使用默认密码"
        else
            error "输入不能为空，请重新输入"
            return 1
        fi
    else
        eval "$var_name=\"$input_value\""
    fi
    
    return 0
}

prompt_yesno() {
    local prompt="$1"
    local default="${2:-y}"
    local response=""
    
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n] "
    else
        prompt="$prompt [y/N] "
    fi
    
    echo -e "${CYAN}$prompt${NC}"
    read -r response
    
    case "$response" in
        [yY]|"") 
            return 0
            ;;
        [nN]) 
            return 1
            ;;
        *) 
            # 对于无效输入，使用默认值
            if [ "$default" = "y" ]; then
                return 0
            else
                return 1
            fi
            ;;
    esac
}

normalize_key_type() {
    local input
    input=$(printf '%s' "${1:-rsa-2048}" | tr '[:upper:]' '[:lower:]')
    case "$input" in
        rsa|rsa2048|rsa-2048) printf 'rsa-2048' ;;
        rsa4096|rsa-4096) printf 'rsa-4096' ;;
        ec256|ecc256|ec-256|ecc-256) printf 'ec-256' ;;
        ec384|ecc384|ec-384|ecc-384) printf 'ec-384' ;;
        ec521|ecc521|ec-521|ecc-521) printf 'ec-521' ;;
        *) printf 'rsa-2048' ;;
    esac
}

KEY_TYPE=$(normalize_key_type "$KEY_TYPE")

# 选择密钥类型
select_key_type() {
    printf "\n"
    printf "%b请选择密钥类型:%b\n" "${CYAN}" "${NC}"
    printf "  1) RSA 2048 (默认，推荐)\n"
    printf "  2) RSA 4096 (更高安全性，较慢)\n"
    printf "  3) ECC 256 (椭圆曲线，快速)\n"
    printf "  4) ECC 384 (椭圆曲线，更高安全)\n"
    printf "  5) ECC 521 (椭圆曲线，最高安全)\n"
    printf "\n"
    printf "%b请选择 [1-5, 默认: 1]: %b" "${CYAN}" "${NC}"
    read -r key_choice
    
    case "$key_choice" in
        2) KEY_TYPE="rsa-4096" ;;
        3) KEY_TYPE="ec-256" ;;
        4) KEY_TYPE="ec-384" ;;
        5) KEY_TYPE="ec-521" ;;
        *) KEY_TYPE="rsa-2048" ;;
    esac
    KEY_TYPE=$(normalize_key_type "$KEY_TYPE")
    KEY_TYPE_SELECTED="true"
    
    info "已选择密钥类型: $KEY_TYPE"
}

# 获取密钥长度参数
get_keylength_arg() {
    local key_type="${1:-$KEY_TYPE}"
    case "$key_type" in
        rsa-2048) printf "2048" ;;
        rsa-4096) printf "4096" ;;
        ec-256) printf "ec-256" ;;
        ec-384) printf "ec-384" ;;
        ec-521) printf "ec-521" ;;
        *) printf "2048" ;;
    esac
}

# 检查是否为 ECC 密钥
is_ecc_key() {
    local key_type="${1:-$KEY_TYPE}"
    [[ "$key_type" == ec-* ]]
}

prompt_path_with_default() {
    local prompt_label="$1"
    local default_value="$2"
    local input_value=""
    local prompt_text
    prompt_text=$(printf "%b请输入 %s [默认: %s]: %b" "${CYAN}" "$prompt_label" "$default_value" "${NC}")
    read -r -p "$prompt_text" input_value
    if [ -z "$input_value" ]; then
        input_value="$default_value"
    fi
    printf "%s" "$input_value"
}

# 选择菜单函数
show_dns_menu() {
    echo
    echo -e "${CYAN}请选择 DNS 服务商:${NC}"
    echo "  1) CloudFlare (推荐)"
    echo "  2) LuaDNS(APIKEY)"
    echo "  3) Hurricane Electric (HE)"
    echo "  4) ClouDNS(APIKEY)"
    echo "  5) PowerDNS (嵌入式API)"
    echo "  6) 1984Hosting (网站登录令牌)"
    echo "  7) deSEC.io (dynDNS服务)"
    echo "  8) dynv6 (HTTP/SSH API)"
    echo
}

show_acme_menu() {
    echo
    echo -e "${CYAN}请选择 ACME 服务器:${NC}"
    echo "  1) Let's Encrypt (推荐)"
    echo "  2) ZeroSSL"
    echo
}

show_validation_menu() {
    echo
    echo -e "${CYAN}请选择验证方式:${NC}"
    echo "  1) DNS 验证 (支持通配符证书)"
    echo "  2) HTTP 验证 (80端口)"
    echo "  3) TLS 验证 (443端口)"
    echo
}

show_cf_auth_menu() {
    echo
    echo -e "${CYAN}请选择 CloudFlare 认证方式:${NC}"
    echo "  1) API Token (推荐)"
    echo "  2) 全局 API Key (不推荐)"
    echo
}

show_cloudns_auth_menu() {
    echo
    echo -e "${CYAN}请选择 ClouDNS 认证方式:${NC}"
    echo "  1) 子用户 Auth ID (推荐)"
    echo "  2) 常规 Auth ID"
    echo
}

# 返回上级菜单
go_back() {
    if prompt_yesno "是否返回上级菜单?" "y"; then
        return 0
    else
        info "退出程序"
        exit 0
    fi
}

# 配置验证方式
configure_validation_method() {
    step "选择证书验证方式"
    
    # 如果申请通配符证书，只能使用 DNS 验证
    if [ -n "$WILDCARD_DOMAIN" ]; then
        info "通配符证书只能使用 DNS 验证方式"
        VALIDATION_METHOD="dns"
        return 0
    fi
    
    while true; do
        show_validation_menu
        echo -e "${CYAN}请选择验证方式 [1-3]: ${NC}"
        read -r validation_choice
        
        case "$validation_choice" in
            1)
                VALIDATION_METHOD="dns"
                info "已选择 DNS 验证方式"
                break
                ;;
            2)
                VALIDATION_METHOD="http"
                info "已选择 HTTP 验证方式 (80端口)"
                
                # 检查端口占用
                if [ "$SKIP_PORT_CHECK" != "true" ] && check_port_usage 80; then
                    warn "80端口可能被占用。脚本将尝试临时释放并在验证后恢复。"
                    if ! prompt_yesno "是否继续?" "y"; then
                        continue
                    fi
                fi
                break
                ;;
            3)
                VALIDATION_METHOD="tls"
                info "已选择 TLS 验证方式 (443端口)"
                
                # 检查端口占用
                if [ "$SKIP_PORT_CHECK" != "true" ] && check_port_usage 443; then
                    warn "443端口可能被占用。脚本将尝试临时释放并在验证后恢复。"
                    if ! prompt_yesno "是否继续?" "y"; then
                        continue
                    fi
                fi
                break
                ;;
            *)
                error "无效选择，请输入 1-3 之间的数字"
                ;;
        esac
    done
}

# 配置模式选择
select_config_mode() {
    title "SSL证书配置"
    
    # 检查是否有完整的配置
    local has_complete_config=true
    
    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        has_complete_config=false
    elif [ "$VALIDATION_METHOD" = "dns" ]; then
        if [ "$DNS_PROVIDER" = "cloudflare" ]; then
            if [ -z "$CF_Token" ] && [ -z "$CF_Key" ]; then
                has_complete_config=false
            fi
        elif [ "$DNS_PROVIDER" = "luadns" ] && [ -z "$LUA_KEY" ]; then
            has_complete_config=false
        elif [ "$DNS_PROVIDER" = "he" ] && [ -z "$HE_USERNAME" ]; then
            has_complete_config=false
        elif [ "$DNS_PROVIDER" = "cloudns" ]; then
            if [ -z "$CLOUDNS_SUB_AUTH_ID" ] && [ -z "$CLOUDNS_AUTH_ID" ]; then
                has_complete_config=false
            fi
            if [ -z "$CLOUDNS_AUTH_PASSWORD" ]; then
                has_complete_config=false
            fi
        elif [ "$DNS_PROVIDER" = "powerdns" ]; then
            if [ -z "$PDNS_Url" ] || [ -z "$PDNS_Token" ]; then
                has_complete_config=false
            fi
        elif [ "$DNS_PROVIDER" = "1984hosting" ]; then
            if [ -z "$One984HOSTING_Username" ] || [ -z "$One984HOSTING_Password" ]; then
                has_complete_config=false
            fi
        elif [ "$DNS_PROVIDER" = "desec" ]; then
            if [ -z "$DEDYN_TOKEN" ]; then
                has_complete_config=false
            fi
        elif [ "$DNS_PROVIDER" = "dynv6" ]; then
            if [ -z "$DYNV6_TOKEN" ] && [ -z "$DYNV6_KEY" ]; then
                has_complete_config=false
            fi
        fi
    fi
    
    if [ "$has_complete_config" = "true" ]; then
        echo -e "${CYAN}检测到完整的环境变量配置:${NC}"
        show_config
        
        if prompt_yesno "是否使用当前环境变量配置申请证书?" "y"; then
            info "使用环境变量配置"
            return 0
        fi
    fi
    
    echo -e "${CYAN}请选择配置方式:${NC}"
    echo "  1) 快速配置 (使用当前环境变量，仅补充缺失信息)"
    echo "  2) 完整配置 (重新输入所有配置)"
    echo "  3) 查看当前配置"
    echo
    
    while true; do
        echo -e "${CYAN}请选择 [1-3]: ${NC}"
        read -r choice
        
        case "$choice" in
            1)
                info "使用快速配置模式"
                quick_config
                return 0
                ;;
            2)
                info "使用完整配置模式"
                full_config
                return 0
                ;;
            3)
                show_config
                ;;
            *)
                error "无效选择，请输入 1-3 之间的数字"
                ;;
        esac
    done
}

# 快速配置模式
quick_config() {
    info "快速配置模式 - 仅补充缺失的配置信息"
    
    # 域名配置
    if [ -z "$DOMAIN" ]; then
        step "域名配置"
        local default_domain=$(generate_default_domain)
        prompt_input "主域名" "DOMAIN" "$default_domain"
    fi
    
    if [ -z "$WILDCARD_DOMAIN" ] && prompt_yesno "是否申请通配符证书?" "y"; then
        prompt_input "通配符域名" "WILDCARD_DOMAIN" "*.$DOMAIN"
    fi
    
    # 邮箱配置
    if [ -z "$EMAIL" ]; then
        step "邮箱配置"
        local default_email=$(generate_default_email "$DOMAIN")
        prompt_input "邮箱地址" "EMAIL" "$default_email"
    fi
    
    # 验证方式配置
    if [ -z "$VALIDATION_METHOD" ]; then
        configure_validation_method
    else
        info "当前验证方式: $VALIDATION_METHOD"
        if prompt_yesno "是否需要修改验证方式?" "n"; then
            configure_validation_method
        fi
    fi
    
    # DNS提供商配置（仅在DNS验证时需要）
    if [ "$VALIDATION_METHOD" = "dns" ]; then
        if [ -z "$DNS_PROVIDER" ]; then
            step "DNS提供商配置"
            configure_dns_provider
        else
            info "当前DNS提供商: $DNS_PROVIDER"
            if prompt_yesno "是否需要修改DNS提供商配置?" "n"; then
                configure_dns_provider
            else
                # 检查当前DNS提供商的配置是否完整
                case "$DNS_PROVIDER" in
                    cloudflare)
                        configure_cloudflare_credentials
                        ;;
                    luadns)
                        if [ -z "$LUA_KEY" ]; then
                            prompt_input "LuaDNS API Key" "LUA_KEY" ""
                        fi
                        if [ -z "$LUA_EMAIL" ]; then
                            prompt_input "LuaDNS 邮箱" "LUA_EMAIL" "$EMAIL"
                        fi
                        ;;
                    he)
                        if [ -z "$HE_USERNAME" ]; then
                            prompt_input "HE 用户名" "HE_USERNAME" ""
                        fi
                        if [ -z "$HE_PASSWORD" ]; then
                            prompt_password "HE 密码" "HE_PASSWORD" ""
                        fi
                        ;;
                    cloudns)
                        configure_cloudns_credentials
                        ;;
                    powerdns)
                        if [ -z "$PDNS_Url" ]; then
                            prompt_input "PowerDNS API 地址" "PDNS_Url" "${PDNS_Url:-}"
                        fi
                        if [ -z "$PDNS_ServerId" ]; then
                            prompt_input "PowerDNS Server ID" "PDNS_ServerId" "${PDNS_ServerId:-localhost}"
                        fi
                        if [ -z "$PDNS_Token" ]; then
                            prompt_input "PowerDNS API Token" "PDNS_Token" "${PDNS_Token:-}"
                        fi
                        if [ -z "$PDNS_Ttl" ]; then
                            prompt_input "TXT 记录 TTL" "PDNS_Ttl" "${PDNS_Ttl:-60}"
                        fi
                        ;;
                    1984hosting)
                        if [ -z "$One984HOSTING_Username" ]; then
                            prompt_input "1984Hosting 用户名" "One984HOSTING_Username" "${One984HOSTING_Username:-}"
                        fi
                        if [ -z "$One984HOSTING_Password" ]; then
                            prompt_password "1984Hosting 登录密码" "One984HOSTING_Password" "${One984HOSTING_Password:-}"
                        fi
                        ;;
                    desec)
                        if [ -z "$DEDYN_TOKEN" ]; then
                            prompt_input "deSEC API Token" "DEDYN_TOKEN" "${DEDYN_TOKEN:-}"
                        fi
                        ;;
                    dynv6)
                        if [ -z "$DYNV6_TOKEN" ]; then
                            if prompt_yesno "是否现在配置 dynv6 HTTP Token?" "y"; then
                                prompt_input "dynv6 HTTP Token" "DYNV6_TOKEN" "${DYNV6_TOKEN:-}"
                            fi
                        fi
                        if [ -z "$DYNV6_KEY" ]; then
                            if prompt_yesno "是否配置 dynv6 SSH Key?" "n"; then
                                prompt_input "SSH Key 路径" "DYNV6_KEY" "${DYNV6_KEY:-}" "true"
                            fi
                        fi
                        ;;
                esac
            fi
        fi
    fi
    
    # 其他配置
    if prompt_yesno "是否需要修改证书路径配置?" "n"; then
        step "证书路径配置"
        local default_cert_path="/root/ssl/$(generate_random_string 6 "cert_").pem"
        local default_key_path="/root/ssl/$(generate_random_string 6 "key_").key"
        prompt_input "证书文件保存路径" "CERT_PATH" "$default_cert_path"
        prompt_input "私钥文件保存路径" "KEY_PATH" "$default_key_path"
    else
        # 设置默认证书路径
        if [ -z "$CERT_PATH" ]; then
            CERT_PATH="/root/ssl/${DOMAIN}/cert.pem"
        fi
        if [ -z "$KEY_PATH" ]; then
            KEY_PATH="/root/ssl/${DOMAIN}/private.key"
        fi
    fi
    
    if [ -z "$ACME_SERVER" ]; then
        ACME_SERVER="letsencrypt"
        info "ACME 服务器默认设置为 Let's Encrypt"
    else
        info "ACME 服务器: $ACME_SERVER"
    fi
    
    if prompt_yesno "是否配置后续脚本?" "n"; then
        step "后续脚本配置"
        POST_SCRIPT_ENABLED="true"
        prompt_input "后续脚本命令" "POST_SCRIPT_CMD" "" "true"
    fi
}

# 完整配置模式
full_config() {
    info "完整配置模式 - 重新输入所有配置"
    
    # 重置所有配置
    local old_domain="$DOMAIN"
    local old_email="$EMAIL"
    
    DOMAIN=""
    WILDCARD_DOMAIN=""
    EMAIL=""
    VALIDATION_METHOD=""
    DNS_PROVIDER=""
    CF_Token=""
    CF_Zone_ID=""
    CF_Account_ID=""
    CF_Key=""
    CF_Email=""
    LUA_KEY=""
    LUA_EMAIL=""
    HE_USERNAME=""
    HE_PASSWORD=""
    CLOUDNS_AUTH_ID=""
    CLOUDNS_SUB_AUTH_ID=""
    CLOUDNS_AUTH_PASSWORD=""
    PDNS_Url=""
    PDNS_ServerId="localhost"
    PDNS_Token=""
    PDNS_Ttl="60"
    One984HOSTING_Username=""
    One984HOSTING_Password=""
    DEDYN_TOKEN=""
    DYNV6_TOKEN=""
    DYNV6_KEY=""
    ACME_SERVER="letsencrypt"
    POST_SCRIPT_CMD=""
    POST_SCRIPT_ENABLED="false"
    
    # 域名配置
    step "域名配置"
    if [ -n "$old_domain" ]; then
        prompt_input "主域名" "DOMAIN" "$old_domain"
    else
        local default_domain=$(generate_default_domain)
        prompt_input "主域名" "DOMAIN" "$default_domain"
    fi
    
    if prompt_yesno "是否申请通配符证书?" "y"; then
        prompt_input "通配符域名" "WILDCARD_DOMAIN" "*.$DOMAIN"
    fi
    
    # 邮箱配置
    step "邮箱配置"
    if [ -n "$old_email" ]; then
        prompt_input "邮箱地址" "EMAIL" "$old_email"
    else
        local default_email=$(generate_default_email "$DOMAIN")
        prompt_input "邮箱地址" "EMAIL" "$default_email"
    fi
    
    # 验证方式配置
    configure_validation_method
    
    # DNS提供商配置（仅在DNS验证时需要）
    if [ "$VALIDATION_METHOD" = "dns" ]; then
        step "DNS提供商配置"
        configure_dns_provider
    fi
    
    # 证书路径配置
    step "证书路径配置"
    local default_cert_path="/root/ssl/${DOMAIN}/cert.pem"
    local default_key_path="/root/ssl/${DOMAIN}/private.key"
    prompt_input "证书文件保存路径" "CERT_PATH" "$default_cert_path"
    prompt_input "私钥文件保存路径" "KEY_PATH" "$default_key_path"
    
    # ACME服务器配置
    step "ACME服务器配置"
    configure_acme_server
    
    # 后续脚本配置
    step "后续脚本配置"
    if prompt_yesno "证书申请成功后是否执行后续脚本?" "n"; then
        POST_SCRIPT_ENABLED="true"
        echo
        echo -e "${CYAN}请输入要执行的命令:${NC}"
        echo -e "${CYAN}示例: systemctl reload nginx${NC}"
        echo -e "${CYAN}示例: bash /path/to/deploy-script.sh${NC}"
        prompt_input "后续脚本命令" "POST_SCRIPT_CMD" "" "true"
    fi
}

# 配置DNS提供商
configure_dns_provider() {
    while true; do
        show_dns_menu
        echo -e "${CYAN}请选择 [1-8]: ${NC}"
        read -r dns_choice
        
        case "$dns_choice" in
            1)
                DNS_PROVIDER="cloudflare"
                echo
                echo -e "${CYAN}CloudFlare 配置:${NC}"
                configure_cloudflare_credentials
                info "已选择 CloudFlare 作为DNS提供商"
                break
                ;;
            2)
                DNS_PROVIDER="luadns"
                echo
                echo -e "${CYAN}LuaDNS 配置:${NC}"
                echo -e "${CYAN}您需要提供LuaDNS的API密钥。${NC}"
                echo -e "${CYAN}可以在 LuaDNS 控制台的 API Keys 页面获取。${NC}"
                prompt_input "LuaDNS API Key" "LUA_KEY" ""
                prompt_input "LuaDNS 账户邮箱" "LUA_EMAIL" "$EMAIL"
                info "已选择 LuaDNS 作为DNS提供商"
                break
                ;;
            3)
                DNS_PROVIDER="he"
                echo
                echo -e "${CYAN}Hurricane Electric 配置:${NC}"
                echo -e "${CYAN}您需要提供HE的账户用户名和密码。${NC}"
                echo -e "${CYAN}注意: 这不是您邮箱的密码，而是HE账户的密码。${NC}"
                prompt_input "HE 用户名" "HE_USERNAME" ""
                prompt_password "HE 密码" "HE_PASSWORD" ""
                info "已选择 Hurricane Electric 作为DNS提供商"
                break
                ;;
            4)
                DNS_PROVIDER="cloudns"
                echo
                echo -e "${CYAN}ClouDNS 配置:${NC}"
                configure_cloudns_credentials
                info "已选择 ClouDNS 作为DNS提供商"
                break
                ;;
            5)
                DNS_PROVIDER="powerdns"
                echo
                echo -e "${CYAN}PowerDNS 配置:${NC}"
                echo -e "${CYAN}请确保已在 PowerDNS 控制台启用 API 并记录 API Token。${NC}"
                echo -e "${CYAN}参考文档: https://doc.powerdns.com/md/httpapi/README/${NC}"
                prompt_input "PowerDNS API 地址 (如 http://ns.example.com:8081)" "PDNS_Url" "${PDNS_Url:-}"
                prompt_input "PowerDNS Server ID (默认: localhost)" "PDNS_ServerId" "${PDNS_ServerId:-localhost}"
                prompt_input "PowerDNS API Token" "PDNS_Token" "${PDNS_Token:-}"
                prompt_input "TXT 记录 TTL (秒)" "PDNS_Ttl" "${PDNS_Ttl:-60}"
                info "已选择 PowerDNS 作为DNS提供商"
                break
                ;;
            6)
                DNS_PROVIDER="1984hosting"
                echo
                echo -e "${CYAN}1984Hosting 配置:${NC}"
                echo -e "${CYAN}1984Hosting 通过网站登录方式更新DNS记录。${NC}"
                echo -e "${CYAN}需要提供网站登录用户名和密码。首次登录后会缓存认证令牌。${NC}"
                echo -e "${YELLOW}注意: 插件会通过HTTP POST方式登录网站，认证令牌会自动保存到 ~/.acme.sh/account.conf${NC}"
                prompt_input "1984Hosting 用户名" "One984HOSTING_Username" "${One984HOSTING_Username:-}"
                prompt_password "1984Hosting 登录密码" "One984HOSTING_Password" "${One984HOSTING_Password:-}"
                info "已选择 1984Hosting 作为DNS提供商"
                break
                ;;
            7)
                DNS_PROVIDER="desec"
                echo
                echo -e "${CYAN}deSEC.io 配置:${NC}"
                echo -e "${CYAN}请在 https://desec.io 账户中创建 API Token，并限制可访问的 IP/CIDR。${NC}"
                prompt_input "deSEC API Token" "DEDYN_TOKEN" "${DEDYN_TOKEN:-}"
                info "已选择 deSEC.io 作为DNS提供商"
                break
                ;;
            8)
                DNS_PROVIDER="dynv6"
                echo
                echo -e "${CYAN}dynv6 配置:${NC}"
                echo -e "${CYAN}可以选择 HTTP Token 或 SSH Key 两种方式，若同时配置将优先使用 HTTP Token。${NC}"
                if prompt_yesno "是否配置 HTTP Token?" "y"; then
                    prompt_input "dynv6 HTTP Token" "DYNV6_TOKEN" "${DYNV6_TOKEN:-}"
                fi
                if prompt_yesno "是否配置 SSH Key?" "n"; then
                    prompt_input "SSH Key 路径 (将导出为 KEY 环境变量)" "DYNV6_KEY" "${DYNV6_KEY:-}" "true"
                fi
                info "已选择 dynv6 作为DNS提供商"
                break
                ;;
            *)
                error "无效选择，请输入 1-8 之间的数字"
                ;;
        esac
    done
}

# 配置 CloudFlare 认证方式
configure_cloudflare_credentials() {
    while true; do
        show_cf_auth_menu
        echo -e "${CYAN}请选择认证方式 [1-2]: ${NC}"
        read -r cf_auth_choice
        
        case "$cf_auth_choice" in
            1)
                # API Token 方式 (推荐)
                echo
                echo -e "${CYAN}CloudFlare API Token 配置:${NC}"
                echo -e "${CYAN}您需要在 CloudFlare 控制台创建 API Token。${NC}"
                echo -e "${CYAN}所需权限: Zone -> DNS -> Edit${NC}"
                echo
                prompt_input "CloudFlare API Token" "CF_Token" ""
                
                echo
                echo -e "${CYAN}Zone ID 和 Account ID (可选):${NC}"
                echo -e "${CYAN}可以在域名的 Overview 页面找到这些ID。${NC}"
                echo -e "${CYAN}如果留空，acme.sh 会自动检测。${NC}"
                prompt_input "Zone ID (可选)" "CF_Zone_ID" "" "true"
                prompt_input "Account ID (可选)" "CF_Account_ID" "" "true"
                
                # 清除非推荐方式的配置
                CF_Key=""
                CF_Email=""
                break
                ;;
            2)
                # 全局 API Key 方式 (不推荐)
                echo
                echo -e "${YELLOW}警告: 全局 API Key 方式不推荐使用，因为泄漏会完全危害您的账户。${NC}"
                echo -e "${CYAN}您可以在 CloudFlare 控制台的 API Tokens 页面找到全局 API Key。${NC}"
                echo
                if prompt_yesno "确定要使用不推荐的全局 API Key 方式吗?" "n"; then
                    prompt_input "CloudFlare 邮箱" "CF_Email" "$EMAIL"
                    prompt_input "CloudFlare 全局 API Key" "CF_Key" ""
                    
                    # 清除推荐方式的配置
                    CF_Token=""
                    CF_Zone_ID=""
                    CF_Account_ID=""
                    break
                fi
                ;;
            *)
                error "无效选择，请输入 1 或 2"
                ;;
        esac
    done
}

# 配置 ClouDNS 认证方式
configure_cloudns_credentials() {
    while true; do
        show_cloudns_auth_menu
        echo -e "${CYAN}请选择认证方式 [1-2]: ${NC}"
        read -r cloudns_auth_choice
        
        case "$cloudns_auth_choice" in
            1)
                # 子用户 Auth ID 方式 (推荐)
                echo
                echo -e "${CYAN}ClouDNS 子用户 Auth ID 配置:${NC}"
                echo -e "${CYAN}您需要在 ClouDNS 控制台创建子用户。${NC}"
                echo -e "${CYAN}推荐使用子用户 Auth ID，因为它只能访问特定区域。${NC}"
                echo
                prompt_input "ClouDNS 子用户 Auth ID" "CLOUDNS_SUB_AUTH_ID" ""
                prompt_password "ClouDNS 密码" "CLOUDNS_AUTH_PASSWORD" ""
                
                # 清除非推荐方式的配置
                CLOUDNS_AUTH_ID=""
                break
                ;;
            2)
                # 常规 Auth ID 方式
                echo
                echo -e "${YELLOW}注意: 常规 Auth ID 可以访问您的整个账户，建议使用子用户 Auth ID。${NC}"
                echo -e "${CYAN}您可以在 ClouDNS 控制台的 API 设置页面找到 Auth ID。${NC}"
                echo
                if prompt_yesno "确定要使用常规 Auth ID 方式吗?" "n"; then
                    prompt_input "ClouDNS 常规 Auth ID" "CLOUDNS_AUTH_ID" ""
                    prompt_password "ClouDNS 密码" "CLOUDNS_AUTH_PASSWORD" ""
                    
                    # 清除推荐方式的配置
                    CLOUDNS_SUB_AUTH_ID=""
                    break
                fi
                ;;
            *)
                error "无效选择，请输入 1 或 2"
                ;;
        esac
    done
}

# 配置ACME服务器
configure_acme_server() {
    while true; do
        show_acme_menu
        echo -e "${CYAN}请选择 [1-2]: ${NC}"
        read -r acme_choice
        
        case "$acme_choice" in
            1)
                ACME_SERVER="letsencrypt"
                info "已选择 Let's Encrypt 作为ACME服务器（推荐）"
                break
                ;;
            2)
                ACME_SERVER="zerossl"
                info "已选择 ZeroSSL 作为ACME服务器"
                break
                ;;
            *)
                error "无效选择，请输入 1-2 之间的数字"
                ;;
        esac
    done
}

# 配置通知设置
configure_notification() {
    title "配置通知设置"
    
    info "通知功能说明："
    echo "  • 通知功能可在证书操作（申请、续期等）完成后发送通知消息"
    echo "  • 支持 Telegram、Webhook 和邮件通知"
    echo "  • 可配置成功和失败时分别是否发送通知"
    echo "  • 续期任务通过通知可知晓脚本是否运行成功"
    echo
    
    local enable_default="n"
    if [ "$NOTIFY_ENABLED" = "true" ]; then
        enable_default="y"
    fi
    
    if prompt_yesno "是否启用通知功能?" "$enable_default"; then
        NOTIFY_ENABLED="true"
        
        local success_default="n"
        if [ "$NOTIFY_ON_SUCCESS" = "true" ]; then
            success_default="y"
        fi
        if prompt_yesno "操作成功时发送通知?" "$success_default"; then
            NOTIFY_ON_SUCCESS="true"
        else
            NOTIFY_ON_SUCCESS="false"
        fi
        
        local failure_default="y"
        if [ "$NOTIFY_ON_FAILURE" != "true" ]; then
            failure_default="n"
        fi
        if prompt_yesno "操作失败时发送通知?" "$failure_default"; then
            NOTIFY_ON_FAILURE="true"
        else
            NOTIFY_ON_FAILURE="false"
        fi
        
        echo
        info "请选择通知方式（可多选，可留空沿用当前配置）："
        
        local telegram_default="n"
        if [ -n "$TELEGRAM_BOT_TOKEN" ] || [ -n "$TELEGRAM_CHAT_ID" ]; then
            telegram_default="y"
        fi
        if prompt_yesno "是否配置 Telegram 通知?" "$telegram_default"; then
            prompt_input "Telegram Bot Token" "TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN" "true"
            prompt_input "Telegram Chat ID" "TELEGRAM_CHAT_ID" "$TELEGRAM_CHAT_ID" "true"
        elif [ "$telegram_default" = "y" ] && prompt_yesno "是否清除 Telegram 通知配置?" "n"; then
            TELEGRAM_BOT_TOKEN=""
            TELEGRAM_CHAT_ID=""
        fi
        
        local webhook_default="n"
        if [ -n "$WEBHOOK_URL" ]; then
            webhook_default="y"
        fi
        if prompt_yesno "是否配置 Webhook 通知?" "$webhook_default"; then
            info "Webhook 将以 JSON 格式 POST: {\"text\":\"消息内容\"}"
            prompt_input "Webhook URL" "WEBHOOK_URL" "$WEBHOOK_URL" "true"
        elif [ "$webhook_default" = "y" ] && prompt_yesno "是否清除 Webhook 配置?" "n"; then
            WEBHOOK_URL=""
        fi
        
        local mail_default="n"
        if [ -n "$MAIL_TO" ]; then
            mail_default="y"
        fi
        if prompt_yesno "是否配置邮件通知?" "$mail_default"; then
            info "邮件通知需要系统已安装并配置 sendmail 或 mailx"
            prompt_input "收件邮箱" "MAIL_TO" "$MAIL_TO" "true"
            prompt_input "邮件主题前缀" "MAIL_SUBJECT_PREFIX" "${MAIL_SUBJECT_PREFIX:-[Acme-DNS]}" "true"
        elif [ "$mail_default" = "y" ] && prompt_yesno "是否清除邮件通知配置?" "n"; then
            MAIL_TO=""
        fi
        
        if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ -z "$WEBHOOK_URL" ] && [ -z "$MAIL_TO" ]; then
            warn "未配置任何通知渠道，启用通知后将不会发送消息"
        else
            success "通知配置完成"
        fi
    else
        NOTIFY_ENABLED="false"
        info "通知功能已禁用"
        if prompt_yesno "是否同时清除所有通知配置?" "n"; then
            TELEGRAM_BOT_TOKEN=""
            TELEGRAM_CHAT_ID=""
            WEBHOOK_URL=""
            MAIL_TO=""
            MAIL_SUBJECT_PREFIX="[Acme-DNS]"
            NOTIFY_ON_SUCCESS="false"
            NOTIFY_ON_FAILURE="false"
            info "已清除通知相关配置"
        fi
    fi
}

# 发送通知
send_notification() {
    local status="$1"
    local title="$2"
    local message="$3"
    
    if [ "$NOTIFY_ENABLED" != "true" ]; then
        return 0
    fi
    
    if [ "$status" = "success" ] && [ "$NOTIFY_ON_SUCCESS" != "true" ]; then
        return 0
    fi
    
    if [ "$status" = "failure" ] && [ "$NOTIFY_ON_FAILURE" != "true" ]; then
        return 0
    fi
    
    if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ -z "$WEBHOOK_URL" ] && [ -z "$MAIL_TO" ]; then
        debug "通知已启用但未配置任何渠道，跳过发送"
        return 0
    fi
    
    local emoji=""
    if [ "$status" = "success" ]; then
        emoji="✅"
    else
        emoji="❌"
    fi
    
    local full_message="${emoji} ${title}

${message}

时间: $(date '+%Y-%m-%d %H:%M:%S')
主机: $(hostname)"
    
    local sanitized_json
    sanitized_json=$(printf '%s' "$full_message" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
    
    local sent=false
    
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
        debug "发送 Telegram 通知..."
        if curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            --data-urlencode "text=${full_message}" >/dev/null 2>&1; then
            debug "Telegram 通知发送成功"
            sent=true
        else
            warn "Telegram 通知发送失败"
        fi
    fi
    
    if [ -n "$WEBHOOK_URL" ]; then
        debug "发送 Webhook 通知..."
        local webhook_json="{\"text\":\"${sanitized_json}\"}"
        if curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "$webhook_json" >/dev/null 2>&1; then
            debug "Webhook 通知发送成功"
            sent=true
        else
            warn "Webhook 通知发送失败"
        fi
    fi
    
    if [ -n "$MAIL_TO" ]; then
        debug "发送邮件通知..."
        local mail_cmd=""
        if command -v sendmail >/dev/null 2>&1; then
            mail_cmd="sendmail"
        elif command -v mailx >/dev/null 2>&1; then
            mail_cmd="mailx"
        elif command -v mail >/dev/null 2>&1; then
            mail_cmd="mail"
        fi
        
        if [ -n "$mail_cmd" ]; then
            local subject="${MAIL_SUBJECT_PREFIX} ${title}"
            if echo "$full_message" | $mail_cmd -s "$subject" "$MAIL_TO" 2>/dev/null; then
                debug "邮件通知发送成功"
                sent=true
            else
                warn "邮件通知发送失败"
            fi
        else
            warn "未找到邮件发送命令（sendmail/mailx/mail）"
        fi
    fi
    
    if [ "$sent" != "true" ]; then
        warn "通知发送未成功，请检查通知渠道配置"
        return 1
    fi
    
    info "通知已发送"
}

# 验证配置
validate_config() {
    local errors=0
    
    if [ -z "$DOMAIN" ]; then
        error "域名未设置"
        errors=$((errors + 1))
    fi
    
    if [ -z "$EMAIL" ]; then
        error "邮箱未设置"
        errors=$((errors + 1))
    fi
    
    if [ -z "$VALIDATION_METHOD" ]; then
        error "验证方式未设置"
        errors=$((errors + 1))
    fi

    # DNS验证需要DNS提供商配置
    if [ "$VALIDATION_METHOD" = "dns" ]; then
        case "$DNS_PROVIDER" in
            cloudflare)
                if [ -z "$CF_Token" ] && [ -z "$CF_Key" ]; then
                    error "CloudFlare 认证信息未设置"
                    errors=$((errors + 1))
                fi
                if [ -n "$CF_Key" ] && [ -z "$CF_Email" ]; then
                    error "使用全局 API Key 时需要设置邮箱"
                    errors=$((errors + 1))
                fi
                ;;
            luadns)
                if [ -z "$LUA_KEY" ]; then
                    error "LuaDNS API Key 未设置"
                    errors=$((errors + 1))
                fi
                if [ -z "$LUA_EMAIL" ]; then
                    LUA_EMAIL="$EMAIL"
                fi
                ;;
            he)
                if [ -z "$HE_USERNAME" ]; then
                    error "HE 用户名未设置"
                    errors=$((errors + 1))
                fi
                if [ -z "$HE_PASSWORD" ]; then
                    error "HE 密码未设置"
                    errors=$((errors + 1))
                fi
                ;;
            cloudns)
                if [ -z "$CLOUDNS_SUB_AUTH_ID" ] && [ -z "$CLOUDNS_AUTH_ID" ]; then
                    error "ClouDNS Auth ID 未设置"
                    errors=$((errors + 1))
                fi
                if [ -z "$CLOUDNS_AUTH_PASSWORD" ]; then
                    error "ClouDNS 密码未设置"
                    errors=$((errors + 1))
                fi
                ;;
            powerdns)
                if [ -z "$PDNS_Url" ]; then
                    error "PowerDNS API 地址未设置"
                    errors=$((errors + 1))
                fi
                if [ -z "$PDNS_Token" ]; then
                    error "PowerDNS API Token 未设置"
                    errors=$((errors + 1))
                fi
                if [ -z "$PDNS_ServerId" ]; then
                    warn "PowerDNS Server ID 未设置，默认使用 localhost"
                    PDNS_ServerId="localhost"
                fi
                ;;
            1984hosting)
                if [ -z "$One984HOSTING_Username" ]; then
                    error "1984Hosting 用户名未设置"
                    errors=$((errors + 1))
                fi
                if [ -z "$One984HOSTING_Password" ]; then
                    error "1984Hosting 登录密码未设置"
                    errors=$((errors + 1))
                fi
                ;;
            desec)
                if [ -z "$DEDYN_TOKEN" ]; then
                    error "deSEC API Token 未设置"
                    errors=$((errors + 1))
                fi
                ;;
            dynv6)
                if [ -z "$DYNV6_TOKEN" ] && [ -z "$DYNV6_KEY" ]; then
                    error "dynv6 需要配置 HTTP Token 或 SSH Key 至少一种方式"
                    errors=$((errors + 1))
                fi
                ;;
            *)
                error "不支持的 DNS 提供商: $DNS_PROVIDER"
                errors=$((errors + 1))
                ;;
        esac
    fi
    
    # HTTP/TLS验证需要检查端口
    if [ "$VALIDATION_METHOD" = "http" ] || [ "$VALIDATION_METHOD" = "tls" ]; then
        local port=""
        if [ "$VALIDATION_METHOD" = "http" ]; then
            port=80
        else
            port=443
        fi
        
        if [ "$SKIP_PORT_CHECK" != "true" ] && check_port_usage $port; then
            warn "端口 $port 可能被占用，验证可能失败"
            if ! prompt_yesno "是否继续?" "y"; then
                errors=$((errors + 1))
            fi
        fi
    fi
    
    if [ $errors -gt 0 ]; then
        error "发现 $errors 个配置错误，请检查后重试"
        return 1
    fi
    
    return 0
}

# 显示配置信息
show_config() {
    echo
    echo -e "${CYAN}当前配置信息:${NC}"
    echo "  • 主域名: ${DOMAIN:-未设置}"
    if [ -n "$WILDCARD_DOMAIN" ]; then
        echo "  • 通配符域名: $WILDCARD_DOMAIN"
    fi
    echo "  • 邮箱: ${EMAIL:-未设置}"
    echo "  • 验证方式: ${VALIDATION_METHOD:-未设置}"
    
    if [ "$VALIDATION_METHOD" = "dns" ]; then
        echo -e "${CYAN}DNS配置:${NC}"
        echo "  • DNS提供商: ${DNS_PROVIDER:-未设置}"
        
        case "$DNS_PROVIDER" in
            cloudflare)
                if [ -n "$CF_Token" ]; then
                    echo "  • CloudFlare Token: ${CF_Token:0:8}**** (API Token)"
                    if [ -n "$CF_Zone_ID" ]; then
                        echo "  • Zone ID: $CF_Zone_ID"
                    fi
                    if [ -n "$CF_Account_ID" ]; then
                        echo "  • Account ID: $CF_Account_ID"
                    fi
                elif [ -n "$CF_Key" ]; then
                    echo "  • CloudFlare Key: ${CF_Key:0:8}**** (全局 API Key)"
                    echo "  • CloudFlare 邮箱: $CF_Email"
                else
                    echo "  • CloudFlare 认证: 未设置"
                fi
                ;;
            luadns)
                if [ -n "$LUA_KEY" ]; then
                    echo "  • LuaDNS Key: ${LUA_KEY:0:8}****"
                else
                    echo "  • LuaDNS Key: 未设置"
                fi
                echo "  • LuaDNS 邮箱: ${LUA_EMAIL:-未设置}"
                ;;
            he)
                echo "  • HE 用户名: ${HE_USERNAME:-未设置}"
                if [ -n "$HE_PASSWORD" ]; then
                    echo "  • HE 密码: ${HE_PASSWORD:0:8}****"
                else
                    echo "  • HE 密码: 未设置"
                fi
                ;;
            cloudns)
                if [ -n "$CLOUDNS_SUB_AUTH_ID" ]; then
                    echo "  • ClouDNS 子用户 Auth ID: ${CLOUDNS_SUB_AUTH_ID:0:8}****"
                elif [ -n "$CLOUDNS_AUTH_ID" ]; then
                    echo "  • ClouDNS 常规 Auth ID: ${CLOUDNS_AUTH_ID:0:8}****"
                else
                    echo "  • ClouDNS Auth ID: 未设置"
                fi
                if [ -n "$CLOUDNS_AUTH_PASSWORD" ]; then
                    echo "  • ClouDNS 密码: ${CLOUDNS_AUTH_PASSWORD:0:8}****"
                else
                    echo "  • ClouDNS 密码: 未设置"
                fi
                ;;
            powerdns)
                echo "  • PowerDNS API 地址: ${PDNS_Url:-未设置}"
                echo "  • PowerDNS Server ID: ${PDNS_ServerId:-localhost}"
                if [ -n "$PDNS_Token" ]; then
                    echo "  • PowerDNS Token: ${PDNS_Token:0:8}****"
                else
                    echo "  • PowerDNS Token: 未设置"
                fi
                echo "  • TXT 记录 TTL: ${PDNS_Ttl:-60} 秒"
                ;;
            1984hosting)
                echo "  • 1984Hosting 用户名: ${One984HOSTING_Username:-未设置}"
                if [ -n "$One984HOSTING_Password" ]; then
                    echo "  • 1984Hosting 密码: ${One984HOSTING_Password:0:3}******"
                else
                    echo "  • 1984Hosting 密码: 未设置"
                fi
                echo "  • 提示: 首次登录后会自动缓存认证令牌"
                ;;
            desec)
                if [ -n "$DEDYN_TOKEN" ]; then
                    echo "  • deSEC API Token: ${DEDYN_TOKEN:0:8}****"
                else
                    echo "  • deSEC API Token: 未设置"
                fi
                echo "  • 建议: 在 deSEC 控制台限制 Token 可访问的 IP"
                ;;
            dynv6)
                if [ -n "$DYNV6_TOKEN" ]; then
                    echo "  • dynv6 HTTP Token: ${DYNV6_TOKEN:0:8}****"
                else
                    echo "  • dynv6 HTTP Token: 未设置"
                fi
                if [ -n "$DYNV6_KEY" ]; then
                    echo "  • dynv6 SSH Key 路径: $DYNV6_KEY"
                else
                    echo "  • dynv6 SSH Key: 未配置"
                fi
                ;;
        esac
    elif [ "$VALIDATION_METHOD" = "http" ]; then
        echo -e "${CYAN}HTTP验证配置:${NC}"
        echo "  • 验证端口: $HTTP_PORT"
        echo "  • 注意: 需要确保80端口可访问且未被占用"
    elif [ "$VALIDATION_METHOD" = "tls" ]; then
        echo -e "${CYAN}TLS验证配置:${NC}"
        echo "  • 验证端口: $TLS_PORT"
        echo "  • 注意: 需要确保443端口可访问且未被占用"
    fi
    
    echo -e "${CYAN}证书配置:${NC}"
    echo "  • 证书路径: ${CERT_PATH:-未设置}"
    echo "  • 私钥路径: ${KEY_PATH:-未设置}"
    echo "  • 密钥类型: ${KEY_TYPE:-rsa-2048}"
    echo "  • ACME服务器: $ACME_SERVER"
    echo "  • 客户端: ${ACME_CLIENT:-acme.sh}"
    echo "  • CA回退顺序: ${ACME_CA_LIST}"
    if [ -n "$CERT_SYNC_DIR" ]; then
        echo "  • 同步目录: $CERT_SYNC_DIR"
    fi
    echo "  • 日志文件: $LOG_FILE (静默模式: $SILENT_MODE)"
    
    if [ "$POST_SCRIPT_ENABLED" = "true" ] && [ -n "$POST_SCRIPT_CMD" ]; then
        echo -e "${CYAN}后续脚本:${NC}"
        echo "  • 后续命令: $POST_SCRIPT_CMD"
    fi
    
    echo -e "${CYAN}通知配置:${NC}"
    echo "  • 通知状态: $([ "$NOTIFY_ENABLED" = "true" ] && echo "已启用" || echo "已禁用")"
    if [ "$NOTIFY_ENABLED" = "true" ]; then
        echo "  • 成功通知: $([ "$NOTIFY_ON_SUCCESS" = "true" ] && echo "是" || echo "否")"
        echo "  • 失败通知: $([ "$NOTIFY_ON_FAILURE" = "true" ] && echo "是" || echo "否")"
        if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ]; then
            echo "  • Telegram: 已配置"
        fi
        if [ -n "$WEBHOOK_URL" ]; then
            echo "  • Webhook: 已配置"
        fi
        if [ -n "$MAIL_TO" ]; then
            echo "  • 邮件: $MAIL_TO"
        fi
    fi
    echo
}

# 修改配置
modify_config() {
    title "修改配置"
    
    while true; do
        show_config
        
        echo -e "${CYAN}请选择要修改的配置:${NC}"
        echo "  1) 域名配置"
        echo "  2) 验证方式配置"
        echo "  3) DNS提供商配置"
        echo "  4) 证书路径配置"
        echo "  5) ACME服务器配置"
        echo "  6) 通知配置"
        echo "  7) 后续脚本配置"
        echo "  8) 密钥类型配置"
        echo "  9) 返回主菜单"
        echo
        
        echo -e "${CYAN}请选择 [1-9]: ${NC}"
        read -r choice
        
        case "$choice" in
            1)
                step "修改域名配置"
                prompt_input "主域名" "DOMAIN" "$DOMAIN"
                if prompt_yesno "是否申请通配符证书?" "y"; then
                    prompt_input "通配符域名" "WILDCARD_DOMAIN" "*.$DOMAIN"
                else
                    WILDCARD_DOMAIN=""
                fi
                prompt_input "邮箱地址" "EMAIL" "$EMAIL"
                ;;
            2)
                step "修改验证方式配置"
                configure_validation_method
                ;;
            3)
                if [ "$VALIDATION_METHOD" = "dns" ]; then
                    step "修改DNS提供商配置"
                    configure_dns_provider
                else
                    error "当前验证方式不是DNS，无需配置DNS提供商"
                fi
                ;;
            4)
                step "修改证书路径配置"
                prompt_input "证书文件保存路径" "CERT_PATH" "$CERT_PATH"
                prompt_input "私钥文件保存路径" "KEY_PATH" "$KEY_PATH"
                ;;
            5)
                step "修改ACME服务器配置"
                configure_acme_server
                ;;
            6)
                configure_notification
                ;;
            7)
                step "修改后续脚本配置"
                if prompt_yesno "是否启用后续脚本?" "n"; then
                    POST_SCRIPT_ENABLED="true"
                    prompt_input "后续脚本命令" "POST_SCRIPT_CMD" "$POST_SCRIPT_CMD" "true"
                else
                    POST_SCRIPT_ENABLED="false"
                    POST_SCRIPT_CMD=""
                fi
                ;;
            8)
                step "修改密钥类型"
                select_key_type
                ;;
            9)
                info "返回主菜单"
                return 0
                ;;
            *)
                error "无效选择，请输入 1-9 之间的数字"
                ;;
        esac
        
        echo
        if ! prompt_yesno "是否继续修改其他配置?" "y"; then
            break
        fi
    done
}

# 保存配置到文件
save_config() {
    local config_file="${1:-./ssl-manager.conf}"

    step "保存配置到文件: $config_file"

    if ! ensure_master_password_for_encryption; then
        return 1
    fi

    local master_password="$MASTER_PASSWORD_SECRET"
    local sensitive_var=""
    for sensitive_var in "${SENSITIVE_CONFIG_VARS[@]}"; do
        local value="${!sensitive_var:-}"
        local enc_value=""
        if [ -n "$value" ] && [ -n "$master_password" ]; then
            if ! enc_value=$(encrypt_sensitive_value "$value" "$master_password"); then
                error "加密敏感信息 $sensitive_var 失败，配置未保存"
                return 1
            fi
        fi
        local enc_var="${sensitive_var}_ENC"
        printf -v "$enc_var" '%s' "$enc_value"
    done

    info "敏感凭据已使用加密方式保存到配置文件"
    info "~/.acme.sh/account.conf 中的敏感字段将同步加密处理"

    cat > "$config_file" << EOF
# SSL证书管理脚本配置文件
# 生成时间: $(date)
# 安全说明: 所有敏感信息均使用 AES-256-CBC + PBKDF2 加密保存，需配置密码才能解密

CONFIG_ENCRYPTION_VERSION="$CONFIG_ENCRYPTION_VERSION"
MASTER_PASSWORD_HASH="$MASTER_PASSWORD_HASH"

# 域名配置
DOMAIN="$DOMAIN"
WILDCARD_DOMAIN="$WILDCARD_DOMAIN"
EMAIL="$EMAIL"

# 验证方式配置
VALIDATION_METHOD="$VALIDATION_METHOD"
HTTP_PORT="$HTTP_PORT"
TLS_PORT="$TLS_PORT"
SKIP_PORT_CHECK="$SKIP_PORT_CHECK"

# 密钥类型
KEY_TYPE="$KEY_TYPE"

# DNS提供商配置
DNS_PROVIDER="$DNS_PROVIDER"
CF_Zone_ID="$CF_Zone_ID"
CF_Account_ID="$CF_Account_ID"
CF_Email="$CF_Email"
LUA_EMAIL="$LUA_EMAIL"
HE_USERNAME="$HE_USERNAME"
CLOUDNS_AUTH_ID="$CLOUDNS_AUTH_ID"
CLOUDNS_SUB_AUTH_ID="$CLOUDNS_SUB_AUTH_ID"
PDNS_Url="$PDNS_Url"
PDNS_ServerId="$PDNS_ServerId"
PDNS_Ttl="$PDNS_Ttl"
One984HOSTING_Username="$One984HOSTING_Username"

# 证书路径配置
CERT_PATH="$CERT_PATH"
KEY_PATH="$KEY_PATH"

# ACME服务器配置
ACME_SERVER="$ACME_SERVER"

# 后续脚本配置
POST_SCRIPT_CMD="$POST_SCRIPT_CMD"
POST_SCRIPT_ENABLED="$POST_SCRIPT_ENABLED"

# 客户端与CA
ACME_CLIENT="$ACME_CLIENT"
ACME_CA_LIST="$ACME_CA_LIST"

# ACME 网络优化
ACME_ACCOUNT_POOL="$ACME_ACCOUNT_POOL"
ACME_REGISTER_TIMEOUT="$ACME_REGISTER_TIMEOUT"
ACME_CURL_CONNECT_TIMEOUT="$ACME_CURL_CONNECT_TIMEOUT"
ACME_CURL_MAX_TIME="$ACME_CURL_MAX_TIME"
ACME_CURL_RETRIES="$ACME_CURL_RETRIES"
ACME_CURL_RETRY_DELAY="$ACME_CURL_RETRY_DELAY"
ACME_RETRY_DELAY="$ACME_RETRY_DELAY"

# 运行与环境
ENV_FILE="$ENV_FILE"
LOG_FILE="$LOG_FILE"
LOG_MAX_SIZE_KB="$LOG_MAX_SIZE_KB"
SILENT_MODE="$SILENT_MODE"
RENEW_THRESHOLD_DAYS="$RENEW_THRESHOLD_DAYS"

# Webroot 与同步
WEBROOT_PATH="$WEBROOT_PATH"
CERT_SYNC_DIR="$CERT_SYNC_DIR"
SERVICE_RELOAD_CMD="$SERVICE_RELOAD_CMD"

# 通知
NOTIFY_ENABLED="$NOTIFY_ENABLED"
NOTIFY_ON_SUCCESS="$NOTIFY_ON_SUCCESS"
NOTIFY_ON_FAILURE="$NOTIFY_ON_FAILURE"
TELEGRAM_CHAT_ID="$TELEGRAM_CHAT_ID"
MAIL_TO="$MAIL_TO"
MAIL_SUBJECT_PREFIX="$MAIL_SUBJECT_PREFIX"

# 加密存储的敏感参数
CF_Token_ENC="${CF_Token_ENC:-}"
CF_Key_ENC="${CF_Key_ENC:-}"
LUA_KEY_ENC="${LUA_KEY_ENC:-}"
HE_PASSWORD_ENC="${HE_PASSWORD_ENC:-}"
CLOUDNS_AUTH_PASSWORD_ENC="${CLOUDNS_AUTH_PASSWORD_ENC:-}"
PDNS_Token_ENC="${PDNS_Token_ENC:-}"
One984HOSTING_Password_ENC="${One984HOSTING_Password_ENC:-}"
DEDYN_TOKEN_ENC="${DEDYN_TOKEN_ENC:-}"
DYNV6_TOKEN_ENC="${DYNV6_TOKEN_ENC:-}"
DYNV6_KEY_ENC="${DYNV6_KEY_ENC:-}"
TELEGRAM_BOT_TOKEN_ENC="${TELEGRAM_BOT_TOKEN_ENC:-}"
WEBHOOK_URL_ENC="${WEBHOOK_URL_ENC:-}"
EOF

    chmod 600 "$config_file"
    sanitize_account_conf_secure
    success "配置已保存到: $config_file"
}

# 从文件加载配置
load_config() {
    local config_file="${1:-./ssl-manager.conf}"

    if [ ! -f "$config_file" ]; then
        error "配置文件不存在: $config_file"
        return 1
    fi

    step "从文件加载配置: $config_file"

    # 检查文件安全性
    if file "$config_file" | grep -q "script" || file "$config_file" | grep -q "binary"; then
        error "配置文件可能不安全，拒绝加载"
        return 1
    fi

    # 加载配置文件
    source "$config_file"
    CONFIG_ENCRYPTION_VERSION="${CONFIG_ENCRYPTION_VERSION:-$CONFIG_ENCRYPTION_VERSION_DEFAULT}"
    KEY_TYPE=$(normalize_key_type "${KEY_TYPE:-rsa-2048}")
    KEY_TYPE_SELECTED="true"

    local decrypted_sensitive=true
    if [ -n "${MASTER_PASSWORD_HASH:-}" ]; then
        info "检测到配置加密，正在验证访问密码..."
        if ensure_master_password_loaded; then
            if ! restore_sensitive_variables_from_config; then
                warn "部分敏感信息解密失败，请检查密码或配置文件"
                decrypted_sensitive=false
            fi
        else
            error "配置加密密码验证失败，未加载敏感信息"
            return 1
        fi
    else
        MASTER_PASSWORD_SECRET=""
    fi

    if [ "$decrypted_sensitive" = true ]; then
        sanitize_account_conf_secure
    fi

    success "配置已从文件加载: $config_file"
    show_config
}

# 安装 acme.sh
install_acme() {
    local acme_dir="$ACME_HOME"
    local acme_script="$acme_dir/acme.sh"
    local max_retries=3
    local retry_count=0
    
    # 检查是否已安装
    if [ -f "$acme_script" ] && [ -x "$acme_script" ]; then
        info "acme.sh 已安装，跳过安装步骤"
        export PATH="$acme_dir:$PATH"
        return 0
    fi
    
    step "安装 acme.sh"
    
    while [ $retry_count -lt $max_retries ]; do
        retry_count=$((retry_count + 1))
        
        if [ $retry_count -gt 1 ]; then
            warn "安装失败，重试 ($retry_count/$max_retries)..."
        fi
        
        # 方法1: 使用官方安装脚本
        info "尝试官方安装脚本..."
        if curl -fsSL https://get.acme.sh | sh -s email="$EMAIL" > /dev/null 2>&1; then
            if [ -f "$acme_script" ]; then
                chmod +x "$acme_script"
                export PATH="$acme_dir:$PATH"
                success "acme.sh 安装成功"
                return 0
            fi
        fi
        
        # 方法2: 使用GitHub镜像
        info "尝试GitHub镜像安装..."
        if curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh -s -- --install-online -m "$EMAIL" > /dev/null 2>&1; then
            if [ -f "$acme_script" ]; then
                chmod +x "$acme_script"
                export PATH="$acme_dir:$PATH"
                success "acme.sh 安装成功 (GitHub镜像)"
                return 0
            fi
        fi
        
        # 方法3: Git克隆
        if command -v git >/dev/null 2>&1; then
            info "尝试 Git 克隆安装..."
            case "$PKG_MANAGER" in
                apt-get) $PKG_INSTALL git >/dev/null 2>&1 || warn "Git 安装失败" ;;
                apk) $PKG_INSTALL git >/dev/null 2>&1 || warn "Git 安装失败" ;;
                pkg) $PKG_INSTALL git >/dev/null 2>&1 || warn "Git 安装失败" ;;
            esac
            
            if git clone https://github.com/acmesh-official/acme.sh.git "$acme_dir" 2>/dev/null; then
                cd "$acme_dir"
                if ./acme.sh --install --home "$acme_dir" --accountemail "$EMAIL" > /dev/null 2>&1; then
                    export PATH="$acme_dir:$PATH"
                    success "acme.sh 安装成功 (Git)"
                    return 0
                fi
            fi
        fi
        
        if [ $retry_count -lt $max_retries ]; then
            sleep 2
        fi
    done
    
    # 最后尝试使用wget
    if command -v wget >/dev/null 2>&1; then
        info "尝试使用wget安装..."
        if wget -O - https://get.acme.sh | sh -s email="$EMAIL" > /dev/null 2>&1; then
            if [ -f "$acme_script" ]; then
                chmod +x "$acme_script"
                export PATH="$acme_dir:$PATH"
                success "acme.sh 安装成功 (wget)"
                return 0
            fi
        fi
    fi
    
    fatal "acme.sh 安装失败，请检查网络连接或手动安装"
}

# 选择并安装客户端（acme.sh 或 certbot）
install_client() {
    case "$ACME_CLIENT" in
        certbot)
            if command -v certbot >/dev/null 2>&1; then
                success "检测到 certbot 客户端"
            else
                warn "未检测到 certbot，自动回退至 acme.sh"
                ACME_CLIENT="acme.sh"
                install_acme
            fi
            ;;
        *)
            ACME_CLIENT="acme.sh"
            install_acme
            ;;
    esac
}

# 使用 certbot 申请证书（仅支持 http/tls，DNS需插件不在此脚本覆盖）
issue_certificate_certbot() {
    local domains=("$DOMAIN")
    if [ -n "$WILDCARD_DOMAIN" ]; then
        warn "certbot 的 standalone/webroot 验证不支持通配符域名，已忽略: $WILDCARD_DOMAIN"
    fi

    step "使用 certbot 申请证书 (验证方式: $VALIDATION_METHOD)"
    local base_args=(--agree-tos --non-interactive -m "$EMAIL")
    local domain_args=(-d "$DOMAIN")
    local success_issue=false

    case "$VALIDATION_METHOD" in
        http)
            local svc_h=$(get_service_using_port "$HTTP_PORT")
            local standalone_ready=true
            if ! setup_standalone_ports "$HTTP_PORT" "$svc_h"; then
                standalone_ready=false
                warn "无法准备端口 $HTTP_PORT 进行HTTP验证"
            fi
            if [ "$standalone_ready" = true ]; then
                if certbot certonly --standalone --preferred-challenges http-01 --http-01-port "$HTTP_PORT" "${base_args[@]}" "${domain_args[@]}"; then
                    success_issue=true
                fi
                restore_standalone_ports
            fi
            if [ "$success_issue" != true ] && [ -n "$WEBROOT_PATH" ] && [ -d "$WEBROOT_PATH" ]; then
                info "尝试 Webroot 验证: $WEBROOT_PATH"
                if certbot certonly --webroot -w "$WEBROOT_PATH" "${base_args[@]}" "${domain_args[@]}"; then
                    success_issue=true
                fi
            fi
            ;;
        tls)
            local svc_t=$(get_service_using_port "$TLS_PORT")
            local standalone_ready=true
            if ! setup_standalone_ports "$TLS_PORT" "$svc_t"; then
                standalone_ready=false
                warn "无法准备端口 $TLS_PORT 进行TLS验证"
            fi
            if [ "$standalone_ready" = true ]; then
                if certbot certonly --standalone --preferred-challenges tls-alpn-01 --tls-alpn-01-port "$TLS_PORT" "${base_args[@]}" "${domain_args[@]}"; then
                    success_issue=true
                fi
                restore_standalone_ports
            fi
            ;;
        dns)
            error "certbot DNS 模式需要额外插件，不在此脚本内支持。请改用 acme.sh 或切换 http/tls 验证。"
            ;;
        *)
            error "未知验证方式: $VALIDATION_METHOD"
            ;;
    esac

    if [ "$success_issue" = true ]; then
        install_certificate_certbot
        verify_certificate
        return 0
    fi

    # 尝试切换到另一种验证方式
    if [ "$VALIDATION_METHOD" = "http" ]; then
        VALIDATION_METHOD="tls"
        warn "切换为 TLS 验证重试 (certbot)"
        issue_certificate_certbot
        return $?
    elif [ "$VALIDATION_METHOD" = "tls" ]; then
        VALIDATION_METHOD="http"
        warn "切换为 HTTP 验证重试 (certbot)"
        issue_certificate_certbot
        return $?
    fi

    fatal "certbot 证书申请失败"
}

install_certificate_certbot() {
    local src_dir="/etc/letsencrypt/live/$DOMAIN"
    local cert_src="$src_dir/fullchain.pem"
    local key_src="$src_dir/privkey.pem"

    step "安装 certbot 证书到自定义路径"
    if [ ! -f "$cert_src" ] || [ ! -f "$key_src" ]; then
        fatal "未找到 certbot 证书: $src_dir"
    fi

    mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")"
    cp -f "$cert_src" "$CERT_PATH"
    cp -f "$key_src" "$KEY_PATH"
    chmod 600 "$KEY_PATH"; chmod 644 "$CERT_PATH"

    sync_certificate_to_dir

    # 设置 deploy hook
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook_file="$hook_dir/acme-dns-sync.sh"
    if mkdir -p "$hook_dir" 2>/dev/null && touch "$hook_file" 2>/dev/null; then
        cat > "$hook_file" << 'EOF'
#!/bin/sh
# certbot 部署钩子：同步证书并可选重载服务
CERT_PATH="${CERT_PATH}"
KEY_PATH="${KEY_PATH}"
CERT_SYNC_DIR="${CERT_SYNC_DIR}"
SERVICE_RELOAD_CMD="${SERVICE_RELOAD_CMD}"

if [ -n "$CERT_PATH" ] && [ -f "$RENEWED_LINEAGE/fullchain.pem" ]; then
    cp -f "$RENEWED_LINEAGE/fullchain.pem" "$CERT_PATH"
fi
if [ -n "$KEY_PATH" ] && [ -f "$RENEWED_LINEAGE/privkey.pem" ]; then
    cp -f "$RENEWED_LINEAGE/privkey.pem" "$KEY_PATH"
fi
chmod 600 "$KEY_PATH" 2>/dev/null || true
chmod 644 "$CERT_PATH" 2>/dev/null || true

if [ -n "$CERT_SYNC_DIR" ]; then
    mkdir -p "$CERT_SYNC_DIR" 2>/dev/null || true
    cp -f "$RENEWED_LINEAGE/fullchain.pem" "$CERT_SYNC_DIR/${RENEWED_DOMAINS%% *}.fullchain.pem" 2>/dev/null || true
    cp -f "$RENEWED_LINEAGE/privkey.pem" "$CERT_SYNC_DIR/${RENEWED_DOMAINS%% *}.key" 2>/dev/null || true
fi

if [ -n "$SERVICE_RELOAD_CMD" ]; then
    sh -c "$SERVICE_RELOAD_CMD" || true
fi
EOF
        chmod +x "$hook_file" 2>/dev/null || true
        success "已配置 certbot 部署钩子"
    else
        warn "无法写入 certbot 部署钩子，续期后需手动同步"
    fi

    success "证书签发/安装流程完成 (certbot)"
}

renew_certificate_certbot() {
    local domain_to_renew="${1:-$DOMAIN}"
    if [ -z "$domain_to_renew" ]; then
        error "未指定域名"
        return 1
    fi
    title "证书续期: $domain_to_renew (certbot)"
    if certbot renew --cert-name "$domain_to_renew" --force-renewal; then
        success "certbot 续期成功"
        install_certificate_certbot
        verify_certificate
        return 0
    else
        error "certbot 续期失败"
        return 1
    fi
}

# 配置 DNS 提供商
ensure_dns_creds() {
    local account_conf="$ACME_HOME/account.conf"

    step "配置 DNS 提供商: $DNS_PROVIDER"
    DNS_PROVIDER_READY="false"

    ensure_master_password_loaded || true

    case "$DNS_PROVIDER" in
        cloudflare)
            if [ -n "$CF_Token" ]; then
                export CF_Token="$CF_Token"
                [ -n "$CF_Zone_ID" ] && export CF_Zone_ID="$CF_Zone_ID"
                [ -n "$CF_Account_ID" ] && export CF_Account_ID="$CF_Account_ID"
            else
                export CF_Key="$CF_Key"
                export CF_Email="$CF_Email"
            fi
            ;;
        luadns)
            export LUA_Key="$LUA_KEY"
            export LUA_Email="$LUA_EMAIL"
            ;;
        he)
            export HE_Username="$HE_USERNAME"
            export HE_Password="$HE_PASSWORD"
            ;;
        cloudns)
            if [ -n "$CLOUDNS_SUB_AUTH_ID" ]; then
                export CLOUDNS_SUB_AUTH_ID="$CLOUDNS_SUB_AUTH_ID"
            elif [ -n "$CLOUDNS_AUTH_ID" ]; then
                export CLOUDNS_AUTH_ID="$CLOUDNS_AUTH_ID"
            fi
            export CLOUDNS_AUTH_PASSWORD="$CLOUDNS_AUTH_PASSWORD"
            ;;
        powerdns)
            export PDNS_Url="$PDNS_Url"
            export PDNS_ServerId="$PDNS_ServerId"
            export PDNS_Token="$PDNS_Token"
            export PDNS_Ttl="${PDNS_Ttl:-60}"
            ;;
        1984hosting)
            if [ -n "$One984HOSTING_Username" ]; then
                export One984HOSTING_Username="$One984HOSTING_Username"
            fi
            if [ -n "$One984HOSTING_Password" ]; then
                export One984HOSTING_Password="$One984HOSTING_Password"
            fi
            warn "1984Hosting 登录信息仅在本次运行中使用，敏感凭据已加密保存"
            ;;
        desec)
            export DEDYN_TOKEN="$DEDYN_TOKEN"
            ;;
        dynv6)
            [ -n "$DYNV6_TOKEN" ] && export DYNV6_TOKEN="$DYNV6_TOKEN"
            if [ -n "$DYNV6_KEY" ]; then
                export KEY="$DYNV6_KEY"
            fi
            ;;
        *)
            error "不支持的 DNS 提供商: $DNS_PROVIDER"
            return 1
            ;;
    esac

    DNS_PROVIDER_READY="true"
    sanitize_account_conf_secure
    return 0
}

setup_dns_provider() { ensure_dns_creds "$@"; }

acme_account_ready_for_server() {
    local server="$1"
    local account_conf="$ACME_HOME/account.conf"

    ACME_EXISTING_ACCOUNT_EMAIL=""
    if [ ! -f "$account_conf" ]; then
        return 1
    fi

    local default_server
    local stored_email
    local stored_ca_url
    local expected_ca_url

    default_server=$(get_account_conf_value "DEFAULT_ACME_SERVER" "$account_conf")
    stored_email=$(get_account_conf_value "ACCOUNT_EMAIL" "$account_conf")
    stored_ca_url=$(get_account_conf_value "CA_URL" "$account_conf")
    expected_ca_url=$(ca_directory_url "$server")

    if [ -n "$default_server" ] && [ "$default_server" != "$server" ]; then
        return 1
    fi
    if [ -n "$expected_ca_url" ] && [ -n "$stored_ca_url" ] && [ "$stored_ca_url" != "$expected_ca_url" ]; then
        return 1
    fi
    if [ -z "$stored_email" ]; then
        return 1
    fi

    ACME_EXISTING_ACCOUNT_EMAIL="$stored_email"
    return 0
}

ensure_acme_account_for_server() {
    local server="${1:-$ACME_SERVER}"
    local mode="${2:-primary}"
    local start_time
    local fallback_domain
    local candidate_list=()
    local total_candidates=0
    local attempt=0
    local registered=false
    local chosen_email=""
    local candidate_email=""
    local cmd_status=0

    start_time=$(date +%s)

    ensure_acme_network_tuning

    local heading="注册 ACME 账户 (CA: $server)"
    if [ "$mode" = "inline" ]; then
        info "$heading"
    else
        step "$heading"
    fi

    "$ACME_HOME/acme.sh" --set-default-ca --server "$server" >/dev/null 2>&1 || true
    sanitize_account_conf_secure

    if [ "$server" = "zerossl" ]; then
        : "${ZEROSSL_EAB_KID:=}"
        : "${ZEROSSL_EAB_HMAC_KEY:=}"
        export ZEROSSL_EAB_KID ZEROSSL_EAB_HMAC_KEY
    fi

    ACME_EXISTING_ACCOUNT_EMAIL=""
    if acme_account_ready_for_server "$server"; then
        local existing_email="$ACME_EXISTING_ACCOUNT_EMAIL"
        success "检测到现有 ACME 账户 (CA: $server, 邮箱: $existing_email)"
        info "ACME 账户检查耗时 $(( $(date +%s) - start_time )) 秒"
        EMAIL="$existing_email"
        return 0
    fi

    fallback_domain="${DOMAIN:-$(generate_default_domain)}"
    mapfile -t candidate_list < <(build_account_candidates "$server" "$fallback_domain")
    total_candidates=${#candidate_list[@]}
    info "ACME 账户候选列表 ($total_candidates): ${candidate_list[*]}"

    for candidate_email in "${candidate_list[@]}"; do
        candidate_email=$(trim_spaces "$candidate_email")
        if [ -z "$candidate_email" ]; then
            continue
        fi

        attempt=$((attempt + 1))
        info "尝试注册 ACME 账户 [CA: $server, 尝试 $attempt/$total_candidates] 邮箱: $candidate_email"

        if command -v timeout >/dev/null 2>&1; then
            timeout "$ACME_REGISTER_TIMEOUT" "$ACME_HOME/acme.sh" --register-account -m "$candidate_email" --server "$server" 2>&1 | tee -a "$LOG_FILE"
            cmd_status=${PIPESTATUS[0]}
        else
            "$ACME_HOME/acme.sh" --register-account -m "$candidate_email" --server "$server" 2>&1 | tee -a "$LOG_FILE"
            cmd_status=${PIPESTATUS[0]}
        fi

        sanitize_account_conf_secure

        if [ $cmd_status -eq 0 ]; then
            success "ACME 账户注册成功 (CA: $server, 邮箱: $candidate_email)"
            registered=true
            chosen_email="$candidate_email"
            break
        elif [ $cmd_status -eq 124 ]; then
            warn "注册 ACME 账户超时 (CA: $server, 邮箱: $candidate_email，超时 ${ACME_REGISTER_TIMEOUT}s)"
        else
            warn "注册 ACME 账户失败 (CA: $server, 邮箱: $candidate_email，退出码: $cmd_status)"
        fi
    done

    info "ACME 账户处理耗时 $(( $(date +%s) - start_time )) 秒"

    if [ "$registered" = true ]; then
        EMAIL="$chosen_email"
        return 0
    fi

    error "无法完成 ACME 账户注册 (CA: $server)。请检查网络、邮箱配置或稍后重试。详细日志: $LOG_FILE"
    return 1
}

# 注册 ACME 账户
register_account() {
    local server="${1:-$ACME_SERVER}"
    if ! ensure_acme_account_for_server "$server" "primary"; then
        fatal "ACME 账户准备失败 (CA: $server)"
    fi
}

# 申请证书
issue_certificate() {
    local max_retries=3
    local domain_args="-d $DOMAIN"
    local ca_list
    local issue_start
    local issue_end
    local elapsed=0
    local issue_success=false
    local used_ca=""
    local failure_summary=()
    local has_wildcard=false
    local keylength_arg
    local ecc_flag=""

    ensure_acme_network_tuning

    keylength_arg=$(get_keylength_arg)
    if is_ecc_key; then
        ecc_flag="--ecc"
    fi

    issue_start=$(date +%s)

    if [ "$VALIDATION_METHOD" = "dns" ] && [ "$DNS_PROVIDER_READY" != "true" ] && [ -n "$DNS_PROVIDER" ]; then
        if ! setup_dns_provider; then
            issue_end=$(date +%s)
            elapsed=$((issue_end - issue_start))
            error "DNS 提供商配置失败"
            info "证书申请流程耗时 ${elapsed} 秒"
            return 1
        fi
    fi

    if [ -n "$WILDCARD_DOMAIN" ]; then
        domain_args="$domain_args -d $WILDCARD_DOMAIN"
        has_wildcard=true
        info "包含通配符域名: $WILDCARD_DOMAIN"
    fi

    step "申请 SSL 证书 (首选验证方式: $VALIDATION_METHOD)"

    ca_list=$(echo "$ACME_CA_LIST" | tr '[:upper:]' '[:lower:]' | tr ',' ' ')

    for ca in $ca_list; do
        if ! ca_is_available "$ca"; then
            warn "CA 不可用，跳过: $ca"
            failure_summary+=("CA:$ca 不可用")
            continue
        fi

        info "使用 CA: $ca"

        if ! ensure_acme_account_for_server "$ca" "inline"; then
            failure_summary+=("CA:$ca 账户准备失败")
            continue
        fi

        local method="$VALIDATION_METHOD"
        local tried_dns_fallback=false
        local retry_count=0

        while [ $retry_count -lt $max_retries ]; do
            retry_count=$((retry_count + 1))
            local issue_status=0

            if [ $retry_count -gt 1 ]; then
                warn "申请失败，重试 ($retry_count/$max_retries) [CA: $ca, 验证: $method]"
                sleep "$ACME_RETRY_DELAY"
            fi

            case "$method" in
                dns)
                    if [ -n "$DNS_PROVIDER" ] && [ "$DNS_PROVIDER_READY" != "true" ]; then
                        if ! setup_dns_provider; then
                            failure_summary+=("CA:$ca DNS配置失败")
                            break
                        fi
                    fi
                    local dns_api=""
                    dns_api=$(get_dns_api_name)
                    if [ -z "$dns_api" ]; then
                        error "未配置可用的 DNS 提供商，无法进行 DNS 验证"
                        failure_summary+=("CA:$ca DNS未配置")
                        break
                    fi

                    if run_acme --monitor-dns-wait --issue --dns "$dns_api" $domain_args --keylength "$keylength_arg" $ecc_flag --force; then
                        success "证书申请成功 [CA: $ca, 验证: DNS]"
                        used_ca="$ca"
                        issue_success=true
                        break 2
                    else
                        issue_status=$?
                        warn "DNS 验证失败 [CA: $ca, 退出码: $issue_status]"
                        failure_summary+=("CA:$ca DNS失败:$issue_status")
                    fi
                    ;;
                http)
                    local svc_h
                    local standalone_ready=true
                    svc_h=$(get_service_using_port "$HTTP_PORT")
                    if ! setup_standalone_ports "$HTTP_PORT" "$svc_h"; then
                        standalone_ready=false
                        warn "无法准备端口 $HTTP_PORT 进行HTTP验证"
                        failure_summary+=("CA:$ca HTTP端口占用")
                    fi

                    if [ "$standalone_ready" = true ]; then
                        if run_acme --issue --standalone $domain_args --httpport "$HTTP_PORT" --keylength "$keylength_arg" $ecc_flag --force; then
                            success "证书申请成功 [CA: $ca, 验证: HTTP]"
                            restore_standalone_ports
                            used_ca="$ca"
                            issue_success=true
                            break 2
                        else
                            issue_status=$?
                            warn "HTTP 验证失败 [CA: $ca, 退出码: $issue_status]"
                            failure_summary+=("CA:$ca HTTP失败:$issue_status")
                        fi
                        restore_standalone_ports
                    fi

                    if [ -n "$WEBROOT_PATH" ] && [ -d "$WEBROOT_PATH" ]; then
                        info "尝试使用 Webroot 验证: $WEBROOT_PATH"
                        if run_acme --issue -w "$WEBROOT_PATH" $domain_args --keylength "$keylength_arg" $ecc_flag --force; then
                            success "证书申请成功 [CA: $ca, 验证: Webroot]"
                            used_ca="$ca"
                            issue_success=true
                            break 2
                        else
                            issue_status=$?
                            warn "Webroot 验证失败 [CA: $ca, 退出码: $issue_status]"
                            failure_summary+=("CA:$ca Webroot失败:$issue_status")
                        fi
                    fi
                    ;;
                tls)
                    local svc_t
                    local standalone_ready=true
                    svc_t=$(get_service_using_port "$TLS_PORT")
                    if ! setup_standalone_ports "$TLS_PORT" "$svc_t"; then
                        standalone_ready=false
                        warn "无法准备端口 $TLS_PORT 进行TLS验证"
                        failure_summary+=("CA:$ca TLS端口占用")
                    fi

                    if [ "$standalone_ready" = true ]; then
                        if run_acme --issue --standalone $domain_args --tlsport "$TLS_PORT" --keylength "$keylength_arg" $ecc_flag --force; then
                            success "证书申请成功 [CA: $ca, 验证: TLS]"
                            restore_standalone_ports
                            used_ca="$ca"
                            issue_success=true
                            break 2
                        else
                            issue_status=$?
                            warn "TLS 验证失败 [CA: $ca, 退出码: $issue_status]"
                            failure_summary+=("CA:$ca TLS失败:$issue_status")
                        fi
                        restore_standalone_ports
                    fi
                    ;;
                *)
                    error "未知验证方式: $method"
                    failure_summary+=("CA:$ca 未知验证方式:$method")
                    break
                    ;;
            esac

            if [ "$issue_success" = true ]; then
                break
            fi

            if [ "$method" != "dns" ] && [ "$tried_dns_fallback" = false ] && [ -n "$DNS_PROVIDER" ]; then
                warn "切换为 DNS 验证并重试 [CA: $ca]"
                tried_dns_fallback=true
                method="dns"
                retry_count=0
                continue
            fi
        done

        if [ "$issue_success" = true ]; then
            break
        fi

        warn "在 CA $ca 上申请失败，尝试下一 CA"
    done

    issue_end=$(date +%s)
    elapsed=$((issue_end - issue_start))

    if [ "$issue_success" = true ]; then
        info "证书申请成功，使用 CA: $used_ca，总耗时 ${elapsed} 秒"
        return 0
    fi

    local failure_text=""
    if [ ${#failure_summary[@]} -gt 0 ]; then
        warn "证书申请失败摘要: ${failure_summary[*]}"
        failure_text="; 详情: ${failure_summary[*]}"
    fi

    error "所有证书申请尝试均失败"
    info "证书申请流程耗时 ${elapsed} 秒"
    return 1
}

# 安装证书
install_certificate() {
    local cert_dir=$(dirname "$CERT_PATH")
    local key_dir=$(dirname "$KEY_PATH")
    
    step "安装证书到指定位置"
    
    mkdir -p "$cert_dir" "$key_dir"
    
    local install_status=0
    if "$ACME_HOME/acme.sh" --install-cert -d "$DOMAIN" \
        --key-file "$KEY_PATH" \
        --fullchain-file "$CERT_PATH" >/dev/null 2>&1; then
        install_status=0
    else
        install_status=$?
    fi
    sanitize_account_conf_secure

    if [ $install_status -eq 0 ]; then
        success "证书安装成功"
        
        # 设置自动续期安装
        setup_auto_renewal
    else
        # 手动复制
        warn "标准安装失败，尝试手动复制..."
        local acme_cert_dir="$ACME_HOME/$DOMAIN"
        if [ -f "$acme_cert_dir/$DOMAIN.key" ] && [ -f "$acme_cert_dir/fullchain.cer" ]; then
            cp "$acme_cert_dir/$DOMAIN.key" "$KEY_PATH"
            cp "$acme_cert_dir/fullchain.cer" "$CERT_PATH"
            success "证书手动复制成功"
            
            # 设置自动续期安装
            setup_auto_renewal
        else
            fatal "证书文件不存在: $acme_cert_dir"
        fi
    fi
    
    chmod 600 "$KEY_PATH"
    chmod 644 "$CERT_PATH"

    # 同步到目录（如设置）
    sync_certificate_to_dir

    # 自定义服务重载
    if [ -n "$SERVICE_RELOAD_CMD" ]; then
        info "执行服务重载命令: $SERVICE_RELOAD_CMD"
        eval "$SERVICE_RELOAD_CMD" || warn "服务重载命令执行失败"
    fi

    success "证书签发/安装流程完成"
}

# 设置自动续期安装
setup_auto_renewal() {
    step "配置自动续期安装"
    
    # 创建续期命令
    local reload_cmd="echo '证书已更新'"
    if [ "$POST_SCRIPT_ENABLED" = "true" ] && [ -n "$POST_SCRIPT_CMD" ]; then
        reload_cmd="$POST_SCRIPT_CMD"
    fi
    
    # 使用 acme.sh 的安装证书功能设置自动续期
    local renew_install_status=0
    if "$ACME_HOME/acme.sh" --install-cert -d "$DOMAIN" \
        --key-file "$KEY_PATH" \
        --fullchain-file "$CERT_PATH" \
        --reloadcmd "$reload_cmd" >/dev/null 2>&1; then
        renew_install_status=0
    else
        renew_install_status=$?
    fi
    sanitize_account_conf_secure

    if [ $renew_install_status -eq 0 ]; then
        success "自动续期安装配置成功"
        info "证书续期时将自动更新到: $CERT_PATH, $KEY_PATH"
    else
        warn "自动续期安装配置失败，续期时需要手动安装"
    fi
}

# 检查并显示续期状态
check_renewal_status() {
    step "检查自动续期状态"
    
    # 检查 cron 任务
    if command -v crontab >/dev/null 2>&1; then
        if crontab -l 2>/dev/null | grep -q "acme.sh.*--cron"; then
            success "Cron 自动续期已启用"
            info "Cron 任务:"
            crontab -l 2>/dev/null | grep "acme.sh.*--cron" | sed 's/^/  /'
            
            # 估算下次运行时间
            local cron_schedule
            cron_schedule=$(crontab -l 2>/dev/null | grep "acme.sh.*--cron" | head -1 | awk '{print $1" "$2" "$3" "$4" "$5}')
            if [ -n "$cron_schedule" ]; then
                info "续期计划: $cron_schedule (每日凌晨或指定时间检查)"
            fi
        else
            warn "未检测到 acme.sh 的 cron 任务"
        fi
    fi
    
    # 检查 systemd timer
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-timers 2>/dev/null | grep -q "acme"; then
            success "Systemd timer 自动续期已启用"
            systemctl list-timers 2>/dev/null | grep "acme" | sed 's/^/  /'
        fi
    fi
    
    printf "\n"
}

# 验证证书
verify_certificate() {
    step "验证生成的证书"
    
    if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
        fatal "证书或私钥文件不存在"
    fi
    
    if ! openssl x509 -in "$CERT_PATH" -noout >/dev/null 2>&1; then
        fatal "证书文件格式无效"
    fi
    
    if ! openssl rsa -in "$KEY_PATH" -check -noout >/dev/null 2>&1; then
        fatal "私钥文件格式无效"
    fi
    
    success "证书验证通过"
    
    echo
    info "证书信息:"
    openssl x509 -in "$CERT_PATH" -noout -subject -dates 2>/dev/null | while read -r line; do
        echo "  • $line"
    done
}

# 执行后续脚本
execute_post_script() {
    if [ "$POST_SCRIPT_ENABLED" = "true" ] && [ -n "$POST_SCRIPT_CMD" ]; then
        step "执行后续命令"
        info "执行命令: $POST_SCRIPT_CMD"
        
        export SSL_CERT_PATH="$CERT_PATH"
        export SSL_KEY_PATH="$KEY_PATH"
        export SSL_DOMAIN="$DOMAIN"
        export SSL_EMAIL="$EMAIL"
        export SSL_WILDCARD_DOMAIN="$WILDCARD_DOMAIN"
        export SSL_DNS_PROVIDER="$DNS_PROVIDER"
        export SSL_VALIDATION_METHOD="$VALIDATION_METHOD"
        
        echo
        info "传递给后续命令的环境变量:"
        echo "  • SSL_CERT_PATH: $SSL_CERT_PATH"
        echo "  • SSL_KEY_PATH: $SSL_KEY_PATH"
        echo "  • SSL_DOMAIN: $SSL_DOMAIN"
        echo "  • SSL_WILDCARD_DOMAIN: $SSL_WILDCARD_DOMAIN"
        echo "  • SSL_EMAIL: $SSL_EMAIL"
        echo "  • SSL_DNS_PROVIDER: $SSL_DNS_PROVIDER"
        echo "  • SSL_VALIDATION_METHOD: $SSL_VALIDATION_METHOD"
        echo
        
        if eval "$POST_SCRIPT_CMD"; then
            success "后续命令执行完成"
        else
            local exit_code=$?
            warn "后续命令执行失败 (退出码: $exit_code)"
        fi
    else
        info "后续命令未启用，跳过执行"
    fi
}

# 证书续期
renew_certificate() {
    local domain_to_renew="${1:-}"
    
    if [ -z "$domain_to_renew" ]; then
        if [ -z "$DOMAIN" ]; then
            echo
            echo -e "${CYAN}证书续期${NC}"
            echo -e "${CYAN}请输入要续期的域名${NC}"
            prompt_input "域名" "DOMAIN" ""
        fi
        domain_to_renew="$DOMAIN"
    fi
    
    local previous_operation="$CURRENT_OPERATION"
    CURRENT_OPERATION="证书续期: ${domain_to_renew}"
    
    title "证书续期: $domain_to_renew"
    
    if ! prompt_yesno "确定要续期证书 $domain_to_renew 吗?" "y"; then
        info "取消续期"
        CURRENT_OPERATION="$previous_operation"
        return
    fi
    
    step "开始续期证书"
    ensure_acme_network_tuning
    
    if [ "$ACME_CLIENT" = "certbot" ]; then
        local result=0
        if ! renew_certificate_certbot "$domain_to_renew"; then
            result=1
        fi
        if [ $result -eq 0 ]; then
            send_notification "success" "证书续期成功" "域名: ${domain_to_renew}
验证方式: certbot"
            CURRENT_OPERATION="$previous_operation"
            return 0
        else
            send_notification "failure" "证书续期失败" "域名: ${domain_to_renew}
验证方式: certbot
请检查日志: ${LOG_FILE}"
            CURRENT_OPERATION="$previous_operation"
            return 1
        fi
    fi
    
    local renew_success=false
    if [ "$VALIDATION_METHOD" = "http" ]; then
        local svc_h=$(get_service_using_port "$HTTP_PORT")
        setup_standalone_ports "$HTTP_PORT" "$svc_h" || warn "无法临时释放端口 $HTTP_PORT，可能续期失败"
        if "$ACME_HOME/acme.sh" --renew -d "$domain_to_renew" --force --httpport "$HTTP_PORT"; then
            renew_success=true
        fi
        sanitize_account_conf_secure
        restore_standalone_ports
    elif [ "$VALIDATION_METHOD" = "tls" ]; then
        local svc_t=$(get_service_using_port "$TLS_PORT")
        setup_standalone_ports "$TLS_PORT" "$svc_t" || warn "无法临时释放端口 $TLS_PORT，可能续期失败"
        if "$ACME_HOME/acme.sh" --renew -d "$domain_to_renew" --force --tlsport "$TLS_PORT"; then
            renew_success=true
        fi
        sanitize_account_conf_secure
        restore_standalone_ports
    else
        if "$ACME_HOME/acme.sh" --renew -d "$domain_to_renew" --force; then
            renew_success=true
        fi
        sanitize_account_conf_secure
    fi

    if [ "$renew_success" = "true" ]; then
        success "证书续期成功"
        
        # 重新安装证书到自定义路径
        install_certificate
        verify_certificate
        
        # 发送成功通知
        send_notification "success" "证书续期成功" "域名: ${domain_to_renew}
验证方式: ${VALIDATION_METHOD}
证书已更新"
        
        # 执行后续脚本
        if [ "$POST_SCRIPT_ENABLED" = "true" ] && [ -n "$POST_SCRIPT_CMD" ]; then
            info "执行后续命令..."
            eval "$POST_SCRIPT_CMD"
        fi
    else
        error "证书续期失败"
        
        # 发送失败通知
        send_notification "failure" "证书续期失败" "域名: ${domain_to_renew}
验证方式: ${VALIDATION_METHOD}
请检查日志: ${LOG_FILE}"
        
        CURRENT_OPERATION="$previous_operation"
        return 1
    fi
    
    CURRENT_OPERATION="$previous_operation"
}

# 续期所有证书
renew_all_certificates() {
    title "续期所有证书"
    
    local previous_operation="$CURRENT_OPERATION"
    CURRENT_OPERATION="批量续期证书"
    
    if ! prompt_yesno "确定要续期所有证书吗?" "y"; then
        info "取消批量续期"
        CURRENT_OPERATION="$previous_operation"
        return
    fi
    
    step "开始续期所有证书"
    ensure_acme_network_tuning
    
    if [ "$ACME_CLIENT" = "certbot" ]; then
        if certbot renew; then
            success "所有证书续期成功 (certbot)"
            send_notification "success" "批量证书续期成功" "所有证书已通过 certbot 续期"
            CURRENT_OPERATION="$previous_operation"
            return 0
        else
            error "部分或全部证书续期失败 (certbot)"
            send_notification "failure" "批量证书续期失败" "部分或全部证书续期失败 (certbot)
请检查日志: ${LOG_FILE}"
            CURRENT_OPERATION="$previous_operation"
            return 1
        fi
    fi

    local renew_all_status=0
    if "$ACME_HOME/acme.sh" --renew-all --force; then
        renew_all_status=0
    else
        renew_all_status=$?
    fi
    sanitize_account_conf_secure

    if [ $renew_all_status -eq 0 ]; then
        success "所有证书续期成功"
        send_notification "success" "批量证书续期成功" "所有证书已通过 acme.sh 续期"
        CURRENT_OPERATION="$previous_operation"
    else
        error "部分或全部证书续期失败"
        send_notification "failure" "批量证书续期失败" "部分或全部证书续期失败
请检查日志: ${LOG_FILE}"
        CURRENT_OPERATION="$previous_operation"
        return 1
    fi
}


# 自动检测并在即将过期时续期/签发
auto_check_and_renew() {
    local domain_to_check="${1:-$DOMAIN}"
    if [ -z "$domain_to_check" ]; then
        error "未指定域名，无法进行自动检测"
        return 1
    fi

    local previous_operation="$CURRENT_OPERATION"
    local previous_domain="$DOMAIN"
    CURRENT_OPERATION="自动检测: ${domain_to_check}"
    DOMAIN="$domain_to_check"

    local cert_file="$ACME_HOME/$domain_to_check/fullchain.cer"
    local need_issue=false
    local need_renew=false
    local days_left=""

    if [ ! -f "$cert_file" ]; then
        info "未发现已有证书，准备首次签发"
        need_issue=true
    else
        local expiry_date
        expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
        local current_epoch
        current_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - current_epoch) / 86400 ))

        if [ "$days_left" -le "$RENEW_THRESHOLD_DAYS" ]; then
            info "证书将于 $days_left 天后过期，准备续期"
            need_renew=true
        else
            success "证书剩余 $days_left 天，无需续期"
            send_notification "success" "证书检查完成" "域名: ${domain_to_check}
剩余有效期: ${days_left} 天
无需续期"
            CURRENT_OPERATION="$previous_operation"
            DOMAIN="$previous_domain"
            return 0
        fi
    fi

    detect_os
    check_dependencies
    install_client

    if [ "$need_issue" = true ]; then
        CURRENT_OPERATION="自动签发: ${domain_to_check}"
    elif [ "$need_renew" = true ]; then
        CURRENT_OPERATION="自动续期: ${domain_to_check}"
    fi

    if [ "$ACME_CLIENT" = "certbot" ]; then
        local result=0
        if [ "$need_issue" = true ]; then
            if issue_certificate_certbot; then
                send_notification "success" "证书签发成功" "域名: ${domain_to_check}
客户端: certbot"
                result=0
            else
                send_notification "failure" "证书签发失败" "域名: ${domain_to_check}
客户端: certbot
请检查日志: ${LOG_FILE}"
                result=1
            fi
        elif [ "$need_renew" = true ]; then
            if renew_certificate_certbot "$domain_to_check"; then
                send_notification "success" "自动续期成功" "域名: ${domain_to_check}
客户端: certbot"
                result=0
            else
                send_notification "failure" "自动续期失败" "域名: ${domain_to_check}
客户端: certbot
请检查日志: ${LOG_FILE}"
                result=1
            fi
        fi
        CURRENT_OPERATION="$previous_operation"
        DOMAIN="$previous_domain"
        return $result
    fi

    local op_success=true
    if [ "$VALIDATION_METHOD" = "dns" ]; then
        if ! setup_dns_provider; then
            op_success=false
        fi
    fi
    if [ "$op_success" = "true" ] && ! register_account; then
        op_success=false
    fi

    if [ "$need_issue" = true ]; then
        if [ "$op_success" = "true" ] && ! issue_certificate; then
            op_success=false
        fi
        if [ "$op_success" = "true" ] && ! install_certificate; then
            op_success=false
        fi
        if [ "$op_success" = "true" ] && ! verify_certificate; then
            op_success=false
        fi

        if [ "$op_success" = "true" ]; then
            send_notification "success" "证书签发成功" "域名: ${domain_to_check}
客户端: acme.sh"
            CURRENT_OPERATION="$previous_operation"
            DOMAIN="$previous_domain"
            return 0
        else
            send_notification "failure" "证书签发失败" "域名: ${domain_to_check}
客户端: acme.sh
请检查日志: ${LOG_FILE}"
            CURRENT_OPERATION="$previous_operation"
            DOMAIN="$previous_domain"
            return 1
        fi
    fi

    if [ "$need_renew" = true ]; then
        local renew_result=0
        if ! renew_certificate "$domain_to_check"; then
            renew_result=1
        fi
        CURRENT_OPERATION="$previous_operation"
        DOMAIN="$previous_domain"
        return $renew_result
    fi

    CURRENT_OPERATION="$previous_operation"
    DOMAIN="$previous_domain"
    return 0
}

# 列出所有证书
list_certificates() {
    title "已安装的证书列表"
    
    local cert_dir="$ACME_HOME"
    local found_certs=0
    
    if [ -d "$cert_dir" ]; then
        for domain_dir in "$cert_dir"/*/; do
            if [ -f "${domain_dir}fullchain.cer" ]; then
                found_certs=1
                local domain=$(basename "$domain_dir")
                local cert_file="${domain_dir}fullchain.cer"
                local expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
                local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
                local current_epoch=$(date +%s)
                local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
                
                echo -e "${CYAN}域名: $domain${NC}"
                echo "  • 过期时间: $expiry_date"
                echo "  • 证书路径: $cert_file"
                
                if [ $days_left -lt 30 ]; then
                    echo -e "  • ${RED}剩余有效期: $days_left 天 (即将过期)${NC}"
                elif [ $days_left -lt 60 ]; then
                    echo -e "  • ${YELLOW}剩余有效期: $days_left 天${NC}"
                else
                    echo -e "  • ${GREEN}剩余有效期: $days_left 天${NC}"
                fi
                echo
            fi
        done
    fi
    
    if [ $found_certs -eq 0 ]; then
        warn "未找到任何证书"
    fi
}

# 卸载证书
remove_certificate() {
    local domain_to_remove="${1:-}"
    
    if [ -z "$domain_to_remove" ]; then
        if [ -z "$DOMAIN" ]; then
            echo
            echo -e "${CYAN}证书卸载${NC}"
            echo -e "${CYAN}请输入要卸载的域名${NC}"
            prompt_input "域名" "DOMAIN" ""
        fi
        domain_to_remove="$DOMAIN"
    fi
    
    title "卸载证书: $domain_to_remove"
    
    if ! prompt_yesno "确定要卸载证书 $domain_to_remove 吗? 此操作不可逆!" "n"; then
        info "取消卸载"
        return
    fi
    
    step "开始卸载证书"
    
    # 移除 acme.sh 中的证书
    local remove_status=0
    if "$ACME_HOME/acme.sh" --remove -d "$domain_to_remove" >/dev/null 2>&1; then
        remove_status=0
    else
        remove_status=$?
    fi
    sanitize_account_conf_secure
    if [ $remove_status -eq 0 ]; then
        success "证书从 acme.sh 中移除成功"
    else
        warn "从 acme.sh 移除证书失败，可能证书不存在"
    fi
    
    # 移除证书文件
    local cert_dir="$ACME_HOME/$domain_to_remove"
    if [ -d "$cert_dir" ]; then
        rm -rf "$cert_dir"
        success "证书文件删除成功: $cert_dir"
    fi
    
    # 如果这是当前配置的域名，移除输出文件
    if [ "$domain_to_remove" = "$DOMAIN" ] && [ -f "$CERT_PATH" ]; then
        if prompt_yesno "是否删除证书输出文件 $CERT_PATH 和 $KEY_PATH?" "n"; then
            rm -f "$CERT_PATH" "$KEY_PATH"
            success "证书输出文件已删除"
        fi
    fi
}

# 卸载 acme.sh
uninstall_acme() {
    title "卸载 acme.sh"
    
    if ! prompt_yesno "确定要完全卸载 acme.sh 吗? 这将删除所有证书!" "n"; then
        info "取消卸载"
        return
    fi
    
    step "开始卸载 acme.sh"
    
    sanitize_account_conf_secure
    if [ -f "$ACME_HOME/acme.sh" ]; then
        if "$ACME_HOME/acme.sh" --uninstall >/dev/null 2>&1; then
            success "acme.sh 卸载成功"
        else
            warn "acme.sh 卸载失败，尝试手动删除"
        fi
    fi
    
    if [ -d "$ACME_HOME" ]; then
        rm -rf "$ACME_HOME"
        success "acme.sh 目录已删除"
    fi
    
    # 从 shell 配置中移除 PATH
    local shell_rc=""
    if [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then
        shell_rc="$HOME/.bashrc"
    elif [ -n "$ZSH_VERSION" ] && [ -f "$HOME/.zshrc" ]; then
        shell_rc="$HOME/.zshrc"
    fi
    
    if [ -n "$shell_rc" ]; then
        sed -i '\|'"$ACME_HOME"'|d' "$shell_rc" 2>/dev/null || true
        info "已从 $shell_rc 中移除 acme.sh PATH"
    fi
}

install_certificate_auto_renew_menu() {
    title "安装证书 (自动续期)"

    if [ -z "${DOMAIN}" ]; then
        prompt_input "域名" "DOMAIN" ""
    fi

    if [ -z "${DOMAIN}" ]; then
        error "未指定域名，无法安装证书"
        return 1
    fi

    info "使用密钥类型: $KEY_TYPE (可在配置菜单中调整默认值)"
    KEY_TYPE_SELECTED="true"

    local default_dir="/etc/ssl/${DOMAIN}"
    local default_cert_file="${default_dir}/${DOMAIN}.cer"
    local default_fullchain_file="${CERT_PATH:-${default_dir}/${DOMAIN}.fullchain.pem}"
    local default_key_file="${KEY_PATH:-${default_dir}/${DOMAIN}.key}"

    mkdir -p "$default_dir" 2>/dev/null || true

    printf "\n"
    local install_cert_file
    install_cert_file=$(prompt_path_with_default "证书文件 (--cert-file)" "$default_cert_file")
    printf "\n"
    local install_fullchain_file
    install_fullchain_file=$(prompt_path_with_default "完整链文件 (--fullchain-file)" "$default_fullchain_file")
    printf "\n"
    local install_key_file
    install_key_file=$(prompt_path_with_default "私钥文件 (--key-file)" "$default_key_file")
    printf "\n"

    CERT_PATH="$install_fullchain_file"
    KEY_PATH="$install_key_file"

    info "准备检查系统依赖与 acme.sh 客户端"
    os_detect
    check_deps
    install_client

    if [ ! -f "$ACME_HOME/acme.sh" ]; then
        step "首次安装 acme.sh"
        install_acme
    fi

    if run_acme --no-tee --install >/dev/null 2>&1; then
        debug "acme.sh --install 已执行"
    else
        info "acme.sh 已初始化，跳过 --install 命令"
    fi

    ensure_acme_network_tuning

    local acme_cert_dir="$ACME_HOME/${DOMAIN}"
    if is_ecc_key; then
        acme_cert_dir="${acme_cert_dir}_ecc"
    fi
    local cert_exists=false
    if [ -d "$acme_cert_dir" ] && [ -f "$acme_cert_dir/fullchain.cer" ]; then
        cert_exists=true
        info "检测到已存在的证书: $acme_cert_dir"
    fi

    if [ "$cert_exists" = false ]; then
        step "证书不存在，需要先申请证书"
        
        if [ -z "$EMAIL" ]; then
            prompt_input "注册邮箱" "EMAIL" ""
        fi
        
        configure_validation_method
        
        if [ "$VALIDATION_METHOD" = "dns" ]; then
            configure_dns_provider
        fi
        
        step "开始申请证书"
        if [ "$VALIDATION_METHOD" = "dns" ]; then
            setup_dns_provider
        fi
        
        register_account
        
        if ! issue_certificate; then
            error "证书申请失败"
            return 1
        fi
    fi

    mkdir -p "$(dirname "$install_cert_file")" "$(dirname "$install_fullchain_file")" "$(dirname "$install_key_file")"

    local install_args=(--install-cert -d "$DOMAIN" --cert-file "$install_cert_file" --fullchain-file "$install_fullchain_file" --key-file "$install_key_file")
    if is_ecc_key; then
        install_args+=(--ecc)
    fi

    step "安装证书到自定义路径"
    if run_acme "${install_args[@]}" >/dev/null 2>&1; then
        success "证书已安装"
        chmod 600 "$install_key_file" 2>/dev/null || true
        chmod 644 "$install_cert_file" "$install_fullchain_file" 2>/dev/null || true
    else
        error "证书安装失败，请确认证书已签发"
        return 1
    fi

    step "配置自动续期 (cron)"
    local renewal_method="cron"
    if run_acme --no-tee --install-cronjob >/dev/null 2>&1; then
        success "已配置 cron 自动续期"
    else
        warn "cron 自动续期配置失败，请手动检查"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        if prompt_yesno "检测到 systemd，是否同时安装 systemd timer?" "n"; then
            if run_acme --no-tee --install-service >/dev/null 2>&1; then
                success "systemd timer 安装成功"
                renewal_method="cron + systemd"
            else
                warn "systemd timer 安装失败"
            fi
        fi
    fi

    printf "\n"
    success "安装完成"
    info "域名: $DOMAIN"
    info "密钥类型: $KEY_TYPE"
    info "证书路径: $install_cert_file"
    info "完整链: $install_fullchain_file"
    info "私钥路径: $install_key_file"
    info "续期方式: $renewal_method"

    check_renewal_status

    return 0
}

# 显示证书信息
show_cert_info() {
    local domain_to_check="${1:-}"
    
    if [ -z "$domain_to_check" ]; then
        if [ -z "$DOMAIN" ]; then
            echo
            echo -e "${CYAN}查看证书信息${NC}"
            echo -e "${CYAN}请输入要查看的域名${NC}"
            prompt_input "域名" "DOMAIN" ""
        fi
        domain_to_check="$DOMAIN"
    fi
    
    title "证书信息: $domain_to_check"
    
    local cert_dir="$ACME_HOME/$domain_to_check"
    local cert_file="$cert_dir/fullchain.cer"
    
    if [ ! -f "$cert_file" ]; then
        error "证书不存在: $domain_to_check"
        if ! go_back; then
            return 1
        fi
    fi
    
    info "证书详情:"
    echo "  • 证书文件: $cert_file"
    echo "  • 私钥文件: $cert_dir/$domain_to_check.key"
    
    step "证书内容:"
    openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -E "(Subject:|Not Before|Not After|DNS:)" | while read -r line; do
        echo "  • $line"
    done
    
    local expiry_days=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry_days" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_days" +%s 2>/dev/null)
    local current_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    echo
    step "证书状态:"
    if [ $days_left -lt 30 ]; then
        echo -e "  • ${RED}剩余有效期: $days_left 天 (即将过期，请及时续期)${NC}"
    elif [ $days_left -lt 60 ]; then
        echo -e "  • ${YELLOW}剩余有效期: $days_left 天 (建议近期续期)${NC}"
    else
        echo -e "  • ${GREEN}剩余有效期: $days_left 天${NC}"
    fi
}

# 一键申请证书流程
certificate_issue_flow() {
    title "申请新证书"
    
    local previous_operation="$CURRENT_OPERATION"
    CURRENT_OPERATION="证书申请: ${DOMAIN:-未设置}"
    
    # 选择配置模式
    if ! select_config_mode; then
        CURRENT_OPERATION="$previous_operation"
        return
    fi
    
    if ! validate_config; then
        error "配置验证失败"
        if ! go_back; then
            CURRENT_OPERATION="$previous_operation"
            return
        fi
    fi
    
    info "使用密钥类型: $KEY_TYPE (可在配置菜单中调整默认值)"
    KEY_TYPE_SELECTED="true"

    # 显示最终配置确认
    step "最终配置确认"
    show_config
    
    if ! prompt_yesno "确认以上配置并开始申请证书?" "y"; then
        info "取消证书申请"
        CURRENT_OPERATION="$previous_operation"
        return
    fi
    
    step "开始证书申请流程"
    detect_os
    check_dependencies
    install_client

    local issue_success=true
    if [ "$ACME_CLIENT" = "certbot" ]; then
        if ! issue_certificate_certbot; then
            issue_success=false
        fi
    else
        if [ "$VALIDATION_METHOD" = "dns" ]; then
            if ! setup_dns_provider; then
                issue_success=false
            fi
        fi
        if [ "$issue_success" = "true" ] && ! register_account; then
            issue_success=false
        fi
        if [ "$issue_success" = "true" ] && ! issue_certificate; then
            issue_success=false
        fi
        if [ "$issue_success" = "true" ] && ! install_certificate; then
            issue_success=false
        fi
        if [ "$issue_success" = "true" ] && ! verify_certificate; then
            issue_success=false
        fi
    fi
    
    echo
    if [ "$issue_success" = "true" ]; then
        success "🎉 SSL 证书生成完成！"
        separator
        info "证书文件位置:"
        echo "  • 证书文件: $CERT_PATH"
        echo "  • 私钥文件: $KEY_PATH"
        if [ -n "$WILDCARD_DOMAIN" ]; then
            echo "  • 通配符域名: $WILDCARD_DOMAIN"
        fi
        echo "  • 验证方式: $VALIDATION_METHOD"
        if [ "$VALIDATION_METHOD" = "dns" ]; then
            echo "  • DNS提供商: $DNS_PROVIDER"
        fi
        separator
        
        # 发送成功通知
        send_notification "success" "证书申请成功" "域名: ${DOMAIN}
通配符: ${WILDCARD_DOMAIN:-无}
验证方式: ${VALIDATION_METHOD}
证书路径: ${CERT_PATH}"
        
        # 保存配置
        if prompt_yesno "是否保存当前配置以便下次使用?" "y"; then
            save_config
        fi
        
        # 询问是否设置快速启动
        echo
        setup_quick_start
        
        execute_post_script
    else
        error "证书申请失败，请检查日志"
        
        # 发送失败通知
        send_notification "failure" "证书申请失败" "域名: ${DOMAIN}
验证方式: ${VALIDATION_METHOD}
请检查日志: ${LOG_FILE}"
    fi
    
    CURRENT_OPERATION="$previous_operation"
}

# 显示菜单
show_menu() {
    title "SSL 证书管理工具   By Prince 2025.10 "
    echo -e "${GREEN}  1) [申请] 申请新证书${NC}"
    echo -e "${YELLOW}  2) [续期] 续期指定证书${NC}"
    echo -e "${YELLOW}  3) [批量续期] 续期所有证书${NC}"
    echo -e "${CYAN}  4) [列表] 列出所有证书${NC}"
    echo -e "${BLUE}  5) [信息] 查看证书信息${NC}"
    echo -e "${MAGENTA}  6) [安装] 安装证书到新路径/服务${NC}"
    echo -e "${RED}  7) [卸载] 卸载证书${NC}"
    echo -e "${RED}  8) [卸载ACME] 卸载 ACME 客户端${NC}"
    echo -e "${MAGENTA}  9) [配置向导] 查看/修改全部配置${NC}"
    echo -e "${CYAN} 10) [通知设置] 配置通知渠道${NC}"
    echo -e "${CYAN} 11) [保存配置] 保存当前配置${NC}"
    echo -e "${CYAN} 12) [加载配置] 从文件加载配置${NC}"
    echo -e "${CYAN} 13) [快捷启动] 配置 'ssl' 快捷命令${NC}"
    echo -e "${CYAN} 14) [帮助] 显示帮助说明${NC}"
    echo -e "${GREEN}  0) [退出] 安全退出程序${NC}"
    echo
}

# 主菜单
main_menu() {
    while true; do
        show_menu
        echo -e "${CYAN}请选择操作 [0-14]: ${NC}"
        read -r choice
        
        case "$choice" in
            1)
                certificate_issue_flow
                ;;
            2)
                renew_certificate
                ;;
            3)
                renew_all_certificates
                ;;
            4)
                list_certificates
                ;;
            5)
                show_cert_info
                ;;
            6)
                install_certificate_auto_renew_menu
                ;;
            7)
                remove_certificate
                ;;
            8)
                uninstall_acme
                ;;
            9)
                modify_config
                ;;
            10)
                configure_notification
                ;;
            11)
                save_config
                ;;
            12)
                load_config
                ;;
            13)
                setup_quick_start menu
                ;;
            14)
                show_help
                ;;
            0)
                info "感谢使用，再见！"
                exit 0
                ;;
            *)
                error "无效选择，请输入 0-14 之间的数字"
                ;;
        esac
        
        echo
        if prompt_yesno "是否返回主菜单?" "y"; then
            continue
        else
            info "感谢使用，再见！"
            exit 0
        fi
    done
}

# 一键运行函数
quick_issue() {
    info "一键模式启动..."
    
    if [ -f "./ssl-manager.conf" ]; then
        info "检测到配置文件，自动加载..."
        load_config "./ssl-manager.conf"
    fi
    
    if validate_config; then
        certificate_issue_flow
    else
        warn "环境变量配置不完整，进入交互式配置"
        certificate_issue_flow
    fi
}

# 帮助信息
show_help() {
    title "帮助信息"
    echo -e "${CYAN}使用说明:${NC}"
    echo "  本脚本用于管理 SSL 证书，支持申请、续期、查看和卸载证书。"
    echo "  支持 DNS 验证、HTTP-80端口验证和 TLS-443端口验证三种方式。"
    echo
    echo -e "${CYAN}主要功能:${NC}"
    echo "  • 申请新证书: 通过 DNS/HTTP/TLS 验证方式申请 SSL 证书"
    echo "  • 证书续期: 续期单个或所有已安装的证书"
    echo "  • 证书管理: 查看证书列表、信息和状态"
    echo "  • 证书卸载: 安全移除不需要的证书"
    echo "  • 配置管理: 显示和修改当前配置"
    echo "  • 快捷启动: 在主菜单中配置 'ssl' 快捷命令"
    echo
    echo -e "${CYAN}支持的验证方式:${NC}"
    echo "  • DNS 验证: 支持通配符证书，需要配置DNS提供商"
    echo "  • HTTP 验证: 使用80端口验证，需要确保80端口可访问"
    echo "  • TLS 验证: 使用443端口验证，需要确保443端口可访问"
    echo
    echo -e "${CYAN}支持的 DNS 提供商:${NC}"
    echo "  • CloudFlare (推荐)"
    echo "  • LuaDNS"
    echo "  • Hurricane Electric (HE)"
    echo "  • ClouDNS"
    echo "  • PowerDNS (Self-hosted)"
    echo "  • 1984Hosting (网站登录令牌)"
    echo "  • deSEC.io (Free dynDNS)"
    echo "  • dynv6 (HTTP/SSH双模式)"
    echo
    echo -e "${CYAN}支持的环境变量:${NC}"
    echo "  DOMAIN                 证书域名"
    echo "  WILDCARD_DOMAIN        通配符域名"
    echo "  EMAIL                  注册邮箱"
    echo "  VALIDATION_METHOD      验证方式: dns, http, tls"
    echo "  HTTP_PORT              HTTP验证端口 (默认: 80)"
    echo "  TLS_PORT               TLS验证端口 (默认: 443)"
    echo "  WEBROOT_PATH           Webroot 路径（HTTP验证兜底）"
    echo "  SKIP_PORT_CHECK        跳过端口检查 (true/false)"
    echo "  DNS_PROVIDER           DNS提供商: cloudflare, luadns, he, cloudns, powerdns, 1984hosting, desec, dynv6"
    echo "  CF_Token               CloudFlare API Token (推荐)"
    echo "  CF_Zone_ID             CloudFlare Zone ID (可选)"
    echo "  CF_Account_ID          CloudFlare Account ID (可选)"
    echo "  CF_Key                 CloudFlare 全局 API Key (不推荐)"
    echo "  CF_Email               CloudFlare 邮箱 (不推荐)"
    echo "  LUA_KEY                LuaDNS API 密钥"
    echo "  LUA_EMAIL              LuaDNS 邮箱"
    echo "  HE_USERNAME            Hurricane Electric 用户名"
    echo "  HE_PASSWORD            Hurricane Electric 密码"
    echo "  CLOUDNS_AUTH_ID        ClouDNS 常规 Auth ID"
    echo "  CLOUDNS_SUB_AUTH_ID    ClouDNS 子用户 Auth ID (推荐)"
    echo "  CLOUDNS_AUTH_PASSWORD  ClouDNS 密码"
    echo "  PDNS_Url               PowerDNS API 地址 (例如 http://ns.example.com:8081)"
    echo "  PDNS_ServerId          PowerDNS Server ID (默认: localhost)"
    echo "  PDNS_Token             PowerDNS API Token"
    echo "  PDNS_Ttl               PowerDNS TXT 记录 TTL (默认: 60秒)"
    echo "  One984HOSTING_Username 1984Hosting 用户名"
    echo "  One984HOSTING_Password 1984Hosting 登录密码 (首次登录会缓存令牌)"
    echo "  DEDYN_TOKEN            deSEC API Token"
    echo "  DYNV6_TOKEN            dynv6 HTTP Token"
    echo "  DYNV6_KEY              dynv6 SSH Key 路径 (可选)"
    echo "  CERT_PATH              证书输出路径"
    echo "  KEY_PATH               私钥输出路径"
    echo "  CERT_SYNC_DIR          若设置，会将证书/私钥复制到该目录"
    echo "  SERVICE_RELOAD_CMD     证书更新后的服务重载命令"
    echo "  ACME_CLIENT            客户端: acme.sh 或 certbot（默认 acme.sh）"
    echo "  ACME_CA_LIST           多CA回退顺序: letsencrypt,zerossl"
    echo "  ACME_ACCOUNT_POOL      逗号分隔的备用 ACME 账户邮箱列表"
    echo "  ACME_REGISTER_TIMEOUT  ACME 账户注册超时时间（秒，默认 30）"
    echo "  ACME_CURL_CONNECT_TIMEOUT ACME 请求连接超时时间（秒，默认 5）"
    echo "  ACME_CURL_MAX_TIME     ACME 请求最大耗时（秒，默认 40）"
    echo "  ACME_CURL_RETRIES      ACME 请求失败重试次数（默认 2）"
    echo "  ACME_CURL_RETRY_DELAY  ACME 请求重试间隔（秒，默认 2）"
    echo "  ACME_RETRY_DELAY       证书申请失败后的重试间隔（秒，默认 3）"
    echo "  ACME_SERVER            兼容旧参数，指定首选CA"
    echo "  ENV_FILE               .env 文件路径（默认 ./.env）"
    echo "  LOG_FILE               日志文件（默认 /tmp/acme-manager.log）"
    echo "  LOG_MAX_SIZE_KB        日志最大大小KB，超出将截断（默认 1024）"
    echo "  SILENT_MODE            静默模式，仅记录日志（true/false）"
    echo "  RENEW_THRESHOLD_DAYS   剩余多少天内自动续期（默认 30）"
    echo "  NOTIFY_ENABLED         启用通知（true/false）"
    echo "  NOTIFY_ON_SUCCESS      成功时是否发送通知（true/false）"
    echo "  NOTIFY_ON_FAILURE      失败时是否发送通知（true/false）"
    echo "  TELEGRAM_BOT_TOKEN     Telegram Bot Token"
    echo "  TELEGRAM_CHAT_ID       Telegram Chat ID"
    echo "  WEBHOOK_URL            通用Webhook URL（JSON: {text:...}）"
    echo "  MAIL_TO                收件邮箱（需本地MTA或sendmail/mailx）"
    echo "  MAIL_SUBJECT_PREFIX    邮件主题前缀（默认 [Acme-DNS]）"
    echo
    echo -e "${CYAN}验证方式选择建议:${NC}"
    echo "  • 通配符证书: 必须使用 DNS 验证"
    echo "  • 单域名证书: 根据服务器环境选择"
    echo "  • 服务器有公网IP且端口开放: 推荐使用 HTTP/TLS 验证"
    echo "  • 服务器在防火墙后或端口受限: 推荐使用 DNS 验证"
    echo
    echo -e "${CYAN}端口验证注意事项:${NC}"
    echo "  • HTTP验证: 需要确保80端口可从公网访问"
    echo "  • TLS验证: 需要确保443端口可从公网访问"
    echo "  • 脚本具备端口智能占用与恢复能力：会自动检测并临时释放80/443端口（优雅停止常见Web服务，如 nginx、apache、caddy、traefik 等），验证完成后自动恢复原服务状态"
    echo "  • 如果仍无法释放端口，可选择强制继续（可能失败）或手动处理"
    echo "  • 可使用 SKIP_PORT_CHECK=true 跳过端口检查"
    echo
    echo -e "${CYAN}使用示例:${NC}"
    echo "  # 交互式菜单模式"
    echo "  ./Acme-DNS.sh"
    echo
    echo "  # 使用HTTP验证申请证书（acme.sh）"
    echo "  DOMAIN=\"your-domain.com\" VALIDATION_METHOD=\"http\" ./Acme-DNS.sh --issue"
    echo
    echo "  # 使用TLS验证申请证书（certbot 客户端）"
    echo "  ACME_CLIENT=certbot DOMAIN=\"your-domain.com\" VALIDATION_METHOD=\"tls\" ./Acme-DNS.sh --issue"
    echo
    echo "  # 使用DNS验证申请通配符证书（ClouDNS）"
    echo "  DOMAIN=\"your-domain.com\" WILDCARD_DOMAIN=\"*.your-domain.com\" VALIDATION_METHOD=\"dns\" DNS_PROVIDER=\"cloudns\" CLOUDNS_SUB_AUTH_ID=\"your_sub_auth_id\" CLOUDNS_AUTH_PASSWORD=\"your_password\" ./Acme-DNS.sh --issue"
    echo
    echo "  # 使用 PowerDNS 申请证书"
    echo "  DOMAIN=\"your-domain.com\" VALIDATION_METHOD=\"dns\" DNS_PROVIDER=\"powerdns\" PDNS_Url=\"http://ns.example.com:8081\" PDNS_Token=\"your_token\" ./Acme-DNS.sh --issue"
    echo
    echo "  # 使用 deSEC.io 申请通配符证书"
    echo "  DOMAIN=\"foobar.dedyn.io\" WILDCARD_DOMAIN=\"*.foobar.dedyn.io\" VALIDATION_METHOD=\"dns\" DNS_PROVIDER=\"desec\" DEDYN_TOKEN=\"your_token\" ./Acme-DNS.sh --issue"
    echo
    echo "  # 使用 dynv6 HTTP Token 申请证书"
    echo "  DOMAIN=\"example.dynv6.net\" WILDCARD_DOMAIN=\"*.example.dynv6.net\" VALIDATION_METHOD=\"dns\" DNS_PROVIDER=\"dynv6\" DYNV6_TOKEN=\"your_http_token\" ./Acme-DNS.sh --issue"
    echo
    echo "  # 自动检测并续期/签发（适合定时任务）"
    echo "  ./Acme-DNS.sh --auto-check --silent"
    echo
    echo -e "${YELLOW}提示: 在 SSH 终端中，建议使用交互式菜单模式以获得最佳体验。${NC}"
}

# 命令行参数处理
init_runtime

ACTION=""
ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --key-type)
            if [ $# -lt 2 ]; then
                fatal "--key-type 需要指定密钥类型"
            fi
            KEY_TYPE=$(normalize_key_type "$2")
            KEY_TYPE_SELECTED="true"
            shift 2
            ;;
        -d|--domain)
            if [ $# -lt 2 ]; then
                fatal "缺少域名参数"
            fi
            DOMAIN="$2"
            shift 2
            ;;
        --silent)
            SILENT_MODE=true
            shift
            ;;
        -i|--issue|issue)
            if [ -z "$ACTION" ]; then
                ACTION="issue"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        install|--install)
            if [ -z "$ACTION" ]; then
                ACTION="install"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -r|--renew|renew)
            if [ -z "$ACTION" ]; then
                ACTION="renew"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -ra|--renew-all|renew-all)
            if [ -z "$ACTION" ]; then
                ACTION="renew_all"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -a|--auto-check|auto-check)
            if [ -z "$ACTION" ]; then
                ACTION="auto_check"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -l|--list|list)
            if [ -z "$ACTION" ]; then
                ACTION="list"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -s|--show|show)
            if [ -z "$ACTION" ]; then
                ACTION="show"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -rm|--remove|remove)
            if [ -z "$ACTION" ]; then
                ACTION="remove"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -u|--uninstall|uninstall)
            if [ -z "$ACTION" ]; then
                ACTION="uninstall"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -c|--config|config)
            if [ -z "$ACTION" ]; then
                ACTION="config"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -q|--quick|quick)
            if [ -z "$ACTION" ]; then
                ACTION="quick"
            else
                ARGS+=("$1")
            fi
            shift
            ;;
        -h|--help|help)
            ACTION="help"
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            ARGS+=("$1")
            shift
            ;;
    esac
done

if [ $# -gt 0 ]; then
    ARGS+=("$@")
fi

if [ ${#ARGS[@]} -gt 0 ]; then
    set -- "${ARGS[@]}"
else
    set --
fi

case "${ACTION:-}" in
    issue)
        certificate_issue_flow
        ;;
    install)
        install_certificate_auto_renew_menu
        ;;
    renew)
        if [ $# -gt 0 ]; then
            renew_certificate "$1"
        else
            renew_certificate
        fi
        ;;
    renew_all)
        renew_all_certificates
        ;;
    auto_check)
        auto_check_and_renew "$1"
        ;;
    list)
        list_certificates
        ;;
    show)
        show_cert_info "$1"
        ;;
    remove)
        remove_certificate "$1"
        ;;
    uninstall)
        uninstall_acme
        ;;
    config)
        show_config
        ;;
    quick)
        quick_issue
        ;;
    help)
        show_help
        exit 0
        ;;
    "")
        if [ ${#ARGS[@]} -eq 0 ]; then
            main_menu
        else
            error "未知参数: ${ARGS[0]}"
            printf "\n"
            show_help
            exit 1
        fi
        ;;
    *)
        error "未知命令: $ACTION"
        printf "\n"
        show_help
        exit 1
        ;;
 esac
