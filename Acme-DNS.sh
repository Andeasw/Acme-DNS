#!/bin/bash
# ===========================================
# RSA 2048 证书管理脚本 (acme.sh + CloudFlare/LuaDNS/Hurricane Electric)
# 支持 Debian、Alpine 和 FreeBSD 系统
# 支持证书申请、续期、管理和卸载
# By Prince 2025.10.15
# ===========================================

set -e

# 配置参数（支持环境变量覆盖）
DOMAIN="${DOMAIN:-}"
WILDCARD_DOMAIN="${WILDCARD_DOMAIN:-}"
CERT_PATH="${CERT_PATH:-}"
KEY_PATH="${KEY_PATH:-}"
EMAIL="${EMAIL:-}"

# DNS 提供商配置
DNS_PROVIDER="${DNS_PROVIDER:-}"  # cloudflare, luadns 或 he

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

# ACME 配置
ACME_SERVER="${ACME_SERVER:-letsencrypt}"

# 后续脚本命令
POST_SCRIPT_CMD="${POST_SCRIPT_CMD:-}"
POST_SCRIPT_ENABLED="${POST_SCRIPT_ENABLED:-false}"

# 系统检测
OS_TYPE=""
PKG_MANAGER=""
PKG_INSTALL=""
PKG_UPDATE=""
ACME_HOME="$HOME/.acme.sh"

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

# 日志函数
error() { echo -e "${RED}[错误] $1${NC}" >&2; }
warn() { echo -e "${YELLOW}[警告] $1${NC}" >&2; }
info() { echo -e "${BLUE}[信息] $1${NC}" >&2; }
success() { echo -e "${GREEN}[成功] $1${NC}" >&2; }
fatal() { echo -e "${RED}[致命错误] $1${NC}" >&2; exit 1; }
step() { echo -e "${CYAN}[步骤] $1${NC}" >&2; }

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
detect_os() {
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

# 检查并安装依赖
check_dependencies() {
    step "检查系统依赖"
    
    local deps=""
    local missing_deps=()
    
    # 检测必需的命令
    local required_cmds="curl openssl"
    local recommended_cmds="socat cron"
    
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

# 选择菜单函数
show_dns_menu() {
    echo
    echo -e "${CYAN}请选择 DNS 服务商:${NC}"
    echo "  1) CloudFlare (推荐)"
    echo "  2) LuaDNS"
    echo "  3) Hurricane Electric (HE)"
    echo
}

show_acme_menu() {
    echo
    echo -e "${CYAN}请选择 ACME 服务器:${NC}"
    echo "  1) Let's Encrypt (推荐)"
    echo "  2) ZeroSSL"
    echo
}

show_cf_auth_menu() {
    echo
    echo -e "${CYAN}请选择 CloudFlare 认证方式:${NC}"
    echo "  1) API Token (推荐)"
    echo "  2) 全局 API Key (不推荐)"
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

# 配置模式选择
select_config_mode() {
    title "SSL证书配置"
    
    # 检查是否有完整的配置
    local has_complete_config=true
    
    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        has_complete_config=false
    elif [ "$DNS_PROVIDER" = "cloudflare" ]; then
        if [ -z "$CF_Token" ] && [ -z "$CF_Key" ]; then
            has_complete_config=false
        fi
    elif [ "$DNS_PROVIDER" = "luadns" ] && [ -z "$LUA_KEY" ]; then
        has_complete_config=false
    elif [ "$DNS_PROVIDER" = "he" ] && [ -z "$HE_USERNAME" ]; then
        has_complete_config=false
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
    
    # DNS提供商配置
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
            esac
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
    
    if prompt_yesno "是否需要修改ACME服务器配置?" "n"; then
        step "ACME服务器配置"
        configure_acme_server
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
    
    # DNS提供商配置
    step "DNS提供商配置"
    configure_dns_provider
    
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
        echo -e "${CYAN}请选择 [1-3]: ${NC}"
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
            *)
                error "无效选择，请输入 1-3 之间的数字"
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
                error "无效选择，请输入 1 或 2"
                ;;
        esac
    done
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
        *)
            error "不支持的 DNS 提供商: $DNS_PROVIDER"
            errors=$((errors + 1))
            ;;
    esac
    
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
    esac
    
    echo -e "${CYAN}证书配置:${NC}"
    echo "  • 证书路径: ${CERT_PATH:-未设置}"
    echo "  • 私钥路径: ${KEY_PATH:-未设置}"
    echo "  • ACME服务器: $ACME_SERVER"
    
    if [ "$POST_SCRIPT_ENABLED" = "true" ] && [ -n "$POST_SCRIPT_CMD" ]; then
        echo -e "${CYAN}后续脚本:${NC}"
        echo "  • 后续命令: $POST_SCRIPT_CMD"
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
        echo "  2) DNS提供商配置"
        echo "  3) 证书路径配置"
        echo "  4) ACME服务器配置"
        echo "  5) 后续脚本配置"
        echo "  6) 返回主菜单"
        echo
        
        echo -e "${CYAN}请选择 [1-6]: ${NC}"
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
                step "修改DNS提供商配置"
                configure_dns_provider
                ;;
            3)
                step "修改证书路径配置"
                prompt_input "证书文件保存路径" "CERT_PATH" "$CERT_PATH"
                prompt_input "私钥文件保存路径" "KEY_PATH" "$KEY_PATH"
                ;;
            4)
                step "修改ACME服务器配置"
                configure_acme_server
                ;;
            5)
                step "修改后续脚本配置"
                if prompt_yesno "是否启用后续脚本?" "n"; then
                    POST_SCRIPT_ENABLED="true"
                    prompt_input "后续脚本命令" "POST_SCRIPT_CMD" "$POST_SCRIPT_CMD" "true"
                else
                    POST_SCRIPT_ENABLED="false"
                    POST_SCRIPT_CMD=""
                fi
                ;;
            6)
                info "返回主菜单"
                return 0
                ;;
            *)
                error "无效选择，请输入 1-6 之间的数字"
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
    
    cat > "$config_file" << EOF
# SSL证书管理脚本配置文件
# 生成时间: $(date)

# 域名配置
DOMAIN="$DOMAIN"
WILDCARD_DOMAIN="$WILDCARD_DOMAIN"
EMAIL="$EMAIL"

# DNS提供商配置
DNS_PROVIDER="$DNS_PROVIDER"

# CloudFlare配置
CF_Token="$CF_Token"
CF_Zone_ID="$CF_Zone_ID"
CF_Account_ID="$CF_Account_ID"
CF_Key="$CF_Key"
CF_Email="$CF_Email"

# LuaDNS配置
LUA_KEY="$LUA_KEY"
LUA_EMAIL="$LUA_EMAIL"

# Hurricane Electric配置
HE_USERNAME="$HE_USERNAME"
HE_PASSWORD="$HE_PASSWORD"

# 证书路径配置
CERT_PATH="$CERT_PATH"
KEY_PATH="$KEY_PATH"

# ACME服务器配置
ACME_SERVER="$ACME_SERVER"

# 后续脚本配置
POST_SCRIPT_CMD="$POST_SCRIPT_CMD"
POST_SCRIPT_ENABLED="$POST_SCRIPT_ENABLED"
EOF

    chmod 600 "$config_file"
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
    
    # 源配置文件
    source "$config_file"
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

# 配置 DNS 提供商
setup_dns_provider() {
    local account_conf="$ACME_HOME/account.conf"
    
    step "配置 DNS 提供商: $DNS_PROVIDER"
    
    case "$DNS_PROVIDER" in
        cloudflare)
            # 清除可能的旧配置
            {
                grep -v "^CF_Token=" "$account_conf" 2>/dev/null || true
                grep -v "^CF_Zone_ID=" "$account_conf" 2>/dev/null || true
                grep -v "^CF_Account_ID=" "$account_conf" 2>/dev/null || true
                grep -v "^CF_Key=" "$account_conf" 2>/dev/null || true
                grep -v "^CF_Email=" "$account_conf" 2>/dev/null || true
            } > "${account_conf}.tmp" && mv "${account_conf}.tmp" "$account_conf"
            
            # 设置新的配置
            if [ -n "$CF_Token" ]; then
                # API Token 方式
                {
                    echo "CF_Token=$CF_Token"
                    [ -n "$CF_Zone_ID" ] && echo "CF_Zone_ID=$CF_Zone_ID"
                    [ -n "$CF_Account_ID" ] && echo "CF_Account_ID=$CF_Account_ID"
                } >> "$account_conf"
                
                export CF_Token="$CF_Token"
                [ -n "$CF_Zone_ID" ] && export CF_Zone_ID="$CF_Zone_ID"
                [ -n "$CF_Account_ID" ] && export CF_Account_ID="$CF_Account_ID"
            else
                # 全局 API Key 方式
                {
                    echo "CF_Key=$CF_Key"
                    echo "CF_Email=$CF_Email"
                } >> "$account_conf"
                
                export CF_Key="$CF_Key"
                export CF_Email="$CF_Email"
            fi
            ;;
            
        luadns)
            {
                grep -v "^LUA_Key=" "$account_conf" 2>/dev/null || true
                grep -v "^LUA_Email=" "$account_conf" 2>/dev/null || true
                echo "LUA_Key=$LUA_KEY"
                echo "LUA_Email=$LUA_EMAIL"
            } > "${account_conf}.tmp" && mv "${account_conf}.tmp" "$account_conf"
            
            export LUA_Key="$LUA_KEY"
            export LUA_Email="$LUA_EMAIL"
            ;;
            
        he)
            {
                grep -v "^HE_Username=" "$account_conf" 2>/dev/null || true
                grep -v "^HE_Password=" "$account_conf" 2>/dev/null || true
                echo "HE_Username=$HE_USERNAME"
                echo "HE_Password=$HE_PASSWORD"
            } > "${account_conf}.tmp" && mv "${account_conf}.tmp" "$account_conf"
            
            export HE_Username="$HE_USERNAME"
            export HE_Password="$HE_PASSWORD"
            ;;
    esac
    
    success "DNS 提供商配置完成"
}

# 注册 ACME 账户
register_account() {
    step "注册 ACME 账户"
    
    case "$ACME_SERVER" in
        letsencrypt)
            "$ACME_HOME/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
            ;;
        zerossl)
            "$ACME_HOME/acme.sh" --set-default-ca --server zerossl >/dev/null 2>&1 || true
            ;;
    esac
    
    if "$ACME_HOME/acme.sh" --register-account -m "$EMAIL" >/dev/null 2>&1; then
        success "ACME 账户注册成功"
    else
        info "使用现有 ACME 账户"
    fi
}

# 申请证书
issue_certificate() {
    local max_retries=3
    local retry_count=0
    local domain_args="-d $DOMAIN"
    
    if [ -n "$WILDCARD_DOMAIN" ]; then
        domain_args="$domain_args -d $WILDCARD_DOMAIN"
        info "包含通配符域名: $WILDCARD_DOMAIN"
    fi
    
    # 确定 DNS API 名称
    local dns_api
    case "$DNS_PROVIDER" in
        cloudflare) dns_api="dns_cf" ;;
        luadns) dns_api="dns_lua" ;;
        he) dns_api="dns_he" ;;
    esac
    
    step "申请 SSL 证书"
    
    while [ $retry_count -lt $max_retries ]; do
        retry_count=$((retry_count + 1))
        
        if [ $retry_count -gt 1 ]; then
            warn "证书申请失败，重试 ($retry_count/$max_retries)..."
            sleep 10
        fi
        
        info "正在申请证书 (尝试 $retry_count/$max_retries)"
        if "$ACME_HOME/acme.sh" --issue --dns "$dns_api" $domain_args \
            --keylength 2048 --force; then
            success "证书申请成功"
            return 0
        fi
    done
    
    # 尝试备用服务器
    if [ "$ACME_SERVER" = "letsencrypt" ]; then
        warn "Let's Encrypt 申请失败，尝试 ZeroSSL..."
        "$ACME_HOME/acme.sh" --set-default-ca --server zerossl >/dev/null 2>&1
        
        if "$ACME_HOME/acme.sh" --issue --dns "$dns_api" $domain_args \
            --keylength 2048 --force; then
            success "使用 ZeroSSL 申请证书成功"
            return 0
        fi
    fi
    
    fatal "所有证书申请尝试都失败"
}

# 安装证书
install_certificate() {
    local cert_dir=$(dirname "$CERT_PATH")
    local key_dir=$(dirname "$KEY_PATH")
    
    step "安装证书到指定位置"
    
    mkdir -p "$cert_dir" "$key_dir"
    
    if "$ACME_HOME/acme.sh" --install-cert -d "$DOMAIN" \
        --key-file "$KEY_PATH" \
        --fullchain-file "$CERT_PATH" >/dev/null 2>&1; then
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
    if "$ACME_HOME/acme.sh" --install-cert -d "$DOMAIN" \
        --key-file "$KEY_PATH" \
        --fullchain-file "$CERT_PATH" \
        --reloadcmd "$reload_cmd" >/dev/null 2>&1; then
        success "自动续期安装配置成功"
        info "证书续期时将自动更新到: $CERT_PATH, $KEY_PATH"
    else
        warn "自动续期安装配置失败，续期时需要手动安装"
    fi
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
        
        echo
        info "传递给后续命令的环境变量:"
        echo "  • SSL_CERT_PATH: $SSL_CERT_PATH"
        echo "  • SSL_KEY_PATH: $SSL_KEY_PATH"
        echo "  • SSL_DOMAIN: $SSL_DOMAIN"
        echo "  • SSL_WILDCARD_DOMAIN: $SSL_WILDCARD_DOMAIN"
        echo "  • SSL_EMAIL: $SSL_EMAIL"
        echo "  • SSL_DNS_PROVIDER: $SSL_DNS_PROVIDER"
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
    
    title "证书续期: $domain_to_renew"
    
    if ! prompt_yesno "确定要续期证书 $domain_to_renew 吗?" "y"; then
        info "取消续期"
        return
    fi
    
    step "开始续期证书"
    
    if "$ACME_HOME/acme.sh" --renew -d "$domain_to_renew" --force; then
        success "证书续期成功"
        
        # 重新安装证书到自定义路径
        install_certificate
        verify_certificate
        
        # 执行后续脚本
        if [ "$POST_SCRIPT_ENABLED" = "true" ] && [ -n "$POST_SCRIPT_CMD" ]; then
            info "执行后续命令..."
            eval "$POST_SCRIPT_CMD"
        fi
    else
        error "证书续期失败"
        return 1
    fi
}

# 续期所有证书
renew_all_certificates() {
    title "续期所有证书"
    
    if ! prompt_yesno "确定要续期所有证书吗?" "y"; then
        info "取消批量续期"
        return
    fi
    
    step "开始续期所有证书"
    
    if "$ACME_HOME/acme.sh" --renew-all --force; then
        success "所有证书续期成功"
    else
        error "部分或全部证书续期失败"
        return 1
    fi
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
    if "$ACME_HOME/acme.sh" --remove -d "$domain_to_remove" >/dev/null 2>&1; then
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
    
    # 选择配置模式
    if ! select_config_mode; then
        return
    fi
    
    if ! validate_config; then
        error "配置验证失败"
        if ! go_back; then
            return
        fi
    fi
    
    # 显示最终配置确认
    step "最终配置确认"
    show_config
    
    if ! prompt_yesno "确认以上配置并开始申请证书?" "y"; then
        info "取消证书申请"
        return
    fi
    
    step "开始证书申请流程"
    detect_os
    check_dependencies
    install_acme
    setup_dns_provider
    register_account
    issue_certificate
    install_certificate
    verify_certificate
    
    echo
    success "🎉 SSL 证书生成完成！"
    separator
    info "证书文件位置:"
    echo "  • 证书文件: $CERT_PATH"
    echo "  • 私钥文件: $KEY_PATH"
    if [ -n "$WILDCARD_DOMAIN" ]; then
        echo "  • 通配符域名: $WILDCARD_DOMAIN"
    fi
    echo "  • DNS提供商: $DNS_PROVIDER"
    separator
    
    # 保存配置
    if prompt_yesno "是否保存当前配置以便下次使用?" "y"; then
        save_config
    fi
    
    execute_post_script
}

# 显示菜单
show_menu() {
    title "SSL 证书管理工具 By Prince 2025.10.15 "
    echo -e "${GREEN}  1) [申请] 申请新证书${NC}"
    echo -e "${YELLOW}  2) [续期] 续期证书${NC}"
    echo -e "${YELLOW}  3) [批量续期] 续期所有证书${NC}"
    echo -e "${CYAN}  4) [列表] 列出所有证书${NC}"
    echo -e "${BLUE}  5) [信息] 查看证书信息${NC}"
    echo -e "${RED}  6) [卸载] 卸载证书${NC}"
    echo -e "${RED}  7) [卸载ACME] 卸载 acme.sh${NC}"
    echo -e "${MAGENTA}  8) [配置] 显示/修改配置${NC}"
    echo -e "${CYAN}  9) [保存配置] 保存当前配置${NC}"
    echo -e "${CYAN} 10) [加载配置] 从文件加载配置${NC}"
    echo -e "${CYAN} 11) [帮助] 显示帮助${NC}"
    echo -e "${GREEN}  0) [退出] 退出程序${NC}"
    echo
}

# 主菜单
main_menu() {
    while true; do
        show_menu
        echo -e "${CYAN}请选择操作 [0-11]: ${NC}"
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
                remove_certificate
                ;;
            7)
                uninstall_acme
                ;;
            8)
                modify_config
                ;;
            9)
                save_config
                ;;
            10)
                load_config
                ;;
            11)
                show_help
                ;;
            0)
                info "感谢使用，再见！"
                exit 0
                ;;
            *)
                error "无效选择，请输入 0-11 之间的数字"
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
    echo
    echo -e "${CYAN}主要功能:${NC}"
    echo "  • 申请新证书: 通过 DNS 验证方式申请 SSL 证书"
    echo "  • 证书续期: 续期单个或所有已安装的证书"
    echo "  • 证书管理: 查看证书列表、信息和状态"
    echo "  • 证书卸载: 安全移除不需要的证书"
    echo "  • 配置管理: 显示和修改当前配置"
    echo
    echo -e "${CYAN}支持的 DNS 提供商:${NC}"
    echo "  • CloudFlare (推荐)"
    echo "  • LuaDNS"
    echo "  • Hurricane Electric (HE)"
    echo
    echo -e "${CYAN}支持的环境变量:${NC}"
    echo "  DOMAIN               证书域名"
    echo "  WILDCARD_DOMAIN      通配符域名"
    echo "  EMAIL                注册邮箱"
    echo "  DNS_PROVIDER         DNS提供商: cloudflare, luadns 或 he"
    echo "  CF_Token             CloudFlare API Token (推荐)"
    echo "  CF_Zone_ID           CloudFlare Zone ID (可选)"
    echo "  CF_Account_ID        CloudFlare Account ID (可选)"
    echo "  CF_Key               CloudFlare 全局 API Key (不推荐)"
    echo "  CF_Email             CloudFlare 邮箱 (不推荐)"
    echo "  LUA_KEY              LuaDNS API 密钥"
    echo "  LUA_EMAIL            LuaDNS 邮箱"
    echo "  HE_USERNAME          Hurricane Electric 用户名"
    echo "  HE_PASSWORD          Hurricane Electric 密码"
    echo "  CERT_PATH            证书输出路径"
    echo "  KEY_PATH             私钥输出路径"
    echo "  ACME_SERVER          ACME 服务器"
    echo "  POST_SCRIPT_CMD      后续命令"
    echo "  POST_SCRIPT_ENABLED  是否启用后续命令"
    echo
    echo -e "${CYAN}使用示例:${NC}"
    echo "  # 交互式菜单模式"
    echo "  ./ssl-manager.sh"
    echo
    echo "  # 一键申请证书 (使用环境变量或配置文件)"
    echo "  DOMAIN=\"your-domain.com\" CF_Token=\"your_token\" ./ssl-manager.sh --issue"
    echo
    echo "  # 保存配置后一键运行"
    echo "  ./ssl-manager.sh --quick"
    echo
    echo "  # 续期证书"
    echo "  DOMAIN=\"your-domain.com\" ./ssl-manager.sh --renew"
    echo
    echo -e "${YELLOW}提示: 在 SSH 终端中，建议使用交互式菜单模式以获得最佳体验。${NC}"
}

# 命令行参数处理
case "${1:-}" in
    -i|--issue)
        certificate_issue_flow
        ;;
    -r|--renew)
        renew_certificate
        ;;
    -ra|--renew-all)
        renew_all_certificates
        ;;
    -l|--list)
        list_certificates
        ;;
    -s|--show)
        show_cert_info
        ;;
    -rm|--remove)
        remove_certificate
        ;;
    -u|--uninstall)
        uninstall_acme
        ;;
    -c|--config)
        show_config
        ;;
    -q|--quick)
        quick_issue
        ;;
    -h|--help|help)
        show_help
        exit 0
        ;;
    *)
        # 如果没有参数，显示主菜单
        if [ $# -eq 0 ]; then
            main_menu
        else
            error "未知参数: $1"
            echo
            show_help
            exit 1
        fi
        ;;
esac
