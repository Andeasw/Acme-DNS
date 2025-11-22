#!/bin/bash

# ==============================================================
# Script Name: Acme-DNS-Super
# Description: 高级 acme.sh 交互式管理脚本 (Let's Encrypt & ZeroSSL 专用版)
# Version: 3.2 (Optimized)
# Author: System Expert
# ==============================================================

# ==============================================================
# 全局定义
# ==============================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'

# 路径定义
CONFIG_FILE="$HOME/.acme_super_config"
ACME_DIR="$HOME/.acme.sh"
ACME_SH="$ACME_DIR/acme.sh"

# 检查 Root 权限
[[ $EUID -ne 0 ]] && echo -e "${RED}[Error] 必须使用 root 权限运行此脚本！${PLAIN}" && exit 1

# ==============================================================
# 配置管理模块
# ==============================================================

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        # 初始化默认配置 (优化：默认 RSA-2048)
        CA_SERVER="letsencrypt"
        KEY_LENGTH="2048"
        USER_EMAIL=""
    fi
}

save_config() {
    cat > "$CONFIG_FILE" <<EOF
CA_SERVER="$CA_SERVER"
KEY_LENGTH="$KEY_LENGTH"
USER_EMAIL="$USER_EMAIL"
EOF
}

# ==============================================================
# 核心功能：依赖与安装
# ==============================================================

check_dependencies() {
    echo -e "${CYAN}正在检查系统核心依赖...${PLAIN}"
    
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
        echo -e "${RED}[Error] 未检测到支持的包管理器，请手动安装依赖。${PLAIN}"
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
        echo -e "${YELLOW}检测到缺失依赖，正在更新源并补全...${PLAIN}"
        $update_cmd
    fi

    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${YELLOW}安装依赖: $dep ...${PLAIN}"
            $install_cmd $dep
        fi
    done
    
    echo -e "${GREEN}所有依赖检查通过。${PLAIN}"

    # 确保 cron 服务运行
    if [[ -n $(command -v systemctl) ]]; then
        if ! systemctl is-active --quiet cron && ! systemctl is-active --quiet crond; then
             systemctl start cron || systemctl start crond
        fi
    fi
}

register_accounts() {
    local email=$1
    if [ -z "$email" ]; then return; fi

    echo -e "${YELLOW}>>> 正在同步 CA 账户注册信息 (Email: $email)...${PLAIN}"
    
    # 1. 注册 Let's Encrypt
    echo -e "${CYAN}[Let's Encrypt] 正在注册/更新账户...${PLAIN}"
    "$ACME_SH" --register-account -m "$email" --server letsencrypt --output-insecure
    
    # 2. 注册 ZeroSSL
    echo -e "${CYAN}[ZeroSSL] 正在注册/更新账户...${PLAIN}"
    "$ACME_SH" --register-account -m "$email" --server zerossl --output-insecure

    echo -e "${GREEN}账户同步完成。${PLAIN}"
}

install_acme_sh() {
    if [ -f "$ACME_SH" ]; then
        echo -e "${GREEN}acme.sh 已安装。${PLAIN}"
        echo -e "版本: $("$ACME_SH" --version | head -n 1)"
    else
        echo -e "${CYAN}准备安装 acme.sh...${PLAIN}"
        
        # 邮箱输入与校验
        while true; do
            if [ -z "$USER_EMAIL" ]; then
                read -p "请输入注册邮箱 (将用于 ACME 账户通知): " input_email
                USER_EMAIL="$input_email"
            fi
            
            if [[ "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                save_config # 立即保存
                break
            else
                echo -e "${RED}邮箱格式错误，请重试。${PLAIN}"
                USER_EMAIL=""
            fi
        done
        
        # 官方安装
        curl https://get.acme.sh | sh -s email="$USER_EMAIL"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}官方源连接失败，切换至 Github 备用源...${PLAIN}"
            ! command -v git &> /dev/null && echo "请先安装 git" && return
            git clone https://github.com/acmesh-official/acme.sh.git ~/.acme.sh
            cd ~/.acme.sh || exit
            ./acme.sh --install -m "$USER_EMAIL"
            cd ..
        fi
    fi
    
    # 重新加载配置环境
    load_config
    
    # 确保账户注册到位
    register_accounts "$USER_EMAIL"
    
    # 设置默认 CA 和自动更新
    "$ACME_SH" --set-default-ca --server "$CA_SERVER"
    "$ACME_SH" --upgrade --auto-upgrade
    
    save_config
    echo -e "${GREEN}初始化环境配置完成！${PLAIN}"
}

# ==============================================================
# 证书签发 (Issue) 模块
# ==============================================================

issue_http() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}请先执行环境初始化！${PLAIN}"; return; fi
    
    echo -e "${YELLOW}>>> 证书签发 - HTTP 模式${PLAIN}"
    echo -e "${YELLOW}提示：仅支持单域名 (非泛域名)，需占用 80 端口或利用现有 Web Server。${PLAIN}"
    
    read -p "请输入域名 (例: www.example.com): " DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}域名不能为空${PLAIN}" && return

    echo -e "${CYAN}验证模式:${PLAIN}"
    echo -e "1. Standalone (脚本模拟 Web 服务，需 80 端口空闲)"
    echo -e "2. Nginx (自动修改 Nginx 配置)"
    echo -e "3. Apache (自动修改 Apache 配置)"
    echo -e "4. Webroot (指定网站根目录)"
    read -p "选择 [1-4]: " MODE

    local cmd_flags=""
    case $MODE in
        1) 
            if command -v netstat &>/dev/null && netstat -tuln | grep -q ":80 "; then
                echo -e "${RED}警告: 80 端口被占用，Standalone 模式可能失败。${PLAIN}"
                read -p "强制继续? (y/n): " force
                [[ "$force" != "y" ]] && return
            fi
            cmd_flags="--standalone" 
            ;;
        2) cmd_flags="--nginx" ;;
        3) cmd_flags="--apache" ;;
        4) 
            read -p "输入网站根目录 (例 /var/www/html): " webroot
            [ ! -d "$webroot" ] && echo -e "${RED}目录不存在${PLAIN}" && return
            cmd_flags="--webroot $webroot"
            ;;
        *) echo -e "${RED}无效选择${PLAIN}"; return ;;
    esac

    "$ACME_SH" --issue -d "$DOMAIN" $cmd_flags --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}签发成功！请继续执行 [安装/部署证书] 步骤。${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}签发失败，请检查端口、防火墙或日志。${PLAIN}"
    fi
}

issue_dns() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}请先执行环境初始化！${PLAIN}"; return; fi

    echo -e "${YELLOW}>>> 证书签发 - DNS API 模式 (推荐)${PLAIN}"
    echo -e "${YELLOW}提示：支持泛域名 (如 *.example.com)，需提供 DNS 厂商 API 密钥。${PLAIN}"
    
    read -p "请输入域名: " DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}域名不能为空${PLAIN}" && return

    echo -e "${CYAN}DNS 服务商:${PLAIN}"
    echo -e "1. CloudFlare"
    echo -e "2. Tencent (DNSPod)"
    echo -e "3. Aliyun (阿里云)"
    echo -e "4. Huawei Cloud"
    echo -e "5. AWS Route53"
    echo -e "6. 手动输入环境变量 (通用模式)"
    echo -e "0. 返回"
    read -p "选择 [0-6]: " DNS_OPT

    # 清理环境变量防止冲突
    unset CF_Key CF_Email DP_Id DP_Key Ali_Key Ali_Secret HUAWEICLOUD_AccessKeyId HUAWEICLOUD_SecretAccessKey AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

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
            read -p "Huawei KeyId: " HUAWEICLOUD_AccessKeyId
            read -p "Huawei Secret: " HUAWEICLOUD_SecretAccessKey
            export HUAWEICLOUD_AccessKeyId="$HUAWEICLOUD_AccessKeyId"
            export HUAWEICLOUD_SecretAccessKey="$HUAWEICLOUD_SecretAccessKey"
            dns_type="dns_huaweicloud"
            ;;
        5)
            read -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID
            read -p "AWS Secret: " AWS_SECRET_ACCESS_KEY
            export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
            dns_type="dns_aws"
            ;;
        6)
            echo -e "${YELLOW}参照 acme.sh 官方文档输入变量。输入 'end' 结束。${PLAIN}"
            while true; do
                read -p "ENV (格式 Key=Value): " env_in
                [[ "$env_in" == "end" ]] && break
                export "$env_in"
            done
            read -p "请输入插件代码 (如 dns_cf): " dns_type
            ;;
        0) return ;;
        *) echo -e "${RED}无效选择${PLAIN}"; return ;;
    esac
    
    [ -z "$dns_type" ] && return

    echo -e "${CYAN}开始请求签发...${PLAIN}"
    "$ACME_SH" --issue --dns "$dns_type" -d "$DOMAIN" --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}签发成功！请继续执行 [安装/部署证书] 步骤。${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}签发失败。${PLAIN}"
    fi
}

# ==============================================================
# 证书部署 (Install) 模块
# ==============================================================

install_cert_menu() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}请先执行环境初始化！${PLAIN}"; return; fi

    local default_domain=$1
    echo -e "${YELLOW}>>> 证书安装 (Install Cert to Service)${PLAIN}"
    
    if [ -z "$default_domain" ]; then
        read -p "请输入已签发域名: " DOMAIN
    else
        DOMAIN=$default_domain
    fi

    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}未找到该域名的证书文件，请先签发。${PLAIN}"
        return
    fi

    echo -e "${CYAN}目标文件路径 (不需要的项直接回车):${PLAIN}"
    read -p "Cert Path (例 /etc/nginx/ssl/cert.pem): " CERT_PATH
    read -p "Key  Path (例 /etc/nginx/ssl/key.pem):  " KEY_PATH
    read -p "CA   Path (例 /etc/nginx/ssl/full.pem): " CA_PATH
    read -p "Reload Cmd (例 systemctl reload nginx): " RELOAD_CMD

    local cmd_build="$ACME_SH --install-cert -d $DOMAIN"
    [[ "$KEY_LENGTH" == "ec"* ]] && cmd_build="$cmd_build --ecc"

    [ -n "$CERT_PATH" ] && cmd_build="$cmd_build --cert-file $CERT_PATH"
    [ -n "$KEY_PATH" ] && cmd_build="$cmd_build --key-file $KEY_PATH"
    [ -n "$CA_PATH" ] && cmd_build="$cmd_build --fullchain-file $CA_PATH"
    [ -n "$RELOAD_CMD" ] && cmd_build="$cmd_build --reloadcmd \"$RELOAD_CMD\""

    echo -e "${YELLOW}执行安装...${PLAIN}"
    eval "$cmd_build"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}安装成功，已添加自动续期钩子。${PLAIN}"
    else
        echo -e "${RED}安装失败，请检查路径权限。${PLAIN}"
    fi
}

# ==============================================================
# 系统设置与维护
# ==============================================================

configure_settings() {
    while true; do
        echo -e "${CYAN}===== 系统设置 =====${PLAIN}"
        echo -e "状态: CA[${GREEN}$CA_SERVER${PLAIN}] | Key[${GREEN}$KEY_LENGTH${PLAIN}] | Email[${GREEN}$USER_EMAIL${PLAIN}]"
        echo "------------------------"
        echo "1. 修改注册邮箱 (将同步更新 CA 账户)"
        echo "2. 切换默认 CA (Let's Encrypt / ZeroSSL)"
        echo "3. 切换密钥规格 (RSA/ECC)"
        echo "4. 强制更新 acme.sh"
        echo "0. 返回"
        read -p "选择: " choice
        
        case $choice in
            1)
                read -p "新邮箱: " new_email
                if [[ "$new_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    USER_EMAIL="$new_email"
                    save_config
                    register_accounts "$USER_EMAIL"
                else
                    echo -e "${RED}格式错误${PLAIN}"
                fi
                ;;
            2)
                echo "1. Let's Encrypt (默认)"
                echo "2. ZeroSSL"
                echo "3. Google Public CA"
                read -p "选择 CA: " ca_opt
                case $ca_opt in
                    1) CA_SERVER="letsencrypt" ;;
                    2) CA_SERVER="zerossl" ;;
                    3) CA_SERVER="google" ;;
                    *) CA_SERVER="letsencrypt" ;;
                esac
                "$ACME_SH" --set-default-ca --server "$CA_SERVER"
                save_config
                ;;
            3)
                echo "1. RSA-2048 (兼容性好)"
                echo "2. RSA-4096"
                echo "3. ECC-256 (速度快)"
                read -p "选择 Key: " key_opt
                case $key_opt in
                    1) KEY_LENGTH="2048" ;;
                    2) KEY_LENGTH="4096" ;;
                    3) KEY_LENGTH="ec-256" ;;
                    *) KEY_LENGTH="2048" ;;
                esac
                save_config
                ;;
            4) "$ACME_SH" --upgrade ;;
            0) return ;;
            *) echo -e "${RED}无效${PLAIN}" ;;
        esac
        echo -e "${GREEN}设置已更新${PLAIN}"
    done
}

manage_certs() {
    if [ ! -f "$ACME_SH" ]; then echo -e "${RED}请先执行环境初始化！${PLAIN}"; return; fi
    
    while true; do
        echo -e "${CYAN}===== 证书维护 =====${PLAIN}"
        "$ACME_SH" --list
        echo "------------------------"
        echo "1. 手动续期 (Force Renew)"
        echo "2. 吊销并删除 (Revoke & Delete)"
        echo "0. 返回"
        read -p "选择: " choice
        
        case $choice in
            1) 
                read -p "域名: " d_renew
                [ -n "$d_renew" ] && "$ACME_SH" --renew -d "$d_renew" --force 
                ;;
            2)
                read -p "域名: " d_del
                if [ -n "$d_del" ]; then
                     read -p "确认吊销? (y/n): " confirm
                     if [[ "$confirm" == "y" ]]; then
                        "$ACME_SH" --revoke -d "$d_del"
                        "$ACME_SH" --remove -d "$d_del"
                        rm -rf "$ACME_DIR/$d_del" "$ACME_DIR/${d_del}_ecc"
                        echo -e "${GREEN}已彻底删除${PLAIN}"
                     fi
                fi
                ;;
            0) return ;;
        esac
    done
}

uninstall_menu() {
    echo -e "${RED}===== 卸载选项 =====${PLAIN}"
    echo "1. 仅清理脚本配置 (保留 acme.sh 及证书)"
    echo "2. 彻底卸载 (移除 acme.sh、证书、任务及本脚本)"
    read -p "选择 [1-2]: " u_opt
    
    if [[ "$u_opt" == "1" ]]; then
        rm -f "$CONFIG_FILE"
        echo -e "${GREEN}配置已清理${PLAIN}"
    elif [[ "$u_opt" == "2" ]]; then
        read -p "确认彻底卸载? 输入 'DELETE': " confirm
        if [[ "$confirm" == "DELETE" ]]; then
            [ -f "$ACME_SH" ] && "$ACME_SH" --uninstall
            rm -rf "$ACME_DIR" "$CONFIG_FILE" "$0"
            echo -e "${GREEN}卸载完成，脚本已自毁。${PLAIN}"
            exit 0
        fi
    fi
}

# ==============================================================
# 主界面
# ==============================================================

show_menu() {
    clear
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${BLUE}           Acme-DNS-Super V3.2  |  自动化证书管理             ${PLAIN}"
    echo -e "${BLUE}==============================================================${PLAIN}"
    # 优化：单行显示状态
    echo -e "当前状态: CA: ${GREEN}${CA_SERVER}${PLAIN} | Key: ${GREEN}${KEY_LENGTH}${PLAIN} | Email: ${GREEN}${USER_EMAIL:-未设置}${PLAIN}"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"

    if [ ! -f "$ACME_SH" ]; then
        echo -e "${RED}>> 检测到系统未安装 acme.sh，请优先执行选项 [1] <<${PLAIN}"
    fi

    echo -e " 1. 初始化环境 (安装依赖 & acme.sh & 注册账户)"
    echo -e " 2. 系统设置 (修改邮箱 / 切换 CA / 密钥规格)"
    echo -e "--------------------------------------------------------------"
    echo -e " 3. 申请证书 - HTTP 模式 (单域名)"
    echo -e " 4. 申请证书 - DNS API 模式 (支持泛域名)"
    echo -e " 5. 安装证书到服务 (Nginx/Apache 等)"
    echo -e "--------------------------------------------------------------"
    echo -e " 6. 证书列表与维护 (续期/吊销)"
    echo -e " 7. 脚本卸载"
    echo -e " 0. 退出"
    echo -e "${BLUE}--------------------------------------------------------------${PLAIN}"
    read -p " 请输入选项 [0-7]: " num

    case $num in
        1) check_dependencies && install_acme_sh ;;
        2) configure_settings ;;
        3) issue_http ;;
        4) issue_dns ;;
        5) install_cert_menu ;;
        6) manage_certs ;;
        7) uninstall_menu ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选择${PLAIN}" ;;
    esac
}

# 入口逻辑
load_config
while true; do
    show_menu
    echo ""
    read -p "按回车键继续..."
done
