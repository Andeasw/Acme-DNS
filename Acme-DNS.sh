
#!/bin/bash
# ===========================================
# Acme-DNS 一键证书管理脚本
# 项目地址: https://github.com/Andeasw/Acme-DNS
# 证书管理脚本 (acme.sh + 多DNS提供商支持)
# By Prince 2025.10
# ===========================================
#!/bin/bash

# ==============================================================
# Script Name: Acme-DNS-Super
# Description: 基于官方 acme.sh 的高级自动化证书管理集成环境
# Version: 3.1 (Stable)
# Author: System Expert
# ==============================================================

# ==============================================================
# 全局定义与环境检测
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
        # 初始化默认配置
        CA_SERVER="letsencrypt"
        KEY_LENGTH="ec-256"
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

    # 核心依赖列表
    local dependencies=(curl wget socat tar openssl cron)
    
    # 仅当缺少依赖时才运行 update
    local missing_dep=false
    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing_dep=true
            break
        fi
    done

    if [ "$missing_dep" = true ]; then
        echo -e "${YELLOW}检测到缺失依赖，正在更新源并安装...${PLAIN}"
        $update_cmd
    fi

    for dep in "${dependencies[@]}"; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${YELLOW}正在安装: $dep ...${PLAIN}"
            $install_cmd $dep
        else
            echo -e "${GREEN}依赖已就绪: $dep${PLAIN}"
        fi
    done

    # 确保 cron 服务正在运行 (简单检测)
    if [[ -n $(command -v systemctl) ]]; then
        if ! systemctl is-active --quiet cron && ! systemctl is-active --quiet crond; then
             echo -e "${YELLOW}尝试启动 Cron 服务...${PLAIN}"
             systemctl start cron || systemctl start crond
        fi
    fi
}

register_accounts() {
    local email=$1
    if [ -z "$email" ]; then return; fi

    echo -e "${YELLOW}>>> 正在同步 CA 账户注册信息 (关联邮箱: $email)...${PLAIN}"
    
    # 1. 注册 Let's Encrypt
    echo -e "${CYAN}[Let's Encrypt] 正在注册/更新...${PLAIN}"
    "$ACME_SH" --register-account -m "$email" --server letsencrypt --output-insecure
    
    # 2. 注册 ZeroSSL (acme.sh 默认 CA)
    echo -e "${CYAN}[ZeroSSL] 正在注册/更新...${PLAIN}"
    "$ACME_SH" --register-account -m "$email" --server zerossl --output-insecure

    echo -e "${GREEN}账户注册流程执行完毕。${PLAIN}"
}

install_acme_sh() {
    if [ -f "$ACME_SH" ]; then
        echo -e "${GREEN}检测到 acme.sh 已安装。${PLAIN}"
        echo -e "版本信息: $("$ACME_SH" --version | head -n 1)"
    else
        echo -e "${CYAN}正在安装 acme.sh (官方源)...${PLAIN}"
        
        # 邮箱输入与校验
        while true; do
            if [ -z "$USER_EMAIL" ]; then
                read -p "请输入用于 ACME 账户注册的邮箱 (重要): " input_email
                USER_EMAIL="$input_email"
            fi
            
            if [[ "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                break
            else
                echo -e "${RED}邮箱格式不正确，请重新输入。${PLAIN}"
                USER_EMAIL=""
            fi
        done
        
        # 使用官方安装脚本
        curl https://get.acme.sh | sh -s email="$USER_EMAIL"
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}官方安装脚本执行失败，请检查网络连接至 githubusercontent.com${PLAIN}"
            echo -e "${YELLOW}尝试备用 git 安装模式...${PLAIN}"
            ! command -v git &> /dev/null && echo "请先安装 git" && return
            git clone https://github.com/acmesh-official/acme.sh.git ~/.acme.sh
            cd ~/.acme.sh || exit
            ./acme.sh --install -m "$USER_EMAIL"
            cd ..
        fi
    fi
    
    # 强制重新加载配置
    load_config
    
    # 后置配置
    register_accounts "$USER_EMAIL"
    "$ACME_SH" --set-default-ca --server "$CA_SERVER"
    "$ACME_SH" --upgrade --auto-upgrade
    
    save_config
    echo -e "${GREEN}acme.sh 初始化完成！${PLAIN}"
}

# ==============================================================
# 证书签发 (Issue) 模块
# ==============================================================

issue_http() {
    echo -e "${YELLOW}>>> 证书签发 - HTTP 验证模式${PLAIN}"
    echo -e "${YELLOW}注意：此模式需要 80 端口，且不支持泛域名。${PLAIN}"
    
    read -p "请输入域名 (例如: www.example.com): " DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}域名不能为空${PLAIN}" && return

    echo -e "${CYAN}请选择验证方式:${PLAIN}"
    echo -e "1. Standalone (脚本模拟 Web 服务，需确保 80 端口空闲)"
    echo -e "2. Nginx (自动利用现有 Nginx 配置验证)"
    echo -e "3. Apache (自动利用现有 Apache 配置验证)"
    echo -e "4. Webroot (指定网站根目录)"
    read -p "选择 [1-4]: " MODE

    local cmd_flags=""
    
    case $MODE in
        1) 
            # 检查端口占用
            if command -v netstat &>/dev/null; then
                if netstat -tuln | grep -q ":80 "; then
                    echo -e "${RED}警告: 检测到 80 端口被占用，Standalone 模式可能失败。${PLAIN}"
                    read -p "是否强制继续? (y/n): " force_run
                    [[ "$force_run" != "y" ]] && return
                fi
            fi
            cmd_flags="--standalone" 
            ;;
        2) cmd_flags="--nginx" ;;
        3) cmd_flags="--apache" ;;
        4) 
            read -p "请输入网站根目录路径 (例 /var/www/html): " WEBROOT_PATH
            if [ ! -d "$WEBROOT_PATH" ]; then
                echo -e "${RED}目录不存在${PLAIN}"
                return
            fi
            cmd_flags="--webroot $WEBROOT_PATH"
            ;;
        *) echo -e "${RED}无效选择${PLAIN}"; return ;;
    esac

    "$ACME_SH" --issue -d "$DOMAIN" $cmd_flags --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}证书签发成功！接下来请执行 [安装/部署证书]。${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}证书签发失败。建议查看日志排查问题。${PLAIN}"
    fi
}

issue_dns() {
    echo -e "${YELLOW}>>> 证书签发 - DNS API 模式 (推荐)${PLAIN}"
    echo -e "${YELLOW}支持泛域名 (如 *.example.com)。需要提供 DNS 服务商 API 密钥。${PLAIN}"
    
    read -p "请输入域名 (例如: *.example.com): " DOMAIN
    [ -z "$DOMAIN" ] && echo -e "${RED}域名不能为空${PLAIN}" && return

    echo -e "${CYAN}选择 DNS 服务商:${PLAIN}"
    echo -e "1. CloudFlare"
    echo -e "2. Tencent Cloud (DNSPod)"
    echo -e "3. Alibaba Cloud (Aliyun)"
    echo -e "4. Huawei Cloud"
    echo -e "5. GoDaddy"
    echo -e "6. Amazon Route53"
    echo -e "7. 自定义/手动输入 (支持 acme.sh 所有插件)"
    echo -e "0. 返回"
    read -p "选择 [0-7]: " DNS_PROVIDER

    local dns_type=""
    
    # 清理可能存在的旧环境变量，防止冲突
    unset CF_Key CF_Email DP_Id DP_Key Ali_Key Ali_Secret HUAWEICLOUD_AccessKeyId HUAWEICLOUD_SecretAccessKey GD_Key GD_Secret AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

    case $DNS_PROVIDER in
        1)
            read -p "CloudFlare Global API Key: " CF_Key
            read -p "CloudFlare Email: " CF_Email
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
            read -p "Huawei Cloud AccessKeyId: " HUAWEICLOUD_AccessKeyId
            read -p "Huawei Cloud SecretAccessKey: " HUAWEICLOUD_SecretAccessKey
            export HUAWEICLOUD_AccessKeyId="$HUAWEICLOUD_AccessKeyId"
            export HUAWEICLOUD_SecretAccessKey="$HUAWEICLOUD_SecretAccessKey"
            dns_type="dns_huaweicloud"
            ;;
        5)
            read -p "GoDaddy Key: " GD_Key
            read -p "GoDaddy Secret: " GD_Secret
            export GD_Key="$GD_Key"
            export GD_Secret="$GD_Secret"
            dns_type="dns_gd"
            ;;
        6)
            read -p "AWS Access Key ID: " AWS_ACCESS_KEY_ID
            read -p "AWS Secret Access Key: " AWS_SECRET_ACCESS_KEY
            export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
            export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
            dns_type="dns_aws"
            ;;
        7)
            echo -e "${YELLOW}请参考 acme.sh 官方 Wiki 查找对应服务商的变量名。${PLAIN}"
            echo -e "输入格式：变量名=值 (输入 'end' 结束)"
            echo -e "例如输入: DP_Id=123456"
            while true; do
                read -p "环境变量输入 > " env_input
                [[ "$env_input" == "end" ]] && break
                if [[ "$env_input" == *"="* ]]; then
                    export "$env_input"
                else
                    echo -e "${RED}格式错误，请包含 '='${PLAIN}"
                fi
            done
            read -p "请输入 DNS 插件名称 (如 dns_cf, dns_dp): " dns_type
            ;;
        0) return ;;
        *) echo -e "${RED}无效选择${PLAIN}"; return ;;
    esac
    
    if [ -z "$dns_type" ]; then
        echo -e "${RED}未指定 DNS 插件类型。${PLAIN}"
        return
    fi

    echo -e "${CYAN}开始签发证书，请稍候...${PLAIN}"
    "$ACME_SH" --issue --dns "$dns_type" -d "$DOMAIN" --keylength "$KEY_LENGTH" --server "$CA_SERVER"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}证书签发成功！接下来请执行 [安装/部署证书]。${PLAIN}"
        install_cert_menu "$DOMAIN"
    else
        echo -e "${RED}证书签发失败。请检查 API 密钥是否正确。${PLAIN}"
    fi
}

# ==============================================================
# 证书部署 (Install) 模块
# ==============================================================

install_cert_menu() {
    local default_domain=$1
    echo -e "${YELLOW}>>> 安装/部署证书 (Install Cert to Service)${PLAIN}"
    echo -e "${CYAN}此步骤将证书复制到指定位置，并设置自动重载服务命令。${PLAIN}"
    
    if [ -z "$default_domain" ]; then
        read -p "请输入已签发的域名: " DOMAIN
    else
        DOMAIN=$default_domain
    fi

    # 验证域名证书是否存在
    if [ ! -d "$ACME_DIR/$DOMAIN" ] && [ ! -d "$ACME_DIR/${DOMAIN}_ecc" ]; then
        echo -e "${RED}错误：未在 acme.sh 目录找到该域名的证书文件。请先签发。${PLAIN}"
        return
    fi

    echo -e "${CYAN}配置目标路径 (无需部署的文件请留空):${PLAIN}"
    read -p "Cert 文件目标路径 (例 /etc/nginx/ssl/cert.pem): " CERT_PATH
    read -p "Key  文件目标路径 (例 /etc/nginx/ssl/key.pem):  " KEY_PATH
    read -p "CA   文件目标路径 (例 /etc/nginx/ssl/fullchain.pem): " CA_PATH
    read -p "服务重载命令 (例 systemctl reload nginx): " RELOAD_CMD

    # 构建命令字符串
    local cmd_build="$ACME_SH --install-cert -d $DOMAIN"
    
    # 处理 ECC 证书路径差异
    if [[ "$KEY_LENGTH" == "ec"* ]]; then
        cmd_build="$cmd_build --ecc"
    fi

    [ -n "$CERT_PATH" ] && cmd_build="$cmd_build --cert-file $CERT_PATH"
    [ -n "$KEY_PATH" ] && cmd_build="$cmd_build --key-file $KEY_PATH"
    [ -n "$CA_PATH" ] && cmd_build="$cmd_build --fullchain-file $CA_PATH"
    [ -n "$RELOAD_CMD" ] && cmd_build="$cmd_build --reloadcmd \"$RELOAD_CMD\""

    echo -e "${YELLOW}正在执行安装...${PLAIN}"
    eval "$cmd_build"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}证书安装配置成功！acme.sh 将在续期后自动执行重载命令。${PLAIN}"
    else
        echo -e "${RED}安装失败。请检查路径权限或路径是否存在。${PLAIN}"
    fi
}

# ==============================================================
# 高级管理与维护
# ==============================================================

configure_settings() {
    while true; do
        echo -e "${CYAN}===== 全局配置管理 =====${PLAIN}"
        echo -e "当前账户邮箱: ${GREEN}${USER_EMAIL:-未设置}${PLAIN}"
        echo -e "当前默认 CA:  ${GREEN}$CA_SERVER${PLAIN}"
        echo -e "密钥类型:     ${GREEN}$KEY_LENGTH${PLAIN}"
        echo "------------------------"
        echo "1. 修改账户注册邮箱 (自动同步更新)"
        echo "2. 切换默认 CA (Let's Encrypt / ZeroSSL)"
        echo "3. 切换密钥长度 (RSA/ECC)"
        echo "4. 查看 acme.sh 运行日志"
        echo "5. 强制更新 acme.sh (官方稳定版)"
        echo "0. 返回主菜单"
        read -p "请选择: " choice
        
        case $choice in
            1)
                read -p "请输入新邮箱: " new_email
                if [[ "$new_email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                    USER_EMAIL="$new_email"
                    save_config
                    register_accounts "$USER_EMAIL"
                else
                    echo -e "${RED}邮箱格式无效${PLAIN}"
                fi
                ;;
            2)
                echo "1. Let's Encrypt"
                echo "2. ZeroSSL"
                echo "3. Google Public CA"
                echo "4. BuyPass"
                read -p "选择 CA [默认 Let's Encrypt]: " ca_choice
                case $ca_choice in
                    1) CA_SERVER="letsencrypt" ;;
                    2) CA_SERVER="zerossl" ;;
                    3) CA_SERVER="google" ;;
                    4) CA_SERVER="buypass" ;;
                    *) CA_SERVER="letsencrypt" ;;
                esac
                "$ACME_SH" --set-default-ca --server "$CA_SERVER"
                save_config
                echo -e "${GREEN}已切换至 $CA_SERVER${PLAIN}"
                ;;
            3)
                echo "1. RSA-2048"
                echo "2. RSA-4096"
                echo "3. ECC-256 (推荐，速度快兼容性好)"
                echo "4. ECC-384"
                read -p "选择 Key 类型: " key_choice
                case $key_choice in
                    1) KEY_LENGTH="2048" ;;
                    2) KEY_LENGTH="4096" ;;
                    3) KEY_LENGTH="ec-256" ;;
                    4) KEY_LENGTH="ec-384" ;;
                    *) KEY_LENGTH="ec-256" ;;
                esac
                save_config
                echo -e "${GREEN}已设置密钥类型为 $KEY_LENGTH${PLAIN}"
                ;;
            4)
                if [ -f "$ACME_DIR/acme.sh.log" ]; then
                    tail -n 50 "$ACME_DIR/acme.sh.log"
                    echo -e "${YELLOW}以上显示最后 50 行日志${PLAIN}"
                else
                    echo -e "${RED}暂无日志文件${PLAIN}"
                fi
                read -p "按回车继续..." 
                ;;
            5)
                echo -e "${CYAN}执行官方更新...${PLAIN}"
                "$ACME_SH" --upgrade
                ;;
            0) return ;;
            *) echo -e "${RED}无效选择${PLAIN}" ;;
        esac
        echo ""
    done
}

manage_certs() {
    while true; do
        echo -e "${CYAN}===== 证书列表与维护 =====${PLAIN}"
        "$ACME_SH" --list
        echo "------------------------"
        echo "1. 手动强制续期 (Renew Force)"
        echo "2. 吊销并删除证书 (Revoke & Remove)"
        echo "3. 移除证书记录 (仅从列表中移除，保留文件)"
        echo "0. 返回"
        read -p "请选择: " choice
        
        case $choice in
            1) 
                read -p "请输入要续期的域名: " renew_domain
                [ -n "$renew_domain" ] && "$ACME_SH" --renew -d "$renew_domain" --force 
                ;;
            2)
                read -p "请输入要吊销删除的域名: " del_domain
                if [ -n "$del_domain" ]; then
                     read -p "确认向 CA 吊销证书吗? (y/n): " is_revoke
                     if [[ "$is_revoke" == "y" ]]; then
                        "$ACME_SH" --revoke -d "$del_domain"
                     fi
                     "$ACME_SH" --remove -d "$del_domain"
                     # 清理残留文件
                     rm -rf "$ACME_DIR/$del_domain"
                     rm -rf "$ACME_DIR/${del_domain}_ecc"
                     echo -e "${GREEN}证书已移除${PLAIN}"
                fi
                ;;
            3)
                read -p "请输入要移除管理的域名: " rm_domain
                [ -n "$rm_domain" ] && "$ACME_SH" --remove -d "$rm_domain"
                ;;
            0) return ;;
            *) echo -e "${RED}无效选择${PLAIN}" ;;
        esac
        read -p "按回车继续..."
    done
}

uninstall_menu() {
    echo -e "${RED}===== 卸载管理 =====${PLAIN}"
    echo "1. 仅清理本脚本配置 (保留 acme.sh 及已签发证书)"
    echo "2. 彻底卸载 (移除 acme.sh、所有证书、Crontab 任务及本脚本)"
    echo "0. 取消"
    read -p "请慎重选择 [0-2]: " un_choice

    case $un_choice in
        1)
            rm -f "$CONFIG_FILE"
            echo -e "${GREEN}本脚本配置文件已删除。${PLAIN}"
            ;;
        2)
            echo -e "${RED}警告：此操作将删除 ~/.acme.sh 目录下所有数据！${PLAIN}"
            read -p "确认执行? (请输入 'uninstall'): " confirm_str
            if [[ "$confirm_str" == "uninstall" ]]; then
                if [ -f "$ACME_SH" ]; then
                    "$ACME_SH" --uninstall
                fi
                rm -rf "$ACME_DIR"
                rm -f "$CONFIG_FILE"
                rm -f "$0"
                echo -e "${GREEN}系统已彻底清理，脚本自毁完成。${PLAIN}"
                exit 0
            else
                echo -e "${YELLOW}操作已取消${PLAIN}"
            fi
            ;;
        *) return ;;
    esac
}

# ==============================================================
# 主程序入口
# ==============================================================

show_menu() {
    clear
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "${BLUE}           Acme-DNS-Super V3.1  |  自动化证书管理             ${PLAIN}"
    echo -e "${BLUE}==============================================================${PLAIN}"
    echo -e "默认 CA:   ${GREEN}$CA_SERVER${PLAIN}"
    echo -e "密钥规格:  ${GREEN}$KEY_LENGTH${PLAIN}"
    echo -e "注册账户:  ${GREEN}${USER_EMAIL:-未设置}${PLAIN}"
    echo -e "--------------------------------------------------------------"
    echo -e " 1. 环境初始化 (安装依赖 & acme.sh)"
    echo -e " 2. 证书签发 - HTTP 验证 (Webroot/Standalone/Nginx)"
    echo -e " 3. 证书签发 - DNS API 验证 (支持泛域名)"
    echo -e " 4. 证书安装 (部署到 Web 服务器)"
    echo -e "--------------------------------------------------------------"
    echo -e " 5. 证书列表与维护 (续期/吊销)"
    echo -e " 6. 全局配置 (切换 CA / 修改邮箱 / 更新)"
    echo -e " 7. 脚本与 acme.sh 卸载"
    echo -e " 0. 退出脚本"
    echo -e "--------------------------------------------------------------"
    read -p " 请输入选项 [0-7]: " num

    case $num in
        1) check_dependencies && install_acme_sh ;;
        2) issue_http ;;
        3) issue_dns ;;
        4) install_cert_menu ;;
        5) manage_certs ;;
        6) configure_settings ;;
        7) uninstall_menu ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选择，请重试${PLAIN}" ;;
    esac
}

# 初始化运行
load_config
# 检查 acme.sh 是否安装，给出提示
if [ ! -f "$ACME_SH" ]; then
    echo -e "${YELLOW}提示: 未检测到 acme.sh，建议优先执行 [1. 环境初始化]${PLAIN}"
    sleep 2
fi

while true; do
    show_menu
    echo ""
    read -p "按回车键返回主菜单..."
done
