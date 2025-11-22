# Acme-DNS-Super 🔐

**[English](#english) | [中文说明](#chinese)**

A powerful, bilingual, and interactive Bash script wrapper for `acme.sh`. It simplifies SSL certificate issuance, installation, and management with a user-friendly menu interface.

> **Current Version:** V1.0.0
> **Core:** Based on the official [acme.sh](https://github.com/acmesh-official/acme.sh)

---

<a name="english"></a>
## 🇬🇧 English Description

### 🚀 Quick Start

**One-Click Installation & Run:**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```

### ✨ Key Features

*   **🌍 Bilingual Support:** Fully localized in **English** and **Chinese** (Menus, Prompts, Errors).
*   **⚡ Smart Initialization:**
    *   Auto-installs dependencies (`curl`, `socat`, `cron`, etc.).
    *   **Auto-registers accounts** for both **Let's Encrypt** and **ZeroSSL** simultaneously to prevent fallback errors.
*   **🚀 Shortcut Command:** Automatically creates a global `ssl` command. You can launch the script anytime by just typing `ssl`.
*   **🛡️ DNS API Modes:**
    *   **8 Pre-configured Providers:** CloudFlare, LuaDNS, Hurricane Electric, ClouDNS, PowerDNS, 1984Hosting, deSEC.io, dynv6.
    *   **🔧 Manual/Custom Mode:** Supports **ALL** acme.sh DNS plugins by allowing manual ENV variable input.
*   **📜 Full Lifecycle Management:** Issue, Install (Deploy to Nginx/Apache path), Renew, and Revoke.
*   **⚙️ Persisted Config:** Remembers your Email, Language, CA, and Key Type settings.

### 📖 Menu Guide

After running the script, you will see the following interactive menu:

1.  **Init Environment:**
    *   Checks/Installs dependencies.
    *   Installs `acme.sh` (Official).
    *   Registers ACME accounts.
    *   Creates the `ssl` shortcut.
    *   *Run this first!*
2.  **System Settings:**
    *   Change Registration Email.
    *   Switch Language (English/Chinese).
    *   Switch Default CA (Let's Encrypt / ZeroSSL).
    *   Switch Key Type (RSA-2048, ECC-256, etc.).
    *   Repair/Update Shortcut.
3.  **Issue Cert - HTTP Mode:**
    *   Standalone (Port 80), Nginx, Apache, or Webroot modes.
    *   Best for single domains.
4.  **Issue Cert - DNS API Mode:**
    *   Supports Wildcard domains (`*.example.com`).
    *   Select your provider or input custom ENV variables.
5.  **Install Cert to Service:**
    *   Copy certs to your specified paths (e.g., `/etc/nginx/ssl/`).
    *   Set reload commands (e.g., `systemctl reload nginx`).
6.  **Cert Maintenance:**
    *   List all certificates.
    *   **Force Renew** specific domains.
    *   **Revoke & Delete** certificates completely.
7.  **Uninstall:**
    *   Remove config only OR Full uninstall (acme.sh + certs + script).

---

<a name="chinese"></a>
## 🇨🇳 中文说明

### 🚀 快速开始

**一键安装并运行：**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```

### ✨ 核心功能

*   **🌍 完美双语支持**：全界面支持 **中文** 和 **English** 切换，不再有语言障碍。
*   **⚡ 智能初始化**：
    *   自动检测并安装依赖 (`curl`, `socat`, `cron`, `openssl` 等)。
    *   **双重账户注册**：初始化时自动同步注册 **Let's Encrypt** 和 **ZeroSSL** 账户，确保切换 CA 时无缝衔接。
*   **🚀 快捷启动指令**：自动创建全局 `ssl` 命令。以后只需在终端输入 `ssl` 即可随时唤醒脚本。
*   **🛡️ 强大的 DNS 支持**：
    *   **8种预设服务商**：CloudFlare, LuaDNS, HE.net, ClouDNS, PowerDNS, 1984Hosting, deSEC.io, dynv6。
    *   **🔧 通用/手动模式**：支持手动输入环境变量，从而兼容 acme.sh 支持的**所有** DNS 插件。
*   **📜 全生命周期管理**：支持证书的 签发、安装 (部署到 Nginx/Apache)、续期 (Renew) 和 吊销 (Revoke)。
*   **⚙️ 配置持久化**：自动保存您的 邮箱、语言偏好、默认 CA 和 密钥类型设置。

### 📖 菜单功能详解

运行脚本后，您将看到以下交互式菜单：

1.  **环境初始化**：
    *   核心步骤！安装依赖、acme.sh、注册账户并配置快捷键。
    *   *首次使用请务必先执行此选项。*
2.  **系统设置**：
    *   修改注册邮箱。
    *   切换语言 (中/英)。
    *   切换默认 CA 厂商。
    *   切换密钥规格 (RSA/ECC)。
    *   修复快捷指令。
3.  **签发证书 - HTTP 模式**：
    *   支持 Standalone (占用80端口)、Nginx、Apache 自动配置或 Webroot 模式。
    *   仅支持单域名。
4.  **签发证书 - DNS API 模式**：
    *   支持 **泛域名** (如 `*.example.com`)。
    *   通过 API Key 验证域名所有权。
    *   包含“手动输入环境变量”选项，可对接任意 DNS 服务商。
5.  **部署证书到服务**：
    *   将签发的证书安装到指定路径 (如 `/etc/nginx/ssl/`)。
    *   配置重载命令 (如 `systemctl reload nginx`)，实现自动续期后重启服务。
6.  **证书维护**：
    *   查看证书列表。
    *   **强制续期** 指定域名。
    *   **吊销并删除** 证书 (清理残留文件)。
7.  **卸载脚本**：
    *   可选：仅清理脚本配置 或 彻底卸载 (移除 acme.sh 及所有证书)。

---

## 🌐 DNS Providers / DNS 服务商支持

| Provider (服务商) | Auth Method (认证方式) | Notes (备注) |
| :--- | :--- | :--- |
| **CloudFlare** | Global API Key + Email | Most Popular / 最常用 |
| **LuaDNS** | API Key + Email | |
| **Hurricane Electric** | Username + Password | he.net |
| **ClouDNS** | Auth ID + Password | Supports Sub-Auth ID |
| **PowerDNS** | API URL + Token | For Self-hosted / 自建 DNS |
| **1984Hosting** | Username + Password | Auto-caches token |
| **deSEC.io** | API Token | Free dynDNS / 免费动态域名 |
| **dynv6** | Token | Supports HTTP/SSH mode |
| **Manual / Custom** | **ENV Key=Value** | **Supports ALL acme.sh plugins** <br> 支持所有插件 (阿里/腾讯/AWS等) |

### 🔧 How to use Custom DNS (如何使用自定义 DNS)

Select **Option 9** in the DNS Menu. You can input any environment variable required by acme.sh plugins.
选择 DNS 菜单中的 **选项 9**。您可以输入 acme.sh 插件所需的任意环境变量。

**Example (Aliyun / 阿里云):**
1. Select Option 9.
2. Input: `Ali_Key=sdfsdfsdfljlbjkljlkjsdfo`
3. Input: `Ali_Secret=jlsdflanljkljlfdsaklkjflsa`
4. Input: `end` (To finish input / 结束输入)
5. Input Plugin Name: `dns_ali`

---

## 🖥️ System Requirements / 系统要求

*   **OS**: Debian/Ubuntu, CentOS/RHEL, Alpine Linux, FreeBSD.
*   **Permissions**: Root access is required (`sudo -i`).
*   **Dependencies**: `curl`, `openssl`, `socat`, `cron` (Script will try to auto-install them).

---

## 🤝 Contributing & Support

*   **Issues**: Please verify with the official [acme.sh](https://github.com/acmesh-official/acme.sh) repository first if it's a certificate issuance error.
*   **Updates**: Use Menu Option 2 -> 5 to upgrade acme.sh core.
