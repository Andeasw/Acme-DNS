# Acme-DNS-Super

**Acme-DNS-Super** is an advanced, rigorous, and bilingual (English/Chinese) Bash wrapper for [acme.sh](https://github.com/acmesh-official/acme.sh). It simplifies SSL certificate issuance, deployment, and maintenance through an intuitive CLI menu.

> **Note:** Version 0.0.1 enforces strict security checks and logic optimization.

### One-Click Launch (Recommended)

*For quick testing (Shortcut feature will be disabled in this mode).*

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```

### Quick Download & Run (Full Features)

**⚠️ Important:** To enable the global shortcut command (`ssl`) and persistent configuration, please download the script locally using the method below.

```bash
wget https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh -O Acme-DNS.sh && chmod +x Acme-DNS.sh && ./Acme-DNS.sh
```

#### OR using curl (Download mode)

```bash
curl -fsSL -o Acme-DNS.sh https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh && chmod +x Acme-DNS.sh && ./Acme-DNS.sh
```

---

## ✨ Key Features

*   **Bilingual Support:** One-click switch between **English** and **Chinese (简体中文)**.
*   **Strict Security:** Input validation for domains and paths to prevent shell injection.
*   **Smart Shortcut:** Creates a global system command (default: `ssl`) for quick access. *Requires local installation.*
*   **Multiple Issuance Modes:**
    *   **HTTP:** Standalone, Nginx, Apache, and Webroot modes.
    *   **DNS:** Support for Cloudflare, LuaDNS, HE.net, ClouDNS, PowerDNS, and generic Manual ENV mode.
*   **Auto-Deployment:** Install certificates directly to Nginx/Apache configurations with auto-reload commands.
*   **Maintenance:** View certificate lists (with localized headers), force renew, or revoke/delete certificates easily.

## 📋 Menu Structure

Upon running the script, you will see the following interactive menu:

1.  **Init Environment:** Installs `socat`, `curl`, `cron`, and `acme.sh` (if missing), and registers your account.
2.  **Settings:**
    *   Change Account Email.
    *   Switch Language (EN/CN).
    *   Switch Default CA (Let's Encrypt / ZeroSSL).
    *   Switch Key Length (RSA-2048 / ECC-256).
    *   **Update/Repair Shortcut.**
3.  **Issue Cert - HTTP Mode:** Best for single domains pointing to the current server.
4.  **Issue Cert - DNS API Mode:** Best for Wildcard certificates or servers behind firewalls.
5.  **Install Cert to Service:** Deploys issued certs to Nginx/Apache paths.
6.  **Cert Maintenance:**
    *   List all certificates (localized table headers).
    *   Force Renew.
    *   Revoke & Delete.
7.  **Uninstall:** Remove the script, shortcut, or fully uninstall `acme.sh`.

## ⚙️ Shortcut Command

If you downloaded the script to your local disk (using `wget` or `curl -o`), the script allows you to create a system shortcut (Menu 1 or Menu 2).

Once created, you can simply type:
```bash
ssl
```
...anywhere in your terminal to open the manager.

> **Why won't it work with `curl | bash`?**
> For security and logic reasons, the shortcut creation is disabled when running in a pipe (online mode) because the system cannot locate a physical file to link to.

## 🛠 Requirements

*   **OS:** Linux (CentOS, Debian, Ubuntu, Alpine, etc.)
*   **User:** Root privileges are required.
*   **Dependencies:** `curl`, `wget`, `socat`, `openssl`, `cron` (The script will attempt to install these automatically).

## 📜 License

This project is a wrapper script based on `acme.sh`.
Released under the MIT License.
