# Acme-DNS SSL Certificate Manager

A powerful and user-friendly Bash script for managing SSL certificates via `acme.sh` with DNS verification. Supports Debian/Ubuntu, Alpine Linux, and FreeBSD.

---

## 🚀 Quick Start

### One-Click Launch (Recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```

### Quick Download & Run

```bash
wget https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh -O Acme-DNS.sh && chmod +x Acme-DNS.sh && ./Acme-DNS.sh
```

#### OR using curl

```
curl -fsSL -o Acme-DNS.sh https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh && chmod +x Acme-DNS.sh && ./Acme-DNS.sh
```

---

## ⚡ One-Click Commands

* **Quick Certificate Issue (existing config):**

```bash
./Acme-DNS.sh --quick
```

* **Issue Certificate (CloudFlare):**

```bash
DOMAIN="example.com" CF_Token="your_token" ./Acme-DNS.sh --issue
```

* **Issue Certificate (ClouDNS):**

```bash
DOMAIN="example.com" CLOUDNS_SUB_AUTH_ID="your_sub_auth_id" CLOUDNS_AUTH_PASSWORD="your_password" ./Acme-DNS.sh --issue
```

* **Wildcard Certificate:**

```bash
DOMAIN="example.com" WILDCARD_DOMAIN="*.example.com" CF_Token="your_token" ./Acme-DNS.sh --issue
```

* **Renew All Certificates:**

```bash
./Acme-DNS.sh --renew-all
```

* **List All Certificates:**

```bash
./Acme-DNS.sh --list
```

---

## 🔐 Features

* Automatic SSL issuance & renewal
* Wildcard certificate support (`*.example.com`)
* **8 DNS Providers**: CloudFlare, LuaDNS, Hurricane Electric, ClouDNS, PowerDNS, 1984Hosting, deSEC.io, dynv6
* Dual ACME server support: Let's Encrypt, ZeroSSL
* **Multi-key-type support**: RSA-2048 (default), RSA-4096, ECC-256, ECC-384, ECC-521
* **Install & Auto-Renew**: Install certificates to custom paths with automatic renewal via cron or systemd
* **Secure Credential Storage**: Sensitive credentials (passwords/tokens) are never stored in plaintext config files
* **DNS Propagation Display**: Real-time countdown display during DNS record propagation wait (120 seconds)
* **Quick Startup**: Optional quick access command - just type `ssl` to launch the script from anywhere
* Interactive menu with color-coded output
* Step-by-step configuration wizard
* Configuration save/load functionality
* Post-installation script support (e.g., reload Nginx)

---

## 🖥️ Supported Systems

| OS            | Package Manager | Status             |
| ------------- | --------------- | ------------------ |
| Debian/Ubuntu | apt-get         | ✅ Fully Supported  |
| Alpine Linux  | apk             | ✅ Fully Supported  |
| FreeBSD       | pkg             | ✅ Fully Supported  |
| CentOS/RHEL   | yum             | ⚠️ Limited Support |

---

## 🌐 Supported DNS Providers

| Provider                | Auth Method                               | Recommended | Notes                    |
| ----------------------- | ----------------------------------------- | ----------- | ------------------------ |
| CloudFlare              | API Token (recommended) or Global API Key | ✅           | Most popular             |
| LuaDNS                  | API Key + Email                           | ✅           | Stable API               |
| Hurricane Electric (HE) | Username + Password                       | ✅           | Account credentials      |
| ClouDNS                 | Sub-Auth ID (recommended) or Auth ID      | ✅           | Limited access support   |
| PowerDNS                | API URL + Token                           | ✅           | Self-hosted DNS          |
| 1984Hosting             | Username + Password                       | ✅           | Login token cached       |
| deSEC.io                | API Token                                 | ✅           | Free dynDNS service      |
| dynv6                   | HTTP Token or SSH Key                     | ✅           | Dual authentication mode |

---

## ⚙️ Configuration

### Basic

```bash
DOMAIN="example.com"
WILDCARD_DOMAIN="*.example.com"  # optional
EMAIL="admin@example.com"
CERT_PATH="/root/ssl/cert.pem"
KEY_PATH="/root/ssl/private.key"
KEY_TYPE="rsa-2048"  # Options: rsa-2048, rsa-4096, ec-256, ec-384, ec-521
```

### DNS Provider Examples

#### CloudFlare (Recommended)
```bash
DNS_PROVIDER="cloudflare"
CF_Token="your_api_token"      # Recommended
CF_Zone_ID="your_zone_id"      # Optional
```

#### PowerDNS (Self-hosted)
```bash
DNS_PROVIDER="powerdns"
PDNS_Url="http://ns.example.com:8081"
PDNS_ServerId="localhost"      # Default: localhost
PDNS_Token="your_api_token"
PDNS_Ttl="60"                  # Default: 60 seconds
```

#### 1984Hosting (Website Login)
```bash
DNS_PROVIDER="1984hosting"
One984HOSTING_Username="your_username"
One984HOSTING_Password="your_password"
# 初次登录后将自动缓存认证令牌到 ~/.acme.sh/account.conf
```

#### deSEC.io (Free dynDNS)
```bash
DNS_PROVIDER="desec"
DEDYN_TOKEN="your_api_token"
# Recommended: Limit token access by IP/CIDR in deSEC control panel
```

#### dynv6 (Dual Authentication)
```bash
DNS_PROVIDER="dynv6"
# Option 1: HTTP REST API
DYNV6_TOKEN="your_http_token"

# Option 2: SSH API
DYNV6_KEY="/path/to/ssh/keyfile"

# If both are set, HTTP Token will be used
```

Other DNS providers (LuaDNS, HE, ClouDNS) follow similar environment variables.

### Advanced

```bash
ACME_SERVER="letsencrypt"           # or "zerossl"
POST_SCRIPT_CMD="systemctl reload nginx"
POST_SCRIPT_ENABLED="true"
```

---

## 🛠️ Common Commands

```bash
# Issue certificate
./Acme-DNS.sh --issue

# Issue certificate with specific key type
KEY_TYPE="ec-256" DOMAIN="example.com" ./Acme-DNS.sh --issue

# Install certificate to custom path with auto-renew
./Acme-DNS.sh install -d example.com --key-type ec-256

# Renew certificate
./Acme-DNS.sh --renew

# Renew all
./Acme-DNS.sh --renew-all

# List certificates
./Acme-DNS.sh --list

# Show certificate details
./Acme-DNS.sh --show

# Remove certificate
./Acme-DNS.sh --remove

# Uninstall acme.sh
./Acme-DNS.sh --uninstall

# Show configuration
./Acme-DNS.sh --config

# Help
./Acme-DNS.sh --help
```

#### ✨ New Feature: Install & Auto-Renew (Option 6)

This new menu option allows you to:

* Select or input a domain name
* Choose key type (RSA-2048/4096, ECC-256/384/521)
* Specify custom installation paths for certificate files
* Automatically configure cron-based renewal
* Optionally set up systemd timer for renewal
* View renewal schedule and next check time

**Usage**: Simply select option `6` from the main menu and follow the prompts.

---

## 💡 Tips & Security

* Use **Sub-Auth ID** for ClouDNS for limited access
* Avoid using global API keys when possible
* Keep strong passwords for all accounts
* Wildcard certificates are fully supported
* Configuration can be saved for quick future use:

```bash
./Acme-DNS.sh --quick
```

---

## 🖥️ System Requirements

* OS: Debian 10+, Ubuntu 20.04+, Alpine 3.14+, FreeBSD 12+
* Dependencies: `curl`, `openssl` (auto-installed)
* Recommended: `socat`, `cron` (auto-installed if needed)
* Bash v4.0+, ~100MB disk space

---

## ⚠️ Troubleshooting

* **Network:** `curl -I https://github.com`
* **Permissions:** `chmod +x Acme-DNS.sh`
* **Dependencies:**

  * Debian/Ubuntu: `apt-get install curl openssl socat`
  * Alpine: `apk add curl openssl socat`
  * FreeBSD: `pkg install curl openssl socat`
* **ClouDNS Auth:** Ensure correct Sub-Auth/Auth ID and password

---

## 🔍 DNS Provider Special Cases & Solutions

### PowerDNS
**Special Requirements:**
- Must have PowerDNS API enabled in configuration
- API Token must be generated in PowerDNS admin panel
- API URL should include port (usually 8081)

**Reference:** https://doc.powerdns.com/md/httpapi/README/

**Solution for API not accessible:**
```bash
# Check PowerDNS config file (pdns.conf or pdns.d/api.conf)
api=yes
api-key=your_secret_token
webserver=yes
webserver-address=0.0.0.0
webserver-port=8081
```

### 1984Hosting
**How It Works:**
- 1984Hosting does **NOT** provide a traditional API
- The acme.sh plugin logs into the 1984Hosting website to update DNS TXT records
- Only username and password are required for initial authentication

**Session Token Caching:**
- After first successful login, 1984Hosting returns an auth token
- This token is automatically saved in `~/.acme.sh/account.conf`
- Future runs will reuse the cached token instead of username/password
- The plugin will only ask for credentials if the token expires

**Requirements:**
- You must own the domain at 1984Hosting
- Standard account (no special API access needed)
- Username and password for the 1984Hosting website

**Troubleshooting:**
1. Verify your credentials are correct for https://1984.hosting/
2. Ensure domain is registered and DNS is managed at 1984Hosting
3. If login fails repeatedly, the cached token may have expired - provide credentials again
4. Clear cached tokens if needed: `rm ~/.acme.sh/account.conf` (use with caution)

**Reference:** https://github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_1984hosting
**Error Reporting:** https://github.com/acmesh-official/acme.sh/issues

### deSEC.io
**Special Requirements:**
- Free dynDNS service, registration required at https://desec.io
- API Token generated from account dashboard
- Supports wildcard certificates

**Security Best Practice:**
- Limit token access by IP address/CIDR in deSEC control panel
- Tokens can be regenerated if compromised

**Common Issues:**
- Ensure domain is registered in deSEC (not just DNS records)
- Token must have full DNS management permissions

**Error Reporting:** https://github.com/acmesh-official/acme.sh/issues

### dynv6
**Dual Authentication Modes:**

**Mode 1: HTTP REST API (Recommended)**
- Simpler setup, just needs HTTP token
- Token can be generated from dynv6 website
- Use `DYNV6_TOKEN` environment variable

**Mode 2: SSH API**
- Requires SSH key authentication
- More secure but complex setup
- Use `DYNV6_KEY` environment variable to specify key file path
- If no key specified, acme.sh will generate one for you
- Generated key must be added to dynv6 account

**Priority:** If both HTTP Token and SSH Key are configured, HTTP Token takes precedence

**SSH Key Setup:**
```bash
# Option 1: Use existing key
export DYNV6_KEY="/path/to/your/private_key"

# Option 2: Let acme.sh generate one
# Key will be generated during first run
# Add the public key to your dynv6 account at:
# https://dynv6.com/keys
```

**Common Issues:**
- Ensure at least one authentication method is configured
- For SSH: public key must be registered in dynv6 account
- For HTTP: token must be valid and not expired

**Error Reporting:** https://github.com/acmesh-official/acme.sh/issues

---

## 📝 Multi-CA Support & Fallback

The script supports automatic fallback between multiple Certificate Authorities:

**Default CA List:** `letsencrypt,zerossl`

If the primary CA (Let's Encrypt) fails, the script automatically tries the next CA (ZeroSSL).

**Customization:**
```bash
ACME_CA_LIST="letsencrypt,zerossl,buypass" ./Acme-DNS.sh --issue
```

---

## 🔧 Advanced Configuration

### Network Tuning
The script includes built-in network optimization for ACME operations:

```bash
ACME_CURL_CONNECT_TIMEOUT=5    # Connection timeout (seconds)
ACME_CURL_MAX_TIME=40          # Maximum operation time (seconds)
ACME_CURL_RETRIES=2            # Number of retries
ACME_CURL_RETRY_DELAY=2        # Delay between retries (seconds)
ACME_REGISTER_TIMEOUT=30       # Account registration timeout (seconds)
```

### Certificate Synchronization
Automatically sync certificates to multiple locations:

```bash
CERT_SYNC_DIR="/etc/nginx/ssl"
SERVICE_RELOAD_CMD="systemctl reload nginx"
./Acme-DNS.sh --issue
```

---

## 🆘 Getting Help

- **GitHub Issues:** https://github.com/Andeasw/Acme-DNS/issues
- **acme.sh Documentation:** https://github.com/acmesh-official/acme.sh
- **DNS Provider Docs:** See individual provider documentation for API setup

