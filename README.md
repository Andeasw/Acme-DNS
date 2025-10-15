# Acme-DNS SSL Certificate Manager  
A powerful and user-friendly bash script for managing SSL certificates via `acme.sh` with DNS verification. Supports Debian/Ubuntu, Alpine Linux, and FreeBSD systems.


## VPS SSH Quick Start  
Run these commands directly in your VPS SSH terminal to download, authorize, and launch the script:

### One-Click Launch (Recommended)
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```

### Quick Download & Run
```bash
wget https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh -O Acme-DNS.sh && chmod +x Acme-DNS.sh && ./Acme-DNS.sh
```

### One-Click Commands for Common Tasks  
- **Quick Certificate Issue (with existing config)**  
  ```bash
  ./Acme-DNS.sh --quick
  ```  

- **Issue Certificate with CloudFlare**  
  ```bash
  DOMAIN="example.com" CF_Token="your_token" ./Acme-DNS.sh --issue
  ```  

- **Issue Wildcard Certificate**  
  ```bash
  DOMAIN="example.com" WILDCARD_DOMAIN="*.example.com" CF_Token="your_token" ./Acme-DNS.sh --issue
  ```  

- **Renew All Certificates**  
  ```bash
  ./Acme-DNS.sh --renew-all
  ```  

- **List All Certificates**  
  ```bash
  ./Acme-DNS.sh --list
  ```  


## Features  

### 🔐 Automatic SSL Certificate Management  
- Certificate issuance and renewal  
- Wildcard certificate support (`*.example.com`)  
- Multiple DNS providers (CloudFlare, LuaDNS, Hurricane Electric)  
- Dual ACME server support (Let's Encrypt, ZeroSSL)  
- RSA 2048 encryption standard  


### 🖥️ User-Friendly Interface  
- Interactive menu system with color coding  
- Step-by-step configuration wizard  
- Input validation and error handling  
- Progress indicators for long operations  
- Configuration save/load functionality  


### 🔧 Advanced Management  
- Single or bulk certificate renewal  
- Certificate listing with expiry status  
- Detailed certificate information view  
- Certificate removal and cleanup  
- Post-installation script execution support  
- Automatic dependency installation  


## Supported DNS Providers  

| Provider                | Authentication Method                  | Recommended |
|-------------------------|----------------------------------------|-------------|
| CloudFlare              | API Token (recommended) or Global API Key | ✅          |
| LuaDNS                  | API Key + Email                        | ✅          |
| Hurricane Electric (HE) | Username + Password                    | ✅          |  


## Supported Systems  

| OS               | Package Manager | Status               |
|------------------|-----------------|----------------------|
| Debian/Ubuntu    | apt-get         | ✅ Fully Supported   |
| Alpine Linux     | apk             | ✅ Fully Supported   |
| FreeBSD          | pkg             | ✅ Fully Supported   |
| CentOS/RHEL      | yum             | ⚠️ Limited Support   |  


## Usage Methods  

### Method 1: Interactive Mode (Recommended)  
Launch the script and follow on-screen prompts:  
```bash
./Acme-DNS.sh
```  


### Method 2: Quick Mode (One-Click)  
Use saved configuration or environment variables:  
```bash
./Acme-DNS.sh --quick
```  


### Method 3: Direct Commands  
Issue certificate with environment variables:  
```bash
DOMAIN="example.com" CF_Token="your_token" ./Acme-DNS.sh --issue
```  


## Environment Variables  
All configurations can be set via environment variables:  

### Basic Configuration  
```bash
DOMAIN="example.com"               # Primary domain
WILDCARD_DOMAIN="*.example.com"    # Optional wildcard domain  
EMAIL="admin@example.com"          # Contact email for ACME servers
CERT_PATH="/root/ssl/cert.pem"     # Path to save certificate
KEY_PATH="/root/ssl/private.key"   # Path to save private key
```  


### DNS Provider Configuration  
```bash
# Select one DNS provider
DNS_PROVIDER="cloudflare"          # "cloudflare", "luadns", or "he"

# CloudFlare Configuration (recommended)
CF_Token="your_api_token"          # API Token (recommended)
CF_Zone_ID="your_zone_id"          # Optional
CF_Account_ID="your_account_id"    # Optional

# CloudFlare Legacy (not recommended)
CF_Key="your_global_api_key"       # Global API Key
CF_Email="your_email@example.com"  # Account email

# LuaDNS Configuration
LUA_KEY="your_luadns_api_key"
LUA_EMAIL="your_luadns_account_email"

# Hurricane Electric Configuration  
HE_USERNAME="your_he_username"
HE_PASSWORD="your_he_password"
```  


### Advanced Configuration  
```bash
# ACME Server (select one)
ACME_SERVER="letsencrypt"          # "letsencrypt" or "zerossl"

# Post-Install Script
POST_SCRIPT_CMD="systemctl reload nginx"  # Example: Reload web server
POST_SCRIPT_ENABLED="true"                # Enable/disable post-script
```  


## Usage Examples  

### Basic Certificate Operations  
```bash
# Issue a new certificate
./Acme-DNS.sh --issue

# Renew a specific certificate
./Acme-DNS.sh --renew

# Renew all certificates
./Acme-DNS.sh --renew-all

# List all certificates
./Acme-DNS.sh --list

# Show certificate details
./Acme-DNS.sh --show
```  


### Management Commands  
```bash
# Remove a certificate
./Acme-DNS.sh --remove

# Uninstall acme.sh completely
./Acme-DNS.sh --uninstall

# Show current configuration
./Acme-DNS.sh --config

# Show help information
./Acme-DNS.sh --help
```  


### Practical One-Click Examples  
1. **Quick CloudFlare Setup**  
   ```bash
   DOMAIN="example.com" CF_Token="your_token" ./Acme-DNS.sh --quick
   ```  

2. **Wildcard Certificate with CloudFlare**  
   ```bash
   DOMAIN="example.com" WILDCARD_DOMAIN="*.example.com" CF_Token="your_token" ./Acme-DNS.sh --issue
   ```  

3. **LuaDNS Certificate**  
   ```bash
   DOMAIN="example.com" LUA_KEY="your_key" LUA_EMAIL="admin@example.com" ./Acme-DNS.sh --issue
   ```  

4. **Save Configuration for Future Use**  
   ```bash
   # First time: configure interactively, then save
   ./Acme-DNS.sh
   # When prompted, save configuration
   # Next time: use quick mode
   ./Acme-DNS.sh --quick
   ```  


## System Requirements  

| Requirement  | Details                                          |
|--------------|--------------------------------------------------|
| Supported OS | Debian 10+, Ubuntu 20.04+, Alpine 3.14+, FreeBSD 12+ |
| Dependencies | `curl`, `openssl` (auto-installed)               |
| Recommended  | `socat`, `cron` (auto-installed if needed)       |
| Shell        | Bash (v4.0+)                                     |
| Disk Space   | ~100MB for `acme.sh` and certificates            |  


## Installation  

### Automatic Installation (Recommended)  
```bash
# Download and run in one command
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```  


### Manual Installation  
```bash
# Download script
wget https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh -O Acme-DNS.sh

# Make executable
chmod +x Acme-DNS.sh

# Run interactive mode
./Acme-DNS.sh
```  


## Interactive Menu Options  
The script provides a comprehensive interactive menu:  

- 📝 **Issue Certificate** - Guided wizard for new SSL certificates  
- 🔄 **Renew Certificate** - Renew specific certificate  
- 🔄 **Renew All** - Bulk renewal of all managed certificates  
- 📋 **List Certificates** - View all certificates with expiry status  
- 🔍 **Certificate Info** - Show detailed certificate information  
- 🗑️ **Remove Certificate** - Uninstall specific certificate  
- 🧹 **Uninstall ACME** - Complete cleanup of `acme.sh`  
- ⚙️ **Configuration** - View and modify settings  
- 💾 **Save Config** - Save current configuration to file  
- 📂 **Load Config** - Load configuration from file  
- ❓ **Help** - Display usage documentation  
- 🚪 **Exit** - Quit the script  


## Configuration Management  

### Save Configuration  
After setting up your preferences, save them for future use:  
```bash
# Configuration will be saved to ./ssl-manager.conf
```  


### Load Saved Configuration  
```bash
# Automatically loads from ./ssl-manager.conf in quick mode
./Acme-DNS.sh --quick
```  


## Notes  
- ✅ **Automatic Dependency Handling** - Missing packages are automatically detected and installed  
- ✅ **Cross-Platform Support** - Works on Debian, Ubuntu, Alpine, and FreeBSD systems  
- ✅ **Smart Retry Logic** - Automatic retries with fallback servers  
- ✅ **Color-Coded Output** - Green = success, Red = error, Yellow = warning, Blue = information  
- ✅ **Wildcard Support** - Full support for `*.example.com` certificates  
- ✅ **Security Focused** - Uses API tokens instead of global keys when possible  
- ✅ **Configuration Persistence** - Save settings for one-click future use  


## Troubleshooting  

### Common Issues  

#### Network Connectivity  
```bash
# Test connectivity
curl -I https://github.com
```  

#### Permission Issues  
```bash
# Ensure script is executable
chmod +x Acme-DNS.sh
```  

#### Dependency Problems  
```bash
# Script automatically installs dependencies, but you can manually install:
# Debian/Ubuntu: apt-get install curl openssl socat
# Alpine: apk add curl openssl socat
# FreeBSD: pkg install curl openssl socat
```  


## License  
This project is open-source. Feel free to use, modify, and distribute as needed.  


## Support  
For issues and feature requests, please open an issue on the GitHub repository.
