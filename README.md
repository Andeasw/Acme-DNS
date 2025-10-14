Acme-DNS SSL Certificate Manager
A powerful and user-friendly bash script for managing SSL certificates using acme.sh with DNS verification. Supports both Debian and Alpine Linux systems.
Features
🔐 Automatic SSL Certificate Management
Certificate issuance and renewal
Wildcard certificate support
Multiple DNS providers (LuaDNS, Hurricane Electric)
Both Let's Encrypt and ZeroSSL support
🖥️ User-Friendly Interface
Interactive menu system
Step-by-step configuration wizard
Color-coded output for better readability
Input validation and error handling
🔧 Advanced Management
Certificate renewal (single or bulk)
Certificate listing and information
Certificate removal and cleanup
Post-installation script support
Supported DNS Providers
LuaDNS - API key authentication
Hurricane Electric (HE) - Username/password authentication
Quick Start
Method 1: Interactive Mode (Recommended)
bash
./Acme-DNS.sh
Method 2: Direct Command with Environment Variables
bash
DOMAIN="example.com" LUA_KEY="your_api_key" ./Acme-DNS.sh --issue
Method 3: Wildcard Certificate
bash
DOMAIN="example.com" WILDCARD_DOMAIN="*.example.com" LUA_KEY="your_api_key" ./Acme-DNS.sh --issue
Environment Variables
All configuration can be set via environment variables:
bash
# Basic Configuration
DOMAIN="example.com"
WILDCARD_DOMAIN="*.example.com"
EMAIL="admin@example.com"
CERT_PATH="/root/ssl/cert.pem"
KEY_PATH="/root/ssl/private.key"

# DNS Provider (choose one)
DNS_PROVIDER="luadns"  # or "he"

# LuaDNS Configuration
LUA_KEY="your_luadns_api_key"
LUA_EMAIL="your_luadns_email"

# Hurricane Electric Configuration  
HE_USERNAME="your_he_username"
HE_PASSWORD="your_he_password"

# ACME Server
ACME_SERVER="letsencrypt"  # or "zerossl"

# Post-install Script
POST_SCRIPT_CMD="systemctl reload nginx"
POST_SCRIPT_ENABLED="true"
Usage Examples
Issue a Certificate
bash
./Acme-DNS.sh --issue
Renew a Certificate
bash
./Acme-DNS.sh --renew
List All Certificates
bash
./Acme-DNS.sh --list
Show Certificate Info
bash
./Acme-DNS.sh --show
System Requirements
Supported OS: Debian, Ubuntu, Alpine Linux
Dependencies: curl, openssl, socat, git
Shell: Bash
Installation
Download the script:
bash
wget https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh
chmod +x Acme-DNS.sh
Run with interactive menu:
bash
./Acme-DNS.sh
Menu Options
The interactive menu provides access to all features:
Issue Certificate - New SSL certificate wizard
Renew Certificate - Renew specific certificate
Renew All - Bulk renewal of all certificates
List Certificates - Show all installed certificates
Certificate Info - Detailed certificate information
Remove Certificate - Uninstall specific certificate
Uninstall ACME - Complete cleanup of acme.sh
Configuration - View and modify settings
Help - Display help information
Exit - Quit the program
Notes
The script automatically handles dependency installation
Supports both single domain and wildcard certificates
Includes comprehensive error handling and retry mechanisms
All operations are logged with clear status messages
License
This project is open source. Feel free to use and modify as needed.
This README provides a clear overview while keeping it simple and focused on the essential information users need to get started.
