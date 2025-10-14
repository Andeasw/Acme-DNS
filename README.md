Acme-DNS SSL Certificate Manager​
A powerful and user-friendly bash script for managing SSL certificates via acme.sh with DNS verification. Supports both Debian/Ubuntu and Alpine Linux systems.​
Quick Start for VPS SSH​
Directly run these commands in your VPS SSH terminal to download, authorize, and launch the script (works for Debian/Ubuntu/Alpine):​
​
​
Features​
🔐 Automatic SSL Certificate Management​
Certificate issuance and renewal​
Wildcard certificate support (*.example.com)​
Multiple DNS providers (LuaDNS, Hurricane Electric)​
Dual ACME server support (Let's Encrypt, ZeroSSL)​
🖥️ User-Friendly Interface​
Interactive menu system​
Step-by-step configuration wizard​
Color-coded output for readability​
Input validation and error handling​
🔧 Advanced Management​
Single or bulk certificate renewal​
Certificate listing and details view​
Certificate removal and cleanup​
Post-installation script execution support​
Supported DNS Providers​
​
Provider​
Authentication Method​
LuaDNS​
API Key + Email​
Hurricane Electric (HE)​
Username + Password​
​
Usage Methods​
Method 1: Interactive Mode (Recommended)​
Launch the script and follow the on-screen prompts:​
​
./Acme-DNS.sh​
​
Method 2: Direct Command with Env Variables​
Issue a certificate by passing environment variables directly:​
​
DOMAIN="example.com" LUA_KEY="your_luadns_api_key" ./Acme-DNS.sh --issue​
​
Method 3: Wildcard Certificate​
Issue a wildcard certificate for your domain:​
​
DOMAIN="example.com" WILDCARD_DOMAIN="*.example.com" LUA_KEY="your_luadns_api_key" ./Acme-DNS.sh --issue​
​
Environment Variables​
All configurations can be set via environment variables (add these to your command or profile):​
​
# Basic Configuration​
DOMAIN="example.com"               # Primary domain​
WILDCARD_DOMAIN="*.example.com"    # Optional wildcard domain​
EMAIL="admin@example.com"          # Contact email for ACME servers​
CERT_PATH="/root/ssl/cert.pem"     # Path to save certificate​
KEY_PATH="/root/ssl/private.key"   # Path to save private key​
​
# DNS Provider (select one: "luadns" or "he")​
DNS_PROVIDER="luadns"​
​
# LuaDNS Configuration (required if DNS_PROVIDER="luadns")​
LUA_KEY="your_luadns_api_key"​
LUA_EMAIL="your_luadns_account_email"​
​
# Hurricane Electric Configuration (required if DNS_PROVIDER="he")​
HE_USERNAME="your_he_username"​
HE_PASSWORD="your_he_password"​
​
# ACME Server (select one: "letsencrypt" or "zerossl")​
ACME_SERVER="letsencrypt"​
​
​
Usage Examples​
Issue a Certificate​
​
./Acme-DNS.sh --issue​
​
Renew a Specific Certificate​
​
./Acme-DNS.sh --renew​
​
Bulk Renew All Certificates​
​
./Acme-DNS.sh --renew-all​
​
List All Installed Certificates​
​
./Acme-DNS.sh --list​
​
Show Detailed Certificate Info​
​
./Acme-DNS.sh --show​
​
System Requirements​
​
Requirement​
Details​
Supported OS​
Debian 10+, Ubuntu 20.04+, Alpine 3.14+​
Dependencies​
curl, openssl, socat, git​
Shell​
Bash (v4.0+)​
​
Installation​
Download the script from GitHub (use the VPS SSH command above, or run manually):​
​
wget https://github.com/Andeasw/Acme-DNS/blob/main/Acme-DNS.sh -O Acme-DNS.sh​
​
Grant executable permission:​
​
chmod +x Acme-DNS.sh​
​
Launch the script (interactive mode):​
​
./Acme-DNS.sh​
​
Interactive Menu Options​
The script’s interactive menu includes these features:​
Issue Certificate: Wizard for new SSL certificates​
Renew Certificate: Renew a specific certificate​
Renew All: Bulk renewal of all managed certificates​
List Certificates: View all installed certificates​
Certificate Info: Show detailed certificate metadata​
Remove Certificate: Uninstall a specific certificate​
Uninstall ACME: Full cleanup of acme.sh and related files​
Configuration: View/modify saved settings​
Help: Display usage documentation​
Exit: Quit the script​
Notes​
The script automatically installs missing dependencies (works for Debian/Alpine).​
Supports both single-domain and wildcard certificates.​
Includes retry mechanisms and detailed operation logs.​
All status messages are color-coded (green = success, red = error, yellow = warning).​
License​
This project is open-source. Feel free to use, modify, and distribute it as needed.
