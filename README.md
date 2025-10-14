# Acme-DNS SSL Certificate Manager

A powerful and user-friendly bash script for managing SSL certificates via `acme.sh` with DNS verification. Supports Debian/Ubuntu and Alpine Linux systems.

## VPS SSH Quick Start

Run these commands directly in your VPS SSH terminal to download, authorize, and launch the script (works for Debian/Ubuntu/Alpine):

# One-Click Launch (Recommended)
```
bash <(curl -fsSL https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh)
```

## Features

### 🔐 Automatic SSL Certificate Management



* Certificate issuance and renewal

* Wildcard certificate support (`*.example.com`)

* Dual DNS providers (LuaDNS, Hurricane Electric)

* Dual ACME server support (Let's Encrypt, ZeroSSL)

### 🖥️ User-Friendly Interface



* Interactive menu system

* Step-by-step configuration wizard

* Color-coded output for readability

* Input validation and error handling

### 🔧 Advanced Management



* Single or bulk certificate renewal

* Certificate listing and details view

* Certificate removal and cleanup

* Post-installation script execution support

## Supported DNS Providers



| Provider                | Authentication Method |
| ----------------------- | --------------------- |
| LuaDNS                  | API Key + Email       |
| Hurricane Electric (HE) | Username + Password   |

## Usage Methods

### Method 1: Interactive Mode (Recommended)

Launch the script and follow on-screen prompts:



```
./Acme-DNS.sh
```

### Method 2: Direct Command with Env Variables

Issue a certificate by passing environment variables directly:



```
DOMAIN="example.com" LUA\_KEY="your\_luadns\_api\_key" ./Acme-DNS.sh --issue
```

### Method 3: Wildcard Certificate

Issue a wildcard certificate for your domain:



```
DOMAIN="example.com" WILDCARD\_DOMAIN="\*.example.com" LUA\_KEY="your\_luadns\_api\_key" ./Acme-DNS.sh --issue
```

## Environment Variables

All configurations can be set via environment variables (add to your command or profile):



```
\# Basic Configuration

DOMAIN="example.com"               # Primary domain

WILDCARD\_DOMAIN="\*.example.com"    # Optional wildcard domain

EMAIL="admin@example.com"          # Contact email for ACME servers

CERT\_PATH="/root/ssl/cert.pem"     # Path to save certificate

KEY\_PATH="/root/ssl/private.key"   # Path to save private key

\# DNS Provider (select one: "luadns" or "he")

DNS\_PROVIDER="luadns"

\# LuaDNS Configuration (required if DNS\_PROVIDER="luadns")

LUA\_KEY="your\_luadns\_api\_key"

LUA\_EMAIL="your\_luadns\_account\_email"

\# Hurricane Electric Configuration (required if DNS\_PROVIDER="he")

HE\_USERNAME="your\_he\_username"

HE\_PASSWORD="your\_he\_password"

\# ACME Server (select one: "letsencrypt" or "zerossl")

ACME\_SERVER="letsencrypt"

\# Post-Install Script (runs after certificate issuance/renewal)

POST\_SCRIPT\_CMD="systemctl reload nginx"  # Example: Reload Nginx

POST\_SCRIPT\_ENABLED="true"                # Enable/disable post-script
```

## Usage Examples

### Issue a Certificate



```
./Acme-DNS.sh --issue
```

### Renew a Specific Certificate



```
./Acme-DNS.sh --renew
```

### Bulk Renew All Certificates



```
./Acme-DNS.sh --renew-all
```

### List All Installed Certificates



```
./Acme-DNS.sh --list
```

### Show Detailed Certificate Info



```
./Acme-DNS.sh --show
```

## System Requirements



| Requirement  | Details                                 |
| ------------ | --------------------------------------- |
| Supported OS | Debian 10+, Ubuntu 20.04+, Alpine 3.14+ |
| Dependencies | `curl`, `openssl`, `socat`, `git`       |
| Shell        | Bash (v4.0+)                            |

## Installation



1. Download the raw script from GitHub (use the VPS SSH command above, or run manually):



```
wget https://raw.githubusercontent.com/Andeasw/Acme-DNS/main/Acme-DNS.sh -O Acme-DNS.sh
```



1. Grant executable permission:



```
chmod +x Acme-DNS.sh
```



1. Launch the script (interactive mode):



```
./Acme-DNS.sh
```

## Interactive Menu Options

The script’s interactive menu includes these features:



* **Issue Certificate**: Wizard for new SSL certificates

* **Renew Certificate**: Renew a specific certificate

* **Renew All**: Bulk renewal of all managed certificates

* **List Certificates**: View all installed certificates

* **Certificate Info**: Show detailed certificate metadata

* **Remove Certificate**: Uninstall a specific certificate

* **Uninstall ACME**: Full cleanup of `acme.sh` and related files

* **Configuration**: View/modify saved settings

* **Help**: Display usage documentation

* **Exit**: Quit the script

## Notes



* The script automatically installs missing dependencies (works for Debian/Alpine).

* Supports both single-domain and wildcard certificates.

* Includes retry mechanisms and detailed operation logs.

* All status messages are color-coded (green = success, red = error, yellow = warning).

* Uses GitHub’s "raw" script URL to ensure direct, executable file downloads (avoids HTML blob issues).

## License

This project is open-source. Feel free to use, modify, and distribute it as needed.
