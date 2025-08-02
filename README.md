# F-Society Toolkit - V2

A comprehensive, automated reconnaissance toolkit for bug bounty hunters and security researchers. This enhanced version includes advanced subdomain enumeration, vulnerability scanning, OSINT collection, and complete automation pipelines.

## 🚀 Features

### Core Reconnaissance Tools
- **🔧 Port Scanner**: Multi-threaded TCP port scanning with service detection
- **⚡ Nmap Integration**: Advanced Nmap scanning with multiple scan types
- **🔍 Subdomain Enumeration**: Multi-method subdomain discovery (DNS, Certificate Transparency, etc.)
- **🔎 Amass Integration**: Professional subdomain enumeration using OWASP Amass
- **💥 GoBuster Integration**: Directory, file, and DNS brute-forcing.
- **🌐 Web Crawler**: Intelligent web application crawling and endpoint discovery
- **📁 Directory Enumeration**: HTTP directory/file enumeration using wordlists
- **🛡️ Vulnerability Scanner**: Automated testing for common web vulnerabilities
- **💉 SQL Injection Scanner**: Automated SQL injection testing with SQLMap.
- **📊 OSINT Collector**: Intelligence gathering from multiple public sources
- **🔑 Hashcat Integration**: Password cracking attacks using Hashcat
- **📶 WiFi Hacking**: Launch Airgeddon for wireless network auditing
- **👤 Social Media Finder**: Find social media accounts by username using Sherlock
- **📸 OSINTGram**: Gather Instagram OSINT data using OSINTGram
- **📷 Instagram Scanner**: Scrape public Instagram profile information
- **🐦 Twitter Scanner**: Scrape public Twitter profile information
- **👔 LinkedIn Searcher**: Search LinkedIn profiles and companies
- **📘 Facebook Searcher**: Search Facebook profiles and pages
- **📧 Email Finder**: Find email users for a given domain
- **📧 Email Verifier**: Verify email addresses and check their validity
- **📱 Mobile OSINT**: Gather OSINT data for a mobile phone number
- **📱 Phone Validator**: Validate and gather information about phone numbers
- **📡 Modem Scanner**: Scan network modems for vulnerabilities
- **💣 Payload Generator**: Generate common payloads (e.g., reverse shells)
- **🤖 Metasploit Automation**: Automate running Metasploit modules
- **🛡️ Domain Reputation**: Check domain/IP reputation using various services
- **📍 IP Geolocation**: Get geolocation information for IP addresses
- **📈 Data Analyzer**: Advanced analysis and reporting of scan results

### Automation & Integration
- **🎯 Full Reconnaissance Pipeline**: Complete automated reconnaissance workflow
- **🔄 Multi-threaded Operations**: High-performance concurrent scanning
- **📋 Multiple Output Formats**: JSON, HTML, and TXT reporting
- **🔧 Configurable Workflows**: Customizable scan profiles and settings
- **🔑 API Integration**: Support for Shodan, GitHub, and other APIs

## 📦 Installation

Follow these steps to set up the toolkit on your local machine.

### 1. Prerequisites
Make sure you have the following installed on your system:
- **Python 3.7+** and `pip`
- **Git**

### 2. Clone the Repository
```bash
git clone https://github.com/Nix-Hax/bug-b ounty-toolkit.git
cd bug-bounty-toolkit
```

### 3. Set Up a Virtual Environment
It is highly recommended to use a Python virtual environment to manage dependencies and avoid conflicts with other projects.

```bash
# Create a virtual environment named 'venv'
python3 -m venv venv

# Activate the virtual environment
# On macOS and Linux:
source venv/bin/activate

# On Windows:
# venv\Scripts\activate
```
*You should see `(venv)` at the beginning of your terminal prompt, indicating that the environment is active.*

### 4. Install Python Dependencies
With the virtual environment active, install the required Python packages. Sherlock is installed as part of this process.
```bash
pip install -r requirements.txt
```

### 5. Install External Tools (Optional but Recommended)
For full functionality, some modules in this toolkit rely on external tools. Please install them using your system's package manager.

**On Debian/Ubuntu:**
```bash
sudo apt-get update && sudo apt-get install -y nmap gobuster sqlmap hashcat
```

**On macOS (using Homebrew):**
```bash
brew install nmap gobuster sqlmap hashcat
```

**For Other Tools:**
- **Amass**: Follow the official [Amass installation guide](https://github.com/OWASP/Amass/blob/master/doc/install.md).
- **Airgeddon**: Follow the official [Airgeddon installation guide](https://github.com/v1s1t0r1sh3r3/airgeddon).
- **Metasploit Framework**: Follow the official [Metasploit installation guide](https://metasploit.help.rapid7.com/docs/installing-the-metasploit-framework).
```

## 🎯 Usage

### Quick Start
```bash
# Show all available commands
python main.py --help

# Run full reconnaissance on a domain
python main.py full-recon example.com

# Basic port scan
python main.py port-scan example.com --common-ports

# Subdomain enumeration
python main.py subdomain-enum example.com
```

### Advanced Usage

#### Port Scanning
```bash
# Basic port scan
python main.py port-scan 192.168.1.1 --common-ports

# Advanced Nmap scanning
python main.py nmap-scan example.com -t comprehensive
python main.py nmap-scan 192.168.1.1 -t service -p 1-1000
python main.py nmap-scan target.com -t vulnerability
```

#### Subdomain Enumeration
```bash
# Multi-method subdomain enumeration
python main.py subdomain-enum example.com -m all -t 100

# Using specific methods
python main.py subdomain-enum example.com -m dns,ct,search

# Using custom wordlist
python main.py subdomain-enum example.com -w custom_wordlist.txt

# Amass integration
python main.py amass-scan example.com -t comprehensive
python main.py amass-scan example.com -t passive
```

#### Web Application Testing
```bash
# Web crawling
python main.py web-crawl https://example.com -d 3 -p 200 --analyze-js

# Directory enumeration with GoBuster
python main.py gobuster-scan dir -t https://example.com -w wordlists/common_dirs.txt

# Vulnerability scanning
python main.py vuln-scan https://example.com
python main.py vuln-scan https://example.com -e /login,/admin,/api

# SQL Injection Scanning
python main.py sql-injection "http://testphp.vulnweb.com/listproducts.php?cat=1" --level 2 --risk 2
```

#### Password Cracking, WiFi & Social Media
```bash
# Hashcat password cracking (MD5 example)
python main.py hashcat-attack /path/to/hashes.txt -m 0 -w /path/to/wordlist.txt

# Launch interactive WiFi hacking session
python main.py wifi-hack

# Find social media accounts by username
python main.py social-scan johndoe -o social_media_report.txt

#### Exploitation & Social Engineering
```bash
# Find email addresses for a domain
python main.py email-find example.com

# Gather OSINT on a phone number
python main.py mobile-osint "+11234567890"

# Scan a modem for vulnerabilities
python main.py modem-scan 192.168.1.1

# Generate a reverse shell payload
python main.py payload-gen reverse_shell --lhost 10.10.10.2 --lport 4444

# Run a Metasploit module (e.g., handler)
python main.py metasploit-run exploit/multi/handler --lhost 10.10.10.2 --lport 4444
```

#### Social Media OSINT Tools
```bash
# Gather Instagram OSINT data using OSINTGram
python main.py osintgram username

# Scrape public Instagram profile information
python main.py instagram-scan username

# Scrape public Twitter profile information
python main.py twitter-scan username

# Search LinkedIn profiles
python main.py linkedin-search "security researcher"

# Search LinkedIn companies
python main.py linkedin-search "company name" --company

# Search Facebook profiles
python main.py facebook-search "person name"
```

#### Validation and Reputation Tools
```bash
# Verify email addresses
python main.py email-verify user@example.com

# Validate phone numbers
python main.py phone-validate +11234567890

# Check domain/IP reputation
python main.py domain-reputation example.com

# Get IP geolocation
python main.py ip-geolocate 8.8.8.8
```

#### OSINT Collection
```bash
# Basic OSINT collection
python main.py osint example.com

# With API keys for enhanced data
python main.py osint example.com --shodan-key YOUR_SHODAN_KEY --github-token YOUR_GITHUB_TOKEN
```

#### Full Reconnaissance Pipeline
```bash
# Complete automated reconnaissance
python main.py full-recon example.com

# Customized reconnaissance
python main.py full-recon example.com \
  --threads 100 \
  --max-subdomains 200 \
  --max-crawl-pages 500 \
  --no-vuln-scan

# Using configuration file
python main.py full-recon example.com --config recon_config.json
```

#### Data Analysis
```bash
# Analyze single scan result
python main.py analyze output/port_scan_example_com_*.json -o html

# Analyze multiple results
python main.py analyze output/port_scan_*.json output/dir_scan_*.json -o html
```

## 🔧 Configuration

### API Keys
For enhanced OSINT collection, configure API keys:

```bash
# Shodan API (for passive reconnaissance)
export SHODAN_API_KEY="your_shodan_api_key"

# GitHub Token (for code/repository searches)
export GITHUB_TOKEN="your_github_token"
```

### Configuration File Example
```json
{
  "threads": 100,
  "timeout": 10,
  "max_subdomains": 200,
  "max_crawl_pages": 500,
  "subdomain_enumeration": true,
  "port_scanning": true,
  "web_crawling": true,
  "vulnerability_scanning": true,
  "osint_collection": true,
  "api_keys": {
    "shodan": "your_shodan_api_key",
    "github": "your_github_token"
  }
}
```

## 📊 Output & Reporting

### Output Formats
- **JSON**: Machine-readable format for further processing
- **HTML**: Rich, interactive reports with charts and graphs
- **TXT**: Simple text format for quick review

### Output Structure
```
output/
├── port_scan_example_com_20240101_120000.json
├── subdomain_enum_example_com_20240101_120500.json
├── web_crawl_example_com_20240101_121000.json
├── vulnerability_scan_example_com_20240101_121500.json
├── osint_collection_example_com_20240101_122000.json
└── full_recon_example_com_20240101_122500.json
```

## 🛠️ Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `port-scan` | Basic port scanning | `python main.py port-scan example.com --common-ports` |
| `nmap-scan` | Advanced Nmap scanning | `python main.py nmap-scan example.com -t comprehensive` |
| `subdomain-enum` | Subdomain enumeration | `python main.py subdomain-enum example.com -m all` |
| `amass-scan` | Amass subdomain scanning | `python main.py amass-scan example.com -t comprehensive` |
| `gobuster-scan` | Directory and DNS busting | `python main.py gobuster-scan dir -t https://example.com -w list.txt` |
| `web-crawl` | Web application crawling | `python main.py web-crawl https://example.com -d 3` |
| `dir-scan` | Directory enumeration | `python main.py dir-scan https://example.com` |
| `vuln-scan` | Vulnerability scanning | `python main.py vuln-scan https://example.com` |
| `sql-injection` | SQL injection scanning | `python main.py sql-injection "http://test.com/search?id=1"` |
| `osint` | OSINT data collection | `python main.py osint example.com` |
| `hashcat-attack` | Password cracking | `python main.py hashcat-attack hashes.txt -m 0 -w list.txt` |
| `wifi-hack` | WiFi hacking | `python main.py wifi-hack` |
| `social-scan` | Social media finder | `python main.py social-scan johndoe` |
| `email-find` | Find email users | `python main.py email-find example.com` |
| `mobile-osint` | Phone number OSINT | `python main.py mobile-osint "+1234567890"` |
| `modem-scan` | Scan modem for vulns | `python main.py modem-scan 192.168.1.1` |
| `payload-gen` | Generate payload | `python main.py payload-gen reverse_shell --lhost 10.0.0.5` |
| `metasploit-run` | Run Metasploit module | `python main.py metasploit-run exploit/multi/handler` |
| `full-recon` | Complete reconnaissance | `python main.py full-recon example.com` |
| `analyze` | Data analysis | `python main.py analyze output/*.json -o html` |

## 🔍 Reconnaissance Methodology

The toolkit follows a structured reconnaissance methodology:

1. **Information Gathering**: OSINT collection and passive reconnaissance
2. **Subdomain Discovery**: Multi-method subdomain enumeration
3. **Port Scanning**: Service discovery and port analysis
4. **Web Application Analysis**: Crawling, directory enumeration, and endpoint discovery
5. **Vulnerability Assessment**: Automated testing for common vulnerabilities
6. **Data Analysis**: Comprehensive reporting and analysis

## 🚨 Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing and educational purposes only. 

- ✅ **Authorized Use**: Only use this tool on systems you own or have explicit written permission to test
- ✅ **Bug Bounty Programs**: Perfect for authorized bug bounty programs and responsible disclosure
- ✅ **Educational**: Great for learning about reconnaissance techniques and security testing
- ❌ **Unauthorized Use**: Never use this tool against systems without proper authorization

**Users are solely responsible for ensuring their use of this tool complies with all applicable laws and regulations.**

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OWASP Amass project for subdomain enumeration
- Nmap project for network scanning capabilities
- The bug bounty and security research community

---

**Happy Hunting! 🎯**
