#!/bin/bash

# WAFHUNTER Installation Script
# Professional Edition v3.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                                      ║"
echo "║                                                                                      ║"
echo "║       ██╗    ██╗ █████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗  ║"
echo "║       ██║    ██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗ ║"
echo "║       ██║ █╗ ██║███████║█████╗  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ║"   
echo "║       ██║███╗██║██╔══██║██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ║"
echo "║       ╚███╔███╔╝██║  ██║██║     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║ ║"
echo "║        ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ║"
echo "║                                                                                      ║"
echo "║  Advanced Web Application Firewall Detection Tool                                    ║"
echo "║  Version: 3.0 | Professional Edition                                                 ║"
echo "║  Author: MrpasswordTz | Country: Tanzania                                            ║"
echo "║                                                                                      ║"
echo "╚══════════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}[*] Starting WAFHUNTER Professional Edition Installation...${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}[!] Warning: Running as root. Consider using a non-root user for security.${NC}"
fi

# Check operating system
OS=""
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
else
    echo -e "${RED}[!] Unsupported operating system: $OSTYPE${NC}"
    exit 1
fi

echo -e "${BLUE}[*] Detected OS: $OS${NC}"

# Check Python version
echo -e "${BLUE}[*] Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
    
    # Check if version is 3.7+
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 7) else 1)'; then
        echo -e "${GREEN}[+] Python version is compatible${NC}"
    else
        echo -e "${RED}[!] Python 3.7+ is required. Current version: $PYTHON_VERSION${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Python 3 is not installed${NC}"
    echo -e "${YELLOW}[*] Please install Python 3.7+ and try again${NC}"
    exit 1
fi

# Check pip
echo -e "${BLUE}[*] Checking pip installation...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[+] pip3 found${NC}"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    echo -e "${GREEN}[+] pip found${NC}"
    PIP_CMD="pip"
else
    echo -e "${RED}[!] pip is not installed${NC}"
    echo -e "${YELLOW}[*] Installing pip...${NC}"
    if [[ "$OS" == "linux" ]]; then
        sudo apt-get update && sudo apt-get install -y python3-pip
    elif [[ "$OS" == "macos" ]]; then
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        python3 get-pip.py
        rm get-pip.py
    fi
    PIP_CMD="pip3"
fi

# Install system dependencies
echo -e "${BLUE}[*] Installing system dependencies...${NC}"
if [[ "$OS" == "linux" ]]; then
    sudo apt-get update
    sudo apt-get install -y curl wget git build-essential
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        brew install curl wget git
    else
        echo -e "${YELLOW}[!] Homebrew not found. Please install system dependencies manually.${NC}"
    fi
fi

# Create virtual environment (optional)
echo -e "${BLUE}[*] Setting up Python environment...${NC}"
if [[ "$1" == "--venv" ]]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    python3 -m venv wafhunter_env
    source wafhunter_env/bin/activate
    echo -e "${GREEN}[+] Virtual environment created and activated${NC}"
fi

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
$PIP_CMD install --upgrade pip
$PIP_CMD install -r requirements.txt

# Verify installation
echo -e "${BLUE}[*] Verifying installation...${NC}"
if python3 -c "import requests, colorama; print('Dependencies OK')" 2>/dev/null; then
    echo -e "${GREEN}[+] Dependencies installed successfully${NC}"
else
    echo -e "${RED}[!] Dependency verification failed${NC}"
    exit 1
fi

# Make scripts executable
echo -e "${BLUE}[*] Setting up executable permissions...${NC}"
chmod +x enhanced_wafhunter.py
chmod +x tests/test_wafhunter.py

# Create directories
echo -e "${BLUE}[*] Creating directories...${NC}"
mkdir -p logs
mkdir -p reports
mkdir -p config

# Test installation
echo -e "${BLUE}[*] Testing installation...${NC}"
if python3 enhanced_wafhunter.py --help &> /dev/null; then
    echo -e "${GREEN}[+] WAFHUNTER is working correctly${NC}"
else
    echo -e "${RED}[!] Installation test failed${NC}"
    exit 1
fi

# Installation complete
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║  🎉 WAFHUNTER Professional Edition Installation Complete! 🎉                ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BLUE}[*] Quick Start:${NC}"
echo -e "${YELLOW}  python3 enhanced_wafhunter.py example.com${NC}"
echo -e "${YELLOW}  python3 enhanced_wafhunter.py --help${NC}"

echo -e "${BLUE}[*] Examples:${NC}"
echo -e "${YELLOW}  # Basic scan${NC}"
echo -e "${YELLOW}  python3 enhanced_wafhunter.py target.com${NC}"
echo -e "${YELLOW}  ${NC}"
echo -e "${YELLOW}  # Stealth mode${NC}"
echo -e "${YELLOW}  python3 enhanced_wafhunter.py target.com --stealth${NC}"
echo -e "${YELLOW}  ${NC}"
echo -e "${YELLOW}  # Generate report${NC}"
echo -e "${YELLOW}  python3 enhanced_wafhunter.py target.com --report json --output report.json${NC}"

echo -e "${BLUE}[*] Documentation:${NC}"
echo -e "${YELLOW}  README_ENHANCED.md - Complete documentation${NC}"
echo -e "${YELLOW}  config.json - Configuration file${NC}"

echo -e "${BLUE}[*] Support:${NC}"
echo -e "${YELLOW}  GitHub: https://github.com/MrpasswordTz/WAFHUNTER${NC}"
echo -e "${YELLOW}  Issues: https://github.com/MrpasswordTz/WAFHUNTER/issues${NC}"

if [[ "$1" == "--venv" ]]; then
    echo -e "${YELLOW}[!] Remember to activate virtual environment:${NC}"
    echo -e "${YELLOW}  source wafhunter_env/bin/activate${NC}"
fi

echo -e "${GREEN}[*] Installation completed successfully!${NC}"