#!/usr/bin/env bash
# =============================================================================
# APISentinel — Kali Linux Setup Script
# Run: chmod +x setup.sh && ./setup.sh
# =============================================================================

set -e

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ___   ___  ____  __               __  _          _"
echo " / _ | / _ \/  _/ / /  ___ ___ ___/ /_(_)__  ___ (_)"
echo "/ __ |/ ___// /  / /__/ -_) _ \/ __/ __/ _ \/ -_) /"
echo "/_/ |_/_/  /___/ /____/\__/_//_/\__/\__/_//_/\__/_/"
echo -e "${NC}"
echo -e "${BOLD}APISentinel Setup — Kali Linux${NC}"
echo -e "${YELLOW}⚠  For authorized security testing only${NC}\n"

# ── Check root ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run with sudo: sudo ./setup.sh${NC}"
  exit 1
fi

# ── System update ─────────────────────────────────────────────────────────
echo -e "${CYAN}[1/6] Updating package lists...${NC}"
apt-get update -qq

# ── Node.js 20 ────────────────────────────────────────────────────────────
echo -e "${CYAN}[2/6] Checking Node.js...${NC}"
if ! command -v node &>/dev/null || [[ $(node -v | cut -d'v' -f2 | cut -d'.' -f1) -lt 18 ]]; then
  echo "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
else
  echo -e "${GREEN}Node.js $(node -v) already installed.${NC}"
fi

# ── Chromium for Puppeteer ────────────────────────────────────────────────
echo -e "${CYAN}[3/6] Checking Chromium (for Puppeteer mode)...${NC}"
if ! command -v chromium &>/dev/null && ! command -v chromium-browser &>/dev/null; then
  echo "Installing Chromium..."
  apt-get install -y chromium
else
  echo -e "${GREEN}Chromium already installed.${NC}"
fi

# Set Puppeteer env
CHROME_PATH=$(command -v chromium 2>/dev/null || command -v chromium-browser 2>/dev/null || echo "")
if [ -n "$CHROME_PATH" ]; then
  export PUPPETEER_EXECUTABLE_PATH="$CHROME_PATH"
  export PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

  # Persist to /etc/environment
  if ! grep -q "PUPPETEER_EXECUTABLE_PATH" /etc/environment 2>/dev/null; then
    echo "PUPPETEER_EXECUTABLE_PATH=${CHROME_PATH}" >> /etc/environment
    echo "PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true" >> /etc/environment
  fi
fi

# ── Additional dependencies ───────────────────────────────────────────────
echo -e "${CYAN}[4/6] Installing system dependencies...${NC}"
apt-get install -y -qq \
  libxss1 libxtst6 libnss3 libasound2 libatk-bridge2.0-0 \
  libgtk-3-0 libgbm-dev xvfb 2>/dev/null || true

# ── npm install ───────────────────────────────────────────────────────────
echo -e "${CYAN}[5/6] Installing Node.js dependencies...${NC}"
cd "$(dirname "$0")"
PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true npm install

# ── Desktop shortcut ──────────────────────────────────────────────────────
echo -e "${CYAN}[6/6] Creating desktop shortcut...${NC}"
INSTALL_DIR="$(pwd)"
DESKTOP_FILE="/usr/share/applications/api-sentinel.desktop"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=APISentinel
Comment=API Key Security Assessment Tool
Exec=bash -c 'cd ${INSTALL_DIR} && PUPPETEER_EXECUTABLE_PATH=${CHROME_PATH} npm start'
Icon=${INSTALL_DIR}/gui/icon.png
Terminal=false
Categories=Security;Network;
Keywords=security;pentest;api;keys;scanner;
EOF

chmod +x "$DESKTOP_FILE"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}✓ APISentinel installation complete!${NC}"
echo ""
echo -e "  Launch with:  ${CYAN}npm start${NC}"
echo -e "  Dev mode:     ${CYAN}npm run dev${NC}"
echo -e "  Build AppImg: ${CYAN}npm run build${NC}"
echo ""
echo -e "${YELLOW}⚠  Remember: Only test systems you have explicit authorization to scan.${NC}"
