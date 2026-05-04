#!/bin/bash
# ============================================================
#  BEAST SETUP — Install ALL tools for full auto bug bounty
#  Run in WSL: chmod +x setup_beast.sh && sudo ./setup_beast.sh
# ============================================================

set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
info() { echo -e "\n${CYAN}${BOLD}[+] $1${NC}"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════╗"
echo "║   BEAST SETUP — Bug Bounty Toolkit  ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# ── System deps ──────────────────────────────────────────────
info "System packages"
apt update -y
apt install -y curl wget git jq nmap python3 python3-pip unzip \
  libpcap-dev chromium-browser libgbm-dev 2>/dev/null || true
ok "System packages installed"

# ── Go ────────────────────────────────────────────────────────
info "Installing Go"
GO_VER="1.22.3"
if ! command -v go &>/dev/null; then
  wget -q "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
  tar -C /usr/local -xzf /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  echo 'export GOPATH=$HOME/go' >> ~/.bashrc
  export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
  export GOPATH=$HOME/go
  ok "Go $GO_VER installed"
else
  ok "Go already installed: $(go version)"
  export PATH=$PATH:$HOME/go/bin
  export GOPATH=$HOME/go
fi

# ── ProjectDiscovery suite ────────────────────────────────────
info "ProjectDiscovery tools"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && ok "subfinder"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null && ok "httpx"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && ok "nuclei"
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null && ok "naabu"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null && ok "katana"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null && ok "dnsx"
go install -v github.com/projectdiscovery/notify/cmd/notify@latest 2>/dev/null && ok "notify"

info "Nuclei templates"
nuclei -update-templates -silent 2>/dev/null && ok "Templates updated"

# ── Fuzzing ───────────────────────────────────────────────────
info "Fuzzing tools"
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && ok "ffuf"
go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null && ok "amass"

# ── URL collection ────────────────────────────────────────────
info "URL collection tools"
go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null && ok "gau"
go install github.com/tomnomnom/waybackurls@latest 2>/dev/null && ok "waybackurls"
go install github.com/tomnomnom/anew@latest 2>/dev/null && ok "anew"

# ── Tomnomnom suite ───────────────────────────────────────────
info "Tomnomnom tools"
go install github.com/tomnomnom/qsreplace@latest 2>/dev/null && ok "qsreplace"
go install github.com/tomnomnom/unfurl@latest 2>/dev/null && ok "unfurl"
go install github.com/tomnomnom/gf@latest 2>/dev/null && ok "gf"
go install github.com/tomnomnom/httprobe@latest 2>/dev/null && ok "httprobe"
go install github.com/tomnomnom/meg@latest 2>/dev/null && ok "meg"
go install github.com/tomnomnom/assetfinder@latest 2>/dev/null && ok "assetfinder"

# ── gf patterns ───────────────────────────────────────────────
info "gf patterns (param classification)"
mkdir -p ~/.gf
git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf-repo 2>/dev/null || true
cp /tmp/gf-repo/examples/*.json ~/.gf/ 2>/dev/null || true
git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp 2>/dev/null || true
cp /tmp/gfp/*.json ~/.gf/ 2>/dev/null || true
ok "gf patterns installed"

# ── Vulnerability scanners ────────────────────────────────────
info "Vulnerability scanners"
go install github.com/hahwul/dalfox/v2@latest 2>/dev/null && ok "dalfox (XSS)"
pip3 install sqlmap --quiet 2>/dev/null && ok "sqlmap"
pip3 install uro --quiet 2>/dev/null && ok "uro (URL dedup)"

# ── Screenshots ───────────────────────────────────────────────
info "Screenshot tools"
go install github.com/sensepost/gowitness@latest 2>/dev/null && ok "gowitness"

# ── SecLists wordlists ────────────────────────────────────────
info "SecLists wordlists"
if [[ ! -d /usr/share/seclists ]]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists
  ok "SecLists installed"
else
  ok "SecLists already present"
fi

# ── Create bugbounty dir ──────────────────────────────────────
mkdir -p ~/bugbounty
ok "~/bugbounty workspace created"

# ── Verify everything ─────────────────────────────────────────
info "Tool verification"
TOOLS=(subfinder httpx nuclei ffuf amass nmap dalfox gowitness sqlmap gau waybackurls)
ALL_OK=true
for t in "${TOOLS[@]}"; do
  if command -v "$t" &>/dev/null; then
    ok "$t ✓"
  else
    warn "$t — NOT FOUND (check PATH)"
    ALL_OK=false
  fi
done

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║         SETUP COMPLETE 🐉            ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Run this to activate Go paths:       "
echo -e "${GREEN}║${NC}   ${BOLD}source ~/.bashrc${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} Then start a hunt:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh example.com${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} With Discord alerts:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh target.com \\${NC}"
echo -e "${GREEN}║${NC}   ${BOLD}  --discord YOUR_WEBHOOK_URL${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} With Telegram alerts:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh target.com \\${NC}"
echo -e "${GREEN}║${NC}   ${BOLD}  --telegram BOT_TOKEN CHAT_ID${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════╝${NC}"
