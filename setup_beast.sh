#!/bin/bash
# ============================================================
#  BEAST SETUP v3.0 — Full Bug Bounty Toolkit Installer
#  Tested on: Kali Linux, Ubuntu 22+, Debian
#  Run: chmod +x setup_beast.sh && sudo ./setup_beast.sh
# ============================================================

set -uo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; }
info() { echo -e "\n${CYAN}${BOLD}[+] $1${NC}"; }
warn() { echo -e "  ${YELLOW}!${NC}  $1"; }

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║   BEAST SETUP v3.0 — Full Bug Bounty Toolkit ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

INSTALL_LOG="/tmp/beast_install.log"
> "$INSTALL_LOG"

try_install() {
  local name="$1"; shift
  "$@" >> "$INSTALL_LOG" 2>&1 && ok "$name" || fail "$name (see $INSTALL_LOG)"
}

# ── Detect user ───────────────────────────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
export GOPATH="$REAL_HOME/go"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"

# ── System packages ───────────────────────────────────────────
info "System packages"
apt-get update -y >> "$INSTALL_LOG" 2>&1
apt-get install -y \
  curl wget git jq nmap python3 python3-pip unzip zip \
  libpcap-dev chromium-browser libgbm-dev dnsutils \
  massdns dnsrecon whois netcat-openbsd make gcc \
  libssl-dev libffi-dev python3-dev ruby ruby-dev \
  >> "$INSTALL_LOG" 2>&1 && ok "System packages" || warn "Some packages failed — continuing"

# ── Go ────────────────────────────────────────────────────────
info "Go language runtime"
GO_VER="1.22.3"
if ! command -v go &>/dev/null; then
  ARCH=$(uname -m); [[ "$ARCH" == "aarch64" ]] && GOARCH="arm64" || GOARCH="amd64"
  wget -q "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz >> "$INSTALL_LOG" 2>&1
  tar -C /usr/local -xzf /tmp/go.tar.gz >> "$INSTALL_LOG" 2>&1
  echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> "$REAL_HOME/.bashrc"
  echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> "$REAL_HOME/.zshrc" 2>/dev/null || true
  echo "export GOPATH=\$HOME/go" >> "$REAL_HOME/.bashrc"
  ok "Go $GO_VER installed"
else
  ok "Go already present: $(go version 2>/dev/null | awk '{print $3}')"
fi

export PATH="$PATH:/usr/local/go/bin:$REAL_HOME/go/bin"
export GOPATH="$REAL_HOME/go"
mkdir -p "$GOPATH"

go_install() {
  local name="$1"; local pkg="$2"
  GOPATH="$REAL_HOME/go" go install "$pkg" >> "$INSTALL_LOG" 2>&1 && ok "$name" || fail "$name"
}

# ── ProjectDiscovery suite ────────────────────────────────────
info "ProjectDiscovery tools"
go_install "subfinder"          "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install "httpx"              "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install "nuclei"             "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
go_install "naabu"              "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
go_install "katana"             "github.com/projectdiscovery/katana/cmd/katana@latest"
go_install "dnsx"               "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
go_install "interactsh-client"  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
go_install "tlsx"               "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
go_install "asnmap"             "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
go_install "cdncheck"           "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
go_install "alterx"             "github.com/projectdiscovery/alterx/cmd/alterx@latest"

info "Nuclei templates"
"$REAL_HOME/go/bin/nuclei" -update-templates -silent >> "$INSTALL_LOG" 2>&1 && ok "Templates updated" || warn "Template update failed"

# ── DNS & Recon ───────────────────────────────────────────────
info "DNS & Recon tools"
go_install "puredns"       "github.com/d3mondev/puredns/v2@latest"
go_install "shuffledns"    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
go_install "hakrevdns"     "github.com/hakluke/hakrevdns@latest"
go_install "assetfinder"   "github.com/tomnomnom/assetfinder@latest"
go_install "amass"         "github.com/owasp-amass/amass/v4/...@master"

# ── Fuzzing & Discovery ───────────────────────────────────────
info "Fuzzing & Discovery tools"
go_install "ffuf"         "github.com/ffuf/ffuf/v2@latest"
go_install "feroxbuster"  "github.com/epi052/feroxbuster@latest" 2>/dev/null || warn "feroxbuster — try: cargo install feroxbuster"

# ── URL collection & crawling ─────────────────────────────────
info "URL collection & crawlers"
go_install "gau"          "github.com/lc/gau/v2/cmd/gau@latest"
go_install "waybackurls"  "github.com/tomnomnom/waybackurls@latest"
go_install "hakrawler"    "github.com/hakluke/hakrawler@latest"
go_install "gospider"     "github.com/jaeles-project/gospider@latest"
go_install "anew"         "github.com/tomnomnom/anew@latest"
go_install "unfurl"       "github.com/tomnomnom/unfurl@latest"
go_install "qsreplace"    "github.com/tomnomnom/qsreplace@latest"
go_install "gf"           "github.com/tomnomnom/gf@latest"
go_install "httprobe"     "github.com/tomnomnom/httprobe@latest"
go_install "meg"          "github.com/tomnomnom/meg@latest"
go_install "kxss"         "github.com/Emoe/kxss@latest"

# ── Injection scanners ────────────────────────────────────────
info "Injection & vuln scanners"
go_install "dalfox"   "github.com/hahwul/dalfox/v2@latest"
go_install "crlfuzz"  "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"

# ── Screenshots ───────────────────────────────────────────────
info "Screenshot tools"
go_install "gowitness"  "github.com/sensepost/gowitness@latest"

# ── Subdomain takeover ────────────────────────────────────────
info "Subdomain takeover"
go_install "subzy"  "github.com/LukaSikic/subzy@latest"

# ── Python tools ─────────────────────────────────────────────
info "Python tools"
pip3_install() {
  local name="$1"; local pkg="$2"
  pip3 install "$pkg" -q >> "$INSTALL_LOG" 2>&1 && ok "$name" || fail "$name"
}
pip3_install "sqlmap"     "sqlmap"
pip3_install "uro"        "uro"
pip3_install "arjun"      "arjun"
pip3_install "s3scanner"  "s3scanner"
pip3_install "requests"   "requests"
pip3_install "colorama"   "colorama"
pip3_install "shodan"     "shodan"

# ── Git-based tools ───────────────────────────────────────────
info "Git-based tools"

git_tool() {
  local name="$1"; local repo="$2"; local dest="$3"; local extra="$4"
  if [[ ! -d "$dest" ]]; then
    git clone --depth 1 "$repo" "$dest" >> "$INSTALL_LOG" 2>&1 || { fail "$name clone"; return; }
    if [[ -n "$extra" ]]; then
      cd "$dest" && eval "$extra" >> "$INSTALL_LOG" 2>&1
      cd - > /dev/null
    fi
    ok "$name"
  else
    ok "$name (already installed — $dest)"
  fi
}

git_tool "Corsy (CORS)"     "https://github.com/s0md3v/Corsy"      "/opt/corsy"    "pip3 install -r requirements.txt -q"
git_tool "smuggler (HTTP)"  "https://github.com/defparam/smuggler"  "/opt/smuggler" "pip3 install -r requirements.txt -q 2>/dev/null || true"
git_tool "cloud_enum"       "https://github.com/initstring/cloud_enum" "/opt/cloud_enum" "pip3 install -r requirements.txt -q"
git_tool "commix"           "https://github.com/commixproject/commix" "/opt/commix"  ""
git_tool "ParamSpider"      "https://github.com/devanshbatham/paramspider" "/opt/paramspider" "pip3 install -q . 2>/dev/null || true"
git_tool "ghauri"           "https://github.com/r0oth3x49/ghauri"   "/opt/ghauri"   "pip3 install -r requirements/common.txt -q 2>/dev/null || true"
git_tool "GraphW00f"        "https://github.com/dolevf/graphw00f"    "/opt/graphw00f" "pip3 install -r requirements.txt -q 2>/dev/null || true"

# Create symlinks for git tools
for pair in "commix:/opt/commix/commix.py" "paramspider:/opt/paramspider/paramspider/main.py" "graphw00f:/opt/graphw00f/main.py"; do
  name="${pair%%:*}"; path="${pair##*:}"
  [[ -f "$path" ]] && ln -sf "$path" "/usr/local/bin/$name" && chmod +x "$path" || true
done

# ── gf patterns ───────────────────────────────────────────────
info "gf patterns"
mkdir -p "$REAL_HOME/.gf"
git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf-repo >> "$INSTALL_LOG" 2>&1 || true
cp /tmp/gf-repo/examples/*.json "$REAL_HOME/.gf/" 2>/dev/null || true
git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp >> "$INSTALL_LOG" 2>&1 || true
cp /tmp/gfp/*.json "$REAL_HOME/.gf/" 2>/dev/null || true
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/.gf/" 2>/dev/null || true
ok "gf patterns installed → $REAL_HOME/.gf/"

# ── Wordlists ─────────────────────────────────────────────────
info "Wordlists & resolvers"
mkdir -p /opt/wordlists

# SecLists
if [[ ! -d /usr/share/seclists ]]; then
  git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists >> "$INSTALL_LOG" 2>&1 && ok "SecLists" || fail "SecLists"
else
  ok "SecLists (already present)"
fi

# DNS resolvers (critical for puredns)
curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
  -o /opt/wordlists/resolvers.txt 2>/dev/null && ok "DNS resolvers" || fail "DNS resolvers"

# DNS brute wordlists
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
  -o /opt/wordlists/dns_small.txt 2>/dev/null && ok "DNS wordlist (small)" || fail "DNS wordlist (small)"
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" \
  -o /opt/wordlists/dns_medium.txt 2>/dev/null && ok "DNS wordlist (medium)" || fail "DNS wordlist (medium)"

# vhost wordlist
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt" \
  -o /opt/wordlists/vhosts.txt 2>/dev/null && ok "vhost wordlist" || fail "vhost wordlist"

# API-specific wordlists
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" \
  -o /opt/wordlists/api_endpoints.txt 2>/dev/null && ok "API wordlist" || fail "API wordlist"

# LFI wordlist
curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" \
  -o /opt/wordlists/lfi.txt 2>/dev/null && ok "LFI wordlist" || fail "LFI wordlist"

# SSTI wordlist
cat > /opt/wordlists/ssti_payloads.txt << 'EOF'
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
{{7*'7'}}
${{"freemarker.template.utility.Execute"?new()("id")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
EOF
ok "SSTI payloads"

# CORS origins for testing
cat > /opt/wordlists/cors_origins.txt << 'EOF'
https://evil.com
null
https://attacker.com
EOF
ok "CORS test origins"

# ── Workspace ─────────────────────────────────────────────────
info "Workspace"
mkdir -p "$REAL_HOME/bugbounty"
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/bugbounty" 2>/dev/null || true
ok "~/bugbounty workspace ready"

# ── Fix permissions ───────────────────────────────────────────
chown -R "$REAL_USER:$REAL_USER" "$REAL_HOME/go" 2>/dev/null || true

# ── Verification ──────────────────────────────────────────────
info "Tool verification"

TOOLS_REQUIRED=(
  subfinder httpx nuclei ffuf nmap dalfox gowitness
  sqlmap gau waybackurls dnsx katana
  hakrawler gospider arjun subzy crlfuzz
  puredns interactsh-client kxss
)

PASS=0; FAIL=0
for t in "${TOOLS_REQUIRED[@]}"; do
  if command -v "$t" &>/dev/null || [[ -f "$REAL_HOME/go/bin/$t" ]]; then
    ok "$t"; ((PASS++))
  else
    fail "$t — NOT FOUND"; ((FAIL++))
  fi
done

echo ""
echo -e "${CYAN}${BOLD}Tool check: ${GREEN}$PASS OK${NC} / ${RED}$FAIL missing${NC}"
[[ $FAIL -gt 0 ]] && echo -e "  ${YELLOW}Run: source ~/.bashrc  then re-verify with 'which subfinder'${NC}"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║         BEAST SETUP COMPLETE 🐉              ║${NC}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC} Activate paths:  ${BOLD}source ~/.bashrc${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} Basic scan:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh example.com${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} Authenticated scan:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh example.com --cookie 'session=abc'${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} With all notifications:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh example.com \\${NC}"
echo -e "${GREEN}║${NC}   ${BOLD}  --discord WEBHOOK --telegram TOKEN ID \\${NC}"
echo -e "${GREEN}║${NC}   ${BOLD}  --slack WEBHOOK${NC}"
echo -e "${GREEN}║${NC}"
echo -e "${GREEN}║${NC} Resume interrupted scan:"
echo -e "${GREEN}║${NC}   ${BOLD}./bugbounty_beast.sh example.com --resume${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Install log: ${YELLOW}$INSTALL_LOG${NC}"
