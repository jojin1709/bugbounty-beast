# 🐉 BEAST MODE v3.0 — Full-Auto Bug Bounty Pipeline

> Give it a domain. Walk away. Come back to findings.

---

## ⚡ Quick Start

```bash
# 1. Install all tools (once, run as root)
chmod +x setup_beast.sh && sudo ./setup_beast.sh

# 2. Reload PATH
source ~/.bashrc

# 3. Run a scan
chmod +x bugbounty_beast.sh
./bugbounty_beast.sh target.com
```

---

## 🎯 Usage

```
./bugbounty_beast.sh <domain> [OPTIONS]
```

| Option | Description | Example |
|--------|-------------|---------|
| `--discord <url>` | Discord webhook alerts | `--discord https://discord.com/api/webhooks/...` |
| `--telegram <token> <chat_id>` | Telegram bot alerts | `--telegram 123:abc -123456789` |
| `--slack <url>` | Slack webhook alerts | `--slack https://hooks.slack.com/...` |
| `--cookie <string>` | Auth cookie for scan | `--cookie 'session=abc123; csrf=xyz'` |
| `--proxy <url>` | Route through proxy | `--proxy http://127.0.0.1:8080` |
| `--rate <int>` | Requests/sec limit | `--rate 30` |
| `--threads <int>` | Thread count | `--threads 100` |
| `--wordlist <path>` | Custom wordlist for fuzzing | `--wordlist /path/to/custom.txt` |
| `--scope <file>` | Extra in-scope domains | `--scope inscope.txt` |
| `--resume` | Resume interrupted scan | `--resume` |
| `--deep` | Deep scan (slower, thorough) | `--deep` |

### Examples

```bash
# Basic scan
./bugbounty_beast.sh hackerone.com

# Full featured
./bugbounty_beast.sh target.com \
  --discord https://discord.com/api/webhooks/xxx \
  --telegram 123456:TOKEN -987654321 \
  --slack https://hooks.slack.com/services/xxx \
  --cookie 'session=abc123' \
  --proxy http://127.0.0.1:8080 \
  --rate 30 --threads 100 --deep

# Authenticated scan
./bugbounty_beast.sh api.target.com --cookie 'Authorization=Bearer eyJ...'

# Resume after interruption
./bugbounty_beast.sh target.com --resume

# Multi-scope
echo -e "sub1.target.com\nsub2.target.com" > extra.txt
./bugbounty_beast.sh target.com --scope extra.txt
```

---

## 🔍 All 28 Phases

| # | Phase | What It Does | Key Tools |
|---|-------|-------------|-----------|
| 1 | Subdomain Enum | Passive + active sub discovery | subfinder, assetfinder, amass, crt.sh, OTX, alterx, puredns |
| 1.5 | DNS Recon | Zone transfer, SPF/DMARC, ASN, TLS SANs, WHOIS | dig, tlsx, asnmap |
| 2 | Live Host Probe | HTTP probe, tech detect, status codes | httpx |
| 2.5 | Security Headers | Checks 7 security headers, clickjacking, cookie flags | curl |
| 3 | Screenshots | Visual recon of all live hosts | gowitness |
| 4 | Port Scan | Top 1000 ports, service detection | naabu, nmap |
| 5 | URL Collection | Wayback, GAU, Common Crawl, URLScan | waybackurls, gau |
| 5.5 | Web Crawling | Deep recursive crawl with JS parsing | katana, gospider, hakrawler |
| 5.6 | Param Discovery | Hidden parameter discovery | arjun |
| 6 | Dir Fuzzing | Directory + API endpoint fuzzing | ffuf |
| 6.1 | 403 Bypass | 15+ bypass techniques (path + header) | curl |
| 6.5 | VHost Fuzzing | Virtual host discovery on same IP | ffuf |
| 7 | XSS Scan | Reflected + DOM XSS detection | dalfox, kxss |
| 7.5 | Open Redirect | URL param redirect testing | curl |
| 8 | SQL Injection | Error-based + time-based SQLi | sqlmap + manual |
| 8.5 | LFI | Path traversal, ffuf + manual payloads | ffuf, curl |
| 9 | SSRF | Cloud metadata + internal SSRF | curl |
| 9.1 | CORS | Origin reflection + credentials check | curl, corsy |
| 9.2 | SSTI | Template injection (7×7=49 canary) | curl |
| 9.3 | Host Header | Host + X-Forwarded-Host injection | curl |
| 9.4 | CRLF | CRLF injection header splitting | crlfuzz, curl |
| 9.5 | XXE | XML external entity injection | curl |
| 9.6 | Cmd Injection | OS command injection | commix, curl |
| 9.7 | HTTP Smuggling | CL.TE / TE.CL request smuggling | smuggler |
| 9.8 | Subdomain TKO | Dangling DNS + service takeover | subzy, nuclei |
| 9.9 | Cloud Enum | S3, GCS, Azure blob discovery | s3scanner, cloud_enum |
| 9.10 | GraphQL | Introspection, batching, IDE exposure | curl |
| 9.11 | WebSocket | WS endpoint detect + origin bypass | curl |
| 10 | Nuclei | 10,000+ templates (CVE, misconfig, etc.) | nuclei |
| 11 | JS Analysis | Secrets, endpoints, IPs, internal URLs | curl + grep |
| 12 | HTML Report | Full interactive report with all findings | bash |

---

## 📁 Output Structure

```
~/bugbounty/<target>/<timestamp>/
├── reports/
│   ├── report.html          ← OPEN THIS — full interactive report
│   └── all_findings.txt     ← quick grep-able findings
├── subs/
│   ├── all_subs.txt         ← all subdomains
│   └── resolved_subs.txt    ← DNS-resolved subs
├── live/
│   ├── live_urls.txt        ← httpx alive URLs (load into Burp)
│   ├── 403_bypass_candidates.txt
│   └── 401_auth_endpoints.txt
├── recon/
│   ├── all_urls_combined.txt
│   ├── interesting_endpoints.txt
│   └── dns/                 ← zone transfer, SPF, DMARC, WHOIS
├── vuln/
│   ├── nuclei_results.txt
│   └── nuclei_critical_high.txt
├── xss/                     ← XSS findings + DOM patterns
├── sqli/                    ← SQLi + sqlmap output
├── ssrf/                    ← SSRF confirmed
├── lfi/                     ← LFI confirmed
├── ssti/                    ← SSTI confirmed
├── cors/                    ← CORS issues
├── crlf/                    ← CRLF findings
├── cmdi/                    ← Command injection
├── xxe/                     ← XXE findings
├── smuggling/               ← HTTP smuggling
├── takeover/                ← Subdomain takeover
├── cloud/                   ← S3/GCS/Azure buckets
├── graphql/                 ← GraphQL introspection
├── websocket/               ← WebSocket endpoints
├── hostinject/              ← Host header injection
├── openredirect/            ← Open redirects
├── vhost/                   ← Virtual hosts
├── params/                  ← Discovered parameters
├── js/
│   ├── secrets_found.txt    ← API keys, tokens
│   ├── js_endpoints.txt     ← Hidden API endpoints
│   └── internal_urls.txt    ← Internal/staging URLs
├── headers/
│   ├── missing_headers.txt
│   └── clickjacking.txt
├── fuzzing/
│   ├── 403_bypassed.txt
│   └── ffuf_*.json
└── screenshots/             ← PNG screenshots
```

---

## 🛠️ Tools Installed by setup_beast.sh

### Go Tools
`subfinder` `httpx` `nuclei` `naabu` `katana` `dnsx` `interactsh-client` `tlsx` `asnmap` `cdncheck` `alterx` `puredns` `shuffledns` `hakrevdns` `assetfinder` `amass` `ffuf` `gau` `waybackurls` `hakrawler` `gospider` `anew` `unfurl` `qsreplace` `gf` `httprobe` `meg` `kxss` `dalfox` `crlfuzz` `gowitness` `subzy`

### Python Tools
`sqlmap` `uro` `arjun` `s3scanner` `shodan`

### Git Tools
`corsy` `smuggler` `cloud_enum` `commix` `paramspider` `ghauri` `graphw00f`

### System
`nmap` `dnsutils` `whois` `massdns` `chromium`

### Wordlists
`SecLists` (full) · DNS resolvers · LFI payloads · vhost list · API endpoints · SSTI payloads

---

## 🔔 Notifications

Alerts fire on: scan start, live hosts found, each phase complete, any critical/high finding (XSS, SQLi, SSRF, LFI, SSTI, takeover, CORS, etc.)

```bash
# Discord + Telegram + Slack simultaneously
./bugbounty_beast.sh target.com \
  --discord https://discord.com/api/webhooks/ID/TOKEN \
  --telegram BOT_TOKEN CHAT_ID \
  --slack https://hooks.slack.com/services/T.../B.../...
```

---

## 💡 Tips

- **First time?** Run `sudo ./setup_beast.sh` → `source ~/.bashrc` → scan
- **HackerOne/Bugcrowd?** Use `--rate 10 --threads 20` to stay under radar
- **Authenticated areas?** Grab your session cookie from browser DevTools → `--cookie`
- **Burp integration?** Use `--proxy http://127.0.0.1:8080` — all traffic goes through Burp
- **VPN/scope?** Use `--scope inscope.txt` with extra in-scope domains
- **Crash/disconnect?** Use `--resume` — skips completed phases
- **Slow network?** Use `--rate 5 --threads 10`
- **Full power?** Add `--deep` — deeper crawl, more nuclei templates, larger wordlists

---

## ⚠️ Legal

This tool is for **authorized bug bounty programs only**.  
Always verify you have permission before scanning any target.  
Never scan without explicit written authorization.

---

## 📊 Severity Reference

| Severity | Examples | Typical Bounty |
|----------|----------|---------------|
| 🔴 Critical | RCE, SQLi with data exfil, Account takeover | $5k–$50k |
| 🟠 High | SSRF to metadata, SSTI→RCE, Auth bypass | $1k–$10k |
| 🟡 Medium | Stored XSS, CORS+credentials, IDOR | $250–$2k |
| 🔵 Low | Reflected XSS, Open redirect, Info leak | $50–$500 |
| ⚪ Info | Missing headers, fingerprinting | $0–$100 |
