
# 🐉 BugBounty Beast — Full Auto Pipeline

Full automated bug bounty recon + vuln scanner for Kali Linux.

## Setup
```bash
git clone https://github.com/jojin1709/bugbounty-beast
cd bugbounty-beast
chmod +x setup_kali.sh bugbounty_beast.sh
sudo ./setup_kali.sh
source ~/.zshrc
```

## Run
```bash
./bugbounty_beast.sh target.com
./bugbounty_beast.sh target.com --discord WEBHOOK_URL
./bugbounty_beast.sh target.com --telegram BOT_TOKEN CHAT_ID
```

## Phases
1. Subdomain enum (subfinder + amass + crt.sh)
2. Live host probe (httpx)
3. Screenshots (gowitness)
4. Port scan (nmap)
5. URL collection (wayback + gau)
6. Dir fuzzing + 403 bypass (ffuf)
7. XSS scan (dalfox)
8. SQLi scan (sqlmap)
9. SSRF detection
10. Nuclei vuln scan
11. JS secret hunting
12. HTML report

## Legal
Only use on targets you have permission to test.
RDME
