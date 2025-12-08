#!/usr/bin/env bash
#RECON TOOl BY WSUITS^
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

# === Banner ===
cat <<'BANNER'
 _   _  _____  _____ _____ _____ _____ _______   __
| | | |/  ___||  _  /  __ \_   _|  ___|_   _\ \ / /
| |_| |\ `--. | | | | /  \/ | | | |__   | |  \ V / 
|  _  | `--. \| | | | |     | | |  __|  | |   \ /  
| | | |/\__/ /\ \_/ / \__/\_| |_| |___  | |   | |  
\_| |_/\____/  \___/ \____/\___/\____/  \_/   \_/  
                                                  

              HSociety Recon
BANNER

DOMAIN="$1"
TS="$(date +"%Y%m%d-%H%M%S")"
OUTDIR="recon_${DOMAIN}_${TS}"
mkdir -p "$OUTDIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "Recon started on $DOMAIN"
echo "Results will be saved in $OUTDIR/"

# WHOIS
log "Collecting WHOIS info..."
whois "$DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null || true

# DNS Records
log "Collecting DNS records..."
{
  echo "A records:"
  dig +short A "$DOMAIN"
  echo
  echo "AAAA records:"
  dig +short AAAA "$DOMAIN"
  echo
  echo "NS records:"
  dig +short NS "$DOMAIN"
  echo
  echo "MX records:"
  dig +short MX "$DOMAIN"
  echo
  echo "TXT records:"
  dig +short TXT "$DOMAIN"
} > "$OUTDIR/dns.txt"

# Subdomain Enumeration (assetfinder + amass if installed)
log "Enumerating subdomains..."
if command -v assetfinder >/dev/null 2>&1; then
  assetfinder --subs-only "$DOMAIN" > "$OUTDIR/subdomains_assetfinder.txt"
fi
if command -v amass >/dev/null 2>&1; then
  amass enum -passive -d "$DOMAIN" -o "$OUTDIR/subdomains_amass.txt"
fi
cat "$OUTDIR"/subdomains_* 2>/dev/null | sort -u > "$OUTDIR/subdomains_all.txt" || true

# Resolve discovered subdomains
log "Resolving live subdomains..."
if [[ -s "$OUTDIR/subdomains_all.txt" ]]; then
  cat "$OUTDIR/subdomains_all.txt" | xargs -n1 -I{} dig +short A {} \
    | sort -u > "$OUTDIR/resolved_ips.txt"
fi

# HTTP probing (httpx)
log "Probing for alive web services..."
if command -v httpx >/dev/null 2>&1; then
  httpx -l "$OUTDIR/subdomains_all.txt" -silent -status-code -title -tech-detect -o "$OUTDIR/httpx.txt"
fi

# Port Scanning (Nmap Top 1000)
log "Running Nmap top 1000 port scan..."
nmap -T3 -Pn --top-ports 1000 -sV -oA "$OUTDIR/nmap_top1k" "$DOMAIN"

# TLS Certificate Info
log "Fetching TLS cert info..."
echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates -ext subjectAltName > "$OUTDIR/tls.txt" || true

# Robots.txt + Headers
log "Fetching robots.txt and headers..."
for SCHEME in http https; do
  {
    echo "===== $SCHEME://$DOMAIN ====="
    curl -s -I "$SCHEME://$DOMAIN" || true
    echo
    echo "Robots:"
    curl -s "$SCHEME://$DOMAIN/robots.txt" | head -n 200 || true
  } > "$OUTDIR/${SCHEME}_headers.txt"
done

log "Recon completed. All data saved in $OUTDIR/"
