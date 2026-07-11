#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] Checking C3PO Local dependencies...${NC}"

missing=0
for cmd in bash python3 ip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${RED}[!] Missing required command: $cmd${NC}" >&2
    missing=1
  fi
done

for cmd in nmap nuclei nxc arp arp-scan codex chromium chromium-browser google-chrome; do
  if command -v "$cmd" >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Optional tool found: $cmd${NC}"
  else
    echo -e "${YELLOW}[i] Optional tool missing: $cmd${NC}"
  fi
done

if command -v codex >/dev/null 2>&1; then
  echo "[i] Codex model discovery is available at runtime via: codex debug models"
else
  echo "[i] Codex model discovery unavailable; deterministic prioritization remains available"
fi

if [ "$missing" -ne 0 ]; then
  exit 1
fi

echo -e "${GREEN}[+] Dependency check complete. No API keys or Docker targets are required.${NC}"
