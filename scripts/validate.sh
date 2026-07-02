#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for file in \
  "$PROJECT_ROOT/run.sh" \
  "$PROJECT_ROOT/bin/run.sh" \
  "$PROJECT_ROOT/pipeline/local_scanner.py" \
  "$PROJECT_ROOT/tools/nxc_phase.py" \
  "$PROJECT_ROOT/README.md" \
  "$PROJECT_ROOT/docs/architecture.md"; do
  if [ ! -f "$file" ]; then
    echo "[!] Missing required file: $file" >&2
    exit 1
  fi
done

for cmd in bash python3 ip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[!] Missing required command: $cmd" >&2
    exit 1
  fi
done

for cmd in nmap nuclei nxc codex arp arp-scan chromium chromium-browser google-chrome; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[*] Optional command not found: $cmd" >&2
  fi
done

python3 -m py_compile "$PROJECT_ROOT/pipeline/local_scanner.py" "$PROJECT_ROOT/tools/nxc_phase.py"

echo "[*] Validation successful."
