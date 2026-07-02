#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_PATH/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
  cat <<EOF
Usage: ./run.sh -i <interface> [options]

Local internal attack-surface scanner for authorized assessments.

Required:
  -i, --interface IFACE   Network interface to assess, for example eth0 or wlan0

Options:
  -v, --verbose           Print verbose scanner output
  --dry-run               Validate interface and scope, then render a scope report only
  -h, --help              Show this help

Examples:
  ./run.sh -i eth0
  ./run.sh -i wlan0
EOF
}

IFACE=""
VERBOSE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i|--interface)
      if [ -z "${2:-}" ]; then
        echo -e "${RED}[!] Missing value for $1${NC}" >&2
        usage
        exit 1
      fi
      IFACE="${2:-}"
      shift 2
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo -e "${RED}[!] Unknown argument: $1${NC}" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$IFACE" ]; then
  echo -e "${RED}[!] Missing required interface. Use: ./run.sh -i <interface>${NC}" >&2
  usage
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo -e "${RED}[!] Missing required command: python3${NC}" >&2
  exit 1
fi

echo -e "${GREEN}[+] Local Attack Surface Scanner${NC}"
echo -e "${GREEN}[+] Interface: ${IFACE}${NC}"

ARGS=(--interface "$IFACE")
if [ "$VERBOSE" = true ]; then
  ARGS+=(--verbose)
fi
if [ "$DRY_RUN" = true ]; then
  ARGS+=(--dry-run)
fi

cleanup() {
  echo
  echo -e "${YELLOW}[!] Interrupted. Partial artifacts may exist under reports/.${NC}" >&2
}
trap cleanup INT

python3 "$PROJECT_ROOT/pipeline/local_scanner.py" "${ARGS[@]}"
