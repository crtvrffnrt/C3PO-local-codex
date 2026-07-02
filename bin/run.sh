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
  -c, --cidr CIDR         Optional CIDR to narrow scope to a single routed subnet
  -v, --verbose           Print verbose scanner output
  --dry-run               Validate interface and scope, then render a scope report only
  --authorized            Acknowledge authorization non-interactively
  -h, --help              Show this help

Examples:
  ./run.sh -i eth0
  ./run.sh -i wlan0
  ./run.sh -i tun0 --cidr 172.16.16.0/24
EOF
}

IFACE=""
CIDR=""
VERBOSE=false
DRY_RUN=false
AUTHORIZED=false

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
    -c|--cidr)
      if [ -z "${2:-}" ]; then
        echo -e "${RED}[!] Missing value for $1${NC}" >&2
        usage
        exit 1
      fi
      CIDR="${2:-}"
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
    --authorized|--i-own-this-scope)
      AUTHORIZED=true
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
if [ -n "$CIDR" ]; then
  echo -e "${GREEN}[+] CIDR scope override: ${CIDR}${NC}"
fi

cat <<'EOF'

Authorization required
This tool performs active local-network discovery and safe enumeration only against scope
derived from the selected interface. Continue only if you own or are explicitly authorized
to assess this local network. The scanner will not run brute force, credential dumping,
exploit modules, destructive checks, or public internet scans.
EOF

if [ "$AUTHORIZED" != true ]; then
  read -r -p "Type I OWN THIS SCOPE to continue: " ACK
  if [ "$ACK" != "I OWN THIS SCOPE" ]; then
    echo -e "${RED}[!] Authorization acknowledgement not provided.${NC}" >&2
    exit 2
  fi
fi

CODEX_MODEL=""
CODEX_REASONING=""
if command -v codex >/dev/null 2>&1; then
  CODEX_HELP="$(codex exec --help 2>&1 || true)"
  if ! grep -q -- "--model" <<<"$CODEX_HELP"; then
    echo -e "${RED}[!] Installed Codex CLI does not support --model. Update Codex CLI or configure a default model.${NC}" >&2
    exit 2
  fi
  if ! grep -Eq -- "--reasoning|reasoning-effort|reasoning" <<<"$CODEX_HELP"; then
    echo -e "${YELLOW}[!] Codex CLI has no documented reasoning flag; reasoning profile will be recorded and included in prompts only.${NC}" >&2
  fi
  cat <<'EOF'

Choose Codex model/reasoning profile:
  1) GPT-5.5 High
  2) GPT-5.5 Medium
  3) GPT-5.5 Low
  4) GPT-5.4 Mini High
  5) GPT-5.4 Mini Medium
  6) GPT-5.4 Mini Low
EOF
  read -r -p "Selection [2]: " MODEL_CHOICE
  MODEL_CHOICE="${MODEL_CHOICE:-2}"
  case "$MODEL_CHOICE" in
    1) CODEX_MODEL="gpt-5.5"; CODEX_REASONING="high" ;;
    2) CODEX_MODEL="gpt-5.5"; CODEX_REASONING="medium" ;;
    3) CODEX_MODEL="gpt-5.5"; CODEX_REASONING="low" ;;
    4) CODEX_MODEL="gpt-5.4-mini"; CODEX_REASONING="high" ;;
    5) CODEX_MODEL="gpt-5.4-mini"; CODEX_REASONING="medium" ;;
    6) CODEX_MODEL="gpt-5.4-mini"; CODEX_REASONING="low" ;;
    *) echo -e "${RED}[!] Invalid model selection.${NC}" >&2; exit 2 ;;
  esac
else
  echo -e "${YELLOW}[!] Codex CLI not found; deterministic local prioritization will be used.${NC}" >&2
fi

ARGS=(--interface "$IFACE")
if [ -n "$CIDR" ]; then
  ARGS+=(--cidr "$CIDR")
fi
ARGS+=(--authorized)
if [ -n "$CODEX_MODEL" ]; then
  ARGS+=(--codex-model "$CODEX_MODEL" --codex-reasoning "$CODEX_REASONING")
fi
if [ "$VERBOSE" = true ]; then
  ARGS+=(--verbose)
fi
if [ "$DRY_RUN" = true ]; then
  ARGS+=(--dry-run)
fi

cleanup() {
  echo
  echo -e "${YELLOW}[!] Interrupted. Partial artifacts may exist under runs/.${NC}" >&2
}
trap cleanup INT

python3 "$PROJECT_ROOT/pipeline/local_scanner.py" "${ARGS[@]}"
