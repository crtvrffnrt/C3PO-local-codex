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
  --codex-model MODEL     Codex model slug; overrides interactive selection
  --codex-reasoning EFFORT
                          Reasoning effort supported by the selected Codex model
  --no-codex              Use deterministic prioritization only
  --no-model-prompt       Do not prompt for a model when running interactively
  -h, --help              Show this help

Examples:
  ./run.sh -i eth0
  ./run.sh -i wlan0
  ./run.sh -i tun0 --cidr 10.20.30.0/24
EOF
}

IFACE=""
CIDR=""
VERBOSE=false
DRY_RUN=false
AUTHORIZED=false
CODEX_MODEL="${CODEX_MODEL:-}"
CODEX_REASONING="${CODEX_REASONING:-}"
NO_CODEX=false
NO_MODEL_PROMPT=false

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
    --codex-model)
      CODEX_MODEL="${2:-}"; shift 2 ;;
    --codex-reasoning)
      CODEX_REASONING="${2:-}"; shift 2 ;;
    --no-codex)
      NO_CODEX=true; shift ;;
    --no-model-prompt)
      NO_MODEL_PROMPT=true; shift ;;
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

SELECTION_JSON='{"enabled":false}'
if [ "$NO_CODEX" = true ]; then
  SELECTION_JSON='{"enabled":false,"reason":"intentionally disabled"}'
elif [ -n "$CODEX_MODEL" ] || [ -n "$CODEX_REASONING" ]; then
  SELECTION_JSON="$(python3 "$PROJECT_ROOT/pipeline/codex_catalog.py" --model "$CODEX_MODEL" --reasoning "$CODEX_REASONING")" || exit $?
elif [ -t 0 ] && [ "$NO_MODEL_PROMPT" = false ]; then
  SELECTION_JSON="$(python3 "$PROJECT_ROOT/pipeline/codex_catalog.py" --interactive)" || exit $?
else
  echo -e "${YELLOW}[!] No Codex selection supplied in noninteractive mode; deterministic prioritization will be used.${NC}" >&2
fi
if [ "$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("enabled", False))' <<<"$SELECTION_JSON")" = true ]; then
  CODEX_MODEL="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("model", ""))' <<<"$SELECTION_JSON")"
  CODEX_REASONING="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("reasoning", ""))' <<<"$SELECTION_JSON")"
  CODEX_MODEL_DISPLAY="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("model_display_name", ""))' <<<"$SELECTION_JSON")"
fi
CODEX_CATALOG_LOADED="$(python3 -c 'import json,sys; v=json.load(sys.stdin).get("catalog_loaded"); print("" if v is None else str(v).lower())' <<<"$SELECTION_JSON")"
CODEX_CATALOG_ERROR="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("catalog_error", ""))' <<<"$SELECTION_JSON")"

ARGS=(--interface "$IFACE")
if [ -n "$CIDR" ]; then
  ARGS+=(--cidr "$CIDR")
fi
ARGS+=(--authorized)
if [ -n "$CODEX_MODEL" ]; then
  ARGS+=(--codex-model "$CODEX_MODEL" --codex-reasoning "$CODEX_REASONING")
  [ -n "${CODEX_MODEL_DISPLAY:-}" ] && ARGS+=(--codex-model-display "$CODEX_MODEL_DISPLAY")
fi
if [ -n "$CODEX_CATALOG_LOADED" ]; then ARGS+=(--codex-catalog-loaded "$CODEX_CATALOG_LOADED"); fi
if [ -n "$CODEX_CATALOG_ERROR" ]; then ARGS+=(--codex-catalog-error "$CODEX_CATALOG_ERROR"); fi
if [ "$NO_CODEX" = true ]; then ARGS+=(--no-codex); fi
if [ "$NO_MODEL_PROMPT" = true ]; then ARGS+=(--no-model-prompt); fi
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
