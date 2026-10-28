#!/usr/bin/env bash
set -euo pipefail

# Scenario 2 — full reset and rerun.
# Flags: --hard (full --no-cache rebuild)

HARD=0
for arg in "$@"; do
    case "$arg" in
        --hard) HARD=1 ;;
        -h|--help) printf 'Usage: %s [--hard]\n' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 64 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$LAB_DIR"

step() { printf '\n===== %s =====\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
fail() { printf '[-] %s\n' "$*" >&2; exit 1; }

step "1. Teardown"
docker compose --profile remediation down -v
docker ps --format '{{.Names}}' | grep -q '^acw3-' \
    && { echo "[-] acw3-* still running"; docker ps --format 'table {{.Names}}' | grep acw3-; exit 1; } \
    || ok "all containers removed"

if [ "$HARD" -eq 1 ]; then
    step "2. Purging cache"
    docker builder prune -af
    step "3. Full rebuild (--no-cache)"
    docker compose build --no-cache target
    docker compose --profile remediation build --no-cache target-patched
    docker compose build --no-cache backend
else
    step "2-3. Cached rebuild"
    docker compose build target
    docker compose --profile remediation build target-patched
    docker compose build backend
fi

step "4. Start containers"
docker compose up -d
docker compose --profile remediation up -d
sleep 3
docker exec acw3-target httpd -v | grep -q '2\.4\.68' \
    || fail "acw3-target not 2.4.68"
docker exec acw3-target-patched httpd -v | grep -q '2\.4\.69' \
    || fail "acw3-target-patched not 2.4.69"
ok "2.4.68 + 2.4.69 running"

step "5. Exploit"
./scripts/scenario2-exploit.sh

step "6. Remediation"
./scripts/scenario2-remediate.sh

step "7. Done"
ok "Reset complete. Evidence under report/evidence/scenario2/"
find ../report/evidence/scenario2 -type f | sort