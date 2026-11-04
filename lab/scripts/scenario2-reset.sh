#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Scenario 2 — RESET SCRIPT (CVE-2026-63686)
# ============================================================================
#
# PURPOSE:
#   Tears down all containers, rebuilds everything from scratch, and reruns
#   the full exploit + remediation pipeline. Use this if something goes wrong
#   or you want a completely fresh run of the evidence capture.
#
# WHAT IT DOES:
#   1. Stops and removes all containers and volumes
#   2. Rebuilds all Docker images (use --hard for --no-cache full rebuild)
#   3. Starts all containers (target, backend, attacker, patched)
#   4. Runs scenario2-exploit.sh (crashes 2.4.68)
#   5. Runs scenario2-remediate.sh (proves 2.4.69 is safe)
#
# FLAGS:
#   --hard   full --no-cache rebuild (slower but guarantees clean images)
#
# USAGE:
#   ./scripts/scenario2-reset.sh          # cached rebuild + rerun
#   ./scripts/scenario2-reset.sh --hard   # full clean rebuild + rerun
# ============================================================================

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