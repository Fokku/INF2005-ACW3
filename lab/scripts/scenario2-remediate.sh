#!/usr/bin/env bash
set -euo pipefail

# Scenario 2 (CVE-2026-63686) — REMEDIATION HALF.
# Hardened + patch-only comparisons against Apache 2.4.69.
# Reads trigger from report/evidence/scenario2/01-exploit/trigger.txt.
#
# Flags: --rebuild | --print
# Env:   TRIGGER

DO_REBUILD=0; PRINT_LOGS=0
for arg in "$@"; do
    case "$arg" in
        --rebuild) DO_REBUILD=1 ;;
        --print)   PRINT_LOGS=1 ;;
        -h|--help) printf 'Usage: %s [--rebuild] [--print]\n' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 64 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

S2="$LAB_DIR/../report/evidence/scenario2"
EX="$S2/01-exploit"
RM="$S2/02-remediation"
HARD="$RM/hardened"
PO="$RM/patch-only"

mkdir -p "$HARD" "$PO"
cd "$LAB_DIR"

step() { printf '\n===== %s =====\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
fail() { printf '[-] %s\n' "$*" >&2; exit 1; }

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
siz() { wc -c < "$1" | tr -d ' '; }
lin() { wc -l < "$1" | tr -d ' '; }

CRASH_RE='AH00051|AH00052|Segmentation fault|SIGSEGV|child pid [0-9]+ exit'

if [ -n "${TRIGGER:-}" ]; then
    TRIGGER_QS="$TRIGGER"
    ok "trigger from env"
elif [ -f "$EX/trigger.txt" ]; then
    TRIGGER_QS=$(sed -n 's#.*scenario?\(.*\)#\1#p' "$EX/trigger.txt")
    [ -n "$TRIGGER_QS" ] || fail "cannot parse $EX/trigger.txt"
    ok "trigger from 01-exploit/trigger.txt"
else
    TRIGGER_QS="charset=big5&mode=bad-body&byte=0xa4&pos=end&size=0"
    warn "no trigger file — using known-good default"
fi
CONTROL_QS="charset=$(echo "$TRIGGER_QS" | sed -n 's/.*charset=\([^&]*\).*/\1/p')&mode=benign"

step "1. Prerequisites"
docker info >/dev/null 2>&1 || fail "Docker not running"
docker ps --format '{{.Names}}' | grep -qx acw3-target-patched \
    || fail "acw3-target-patched not running — docker compose --profile remediation up -d"
ok "patched target up"

if [ "$DO_REBUILD" -eq 1 ]; then
    step "2. Rebuilding target-patched (--no-cache)"
    docker compose --profile remediation build --no-cache target-patched
    docker compose --profile remediation up -d target-patched
    ok "rebuilt"
else
    step "2. Skipping rebuild (pass --rebuild to force)"
fi

step "3. Verify patched target"
docker exec acw3-target-patched httpd -v | grep -q 'Apache/2\.4\.69' \
    || fail "acw3-target-patched is not 2.4.69"
ok "version: 2.4.69"

if docker exec acw3-target-patched grep -q 'ProxyHTMLEnable  On' \
       /usr/local/apache2/conf/lab-hardened.conf 2>/dev/null; then
    docker exec acw3-target-patched sed -i \
        's/ProxyHTMLEnable  On/ProxyHTMLEnable  Off/' \
        /usr/local/apache2/conf/lab-hardened.conf
    docker restart acw3-target-patched >/dev/null; sleep 3
fi
ok "hardened config Off"

run_final() {
    local dir="$1"
    curl -sS -o "$dir/body.bin" --max-time 10 -w '%{http_code}\n' \
        "http://127.0.0.1:8081/proxy/scenario?${TRIGGER_QS}" \
        > "$dir/status.txt" 2> "$dir/client.txt" || true
    curl -sS -o "$dir/control-body.html" --max-time 10 -w 'control_status=%{http_code}\n' \
        "http://127.0.0.1:8081/proxy/scenario?${CONTROL_QS}" \
        >> "$dir/status.txt" 2>/dev/null || true
    sleep 3
    docker logs --since 10m acw3-target-patched > "$dir/server.log" 2>&1
    if grep -Eq "$CRASH_RE" "$dir/server.log"; then
        grep -E "$CRASH_RE" "$dir/server.log" > "$dir/crash-lines.txt"
        echo "crash"
    else
        grep -E 'AH0144[0-9]|AH01431|xml2enc' "$dir/server.log" > "$dir/skip-lines.txt" 2>/dev/null || true
        echo "safe"
    fi
}

step "4. Hardened (ProxyHTMLEnable Off)"
R=$(run_final "$HARD")
[ "$R" = "safe" ] || fail "hardened: unexpected crash"
ok "hardened: SAFE"
printf '    server.log  %s bytes, %s lines, sha256 %s\n' \
    "$(siz "$HARD/server.log")" "$(lin "$HARD/server.log")" "$(sha "$HARD/server.log")"

if [ "$PRINT_LOGS" -eq 1 ]; then
    step "Full hardened server log"
    cat -n "$HARD/server.log"
fi

step "5. Patch-only (ProxyHTMLEnable On)"
docker exec acw3-target-patched sed -i \
    's/ProxyHTMLEnable  Off/ProxyHTMLEnable  On/' \
    /usr/local/apache2/conf/lab-hardened.conf
docker restart acw3-target-patched >/dev/null
n=0; until curl -fsS "http://127.0.0.1:8081/proxy/" >/dev/null 2>&1; do
    n=$((n+1)); [ "$n" -gt 30 ] && fail "not ready"; sleep 1
done

R=$(run_final "$PO")

docker exec acw3-target-patched sed -i \
    's/ProxyHTMLEnable  On/ProxyHTMLEnable  Off/' \
    /usr/local/apache2/conf/lab-hardened.conf
docker restart acw3-target-patched >/dev/null 2>&1 || true

[ "$R" = "safe" ] || fail "patch-only: unexpected crash"
ok "patch-only: SAFE"
printf '    server.log  %s bytes, %s lines, sha256 %s\n' \
    "$(siz "$PO/server.log")" "$(lin "$PO/server.log")" "$(sha "$PO/server.log")"
printf '\n    Filter engaged, no crash (from 02-remediation/patch-only/server.log):\n'
grep -E 'AH0144[0-9]' "$PO/server.log" | head -2 | sed 's/^/    /' || true

if [ "$PRINT_LOGS" -eq 1 ]; then
    step "Full patch-only server log — every line as captured to disk"
    cat -n "$PO/server.log"
    printf '\n(sha256 of above: %s)\n' "$(sha "$PO/server.log")"
fi

{
    printf 'Scenario 2 (CVE-2026-63686) — REMEDIATION run %s\n\n' "$(date -u +%FT%TZ)"
    printf 'Target:   Apache 2.4.69 (acw3-target-patched, :8081)\n'
    printf 'Trigger:  %s\n' "$TRIGGER_QS"
    printf 'Control:  %s\n\n' "$CONTROL_QS"
    printf 'Results:\n'
    printf '  hardened   (ProxyHTMLEnable Off):  SAFE\n'
    printf '  patch-only (ProxyHTMLEnable On):   SAFE\n\n'
    printf 'Evidence integrity:\n'
    printf '  hardened/server.log    %s bytes  %s lines  sha256=%s\n' "$(siz "$HARD/server.log")" "$(lin "$HARD/server.log")" "$(sha "$HARD/server.log")"
    printf '  patch-only/server.log  %s bytes  %s lines  sha256=%s\n' "$(siz "$PO/server.log")" "$(lin "$PO/server.log")" "$(sha "$PO/server.log")"
    printf '  patch-only/skip-lines.txt  sha256=%s\n\n' "$(sha "$PO/skip-lines.txt")"
    printf 'Key files:\n'
    printf '  02-remediation/hardened/server.log    FULL unedited log\n'
    printf '  02-remediation/patch-only/server.log  FULL unedited log\n'
    printf '  02-remediation/patch-only/skip-lines.txt  AH0144x (no AH00052)\n'
} > "$RM/summary.txt"

step "6. Summary"
cat "$RM/summary.txt"
printf '\n[+] Remediation complete.\n'