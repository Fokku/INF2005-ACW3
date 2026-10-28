#!/usr/bin/env bash
set -euo pipefail

# Scenario 2 (CVE-2026-63686) — VERIFY.
# Runs exploit + remediate, asserts evidence, writes capture-transcript.txt
# with every full log + sha256. This is the one command you run for the report.
#
# Usage: ./scripts/scenario2-verify.sh [--print]

PRINT_LOGS=0
for arg in "$@"; do
    case "$arg" in
        --print) PRINT_LOGS=1 ;;
        -h|--help) printf 'Usage: %s [--print]\n' "$0"; exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 64 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

S2="$LAB_DIR/../report/evidence/scenario2"
EX="$S2/01-exploit"
HARD="$S2/02-remediation/hardened"
PO="$S2/02-remediation/patch-only"
TRANSCRIPT="$S2/capture-transcript.txt"

cd "$LAB_DIR"

step() { printf '\n===== %s =====\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
fail() { printf '[-] %s\n' "$*" >&2; exit 1; }

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
siz() { wc -c < "$1" | tr -d ' '; }
lin() { wc -l < "$1" | tr -d ' '; }

step "0. Checking containers"
docker ps --format '{{.Names}}' | grep -qx acw3-target \
    || fail "acw3-target not running — docker compose up -d"
docker ps --format '{{.Names}}' | grep -qx acw3-target-patched \
    || fail "acw3-target-patched not running — docker compose --profile remediation up -d"
docker ps --format '{{.Names}}' | grep -qx acw3-backend \
    || fail "acw3-backend not running"
ok "all containers up"

step "1. Exploit half (expect crash on 2.4.68)"
if [ "$PRINT_LOGS" -eq 1 ]; then
    ./scripts/scenario2-exploit.sh --print
else
    ./scripts/scenario2-exploit.sh
fi

step "2. Remediation half (expect safe on 2.4.69)"
if [ "$PRINT_LOGS" -eq 1 ]; then
    ./scripts/scenario2-remediate.sh --print
else
    ./scripts/scenario2-remediate.sh
fi

step "3. Asserting evidence files"

[ -s "$EX/server.log" ]    || fail "01-exploit/server.log missing or empty"
[ -s "$EX/client.txt" ]    || fail "01-exploit/client.txt missing or empty"
[ -s "$EX/crash-lines.txt" ] \
    || fail "01-exploit/crash-lines.txt missing — exploit did not crash"
grep -qE 'AH00052|SIGSEGV' "$EX/crash-lines.txt" \
    || fail "01-exploit/crash-lines.txt does not contain AH00052/SIGSEGV"
ok "vulnerable: full log + crash evidence (AH00052 SIGSEGV)"

[ ! -s "$HARD/crash-lines.txt" ] \
    || fail "hardened/crash-lines.txt exists — hardened target crashed"
[ -s "$HARD/server.log" ]   || fail "hardened/server.log missing"
ok "hardened: full log present, no crash"

[ ! -s "$PO/crash-lines.txt" ] \
    || fail "patch-only/crash-lines.txt exists — patch-only target crashed"
[ -s "$PO/server.log" ]     || fail "patch-only/server.log missing"
[ -s "$PO/skip-lines.txt" ] || fail "patch-only/skip-lines.txt missing"
grep -qE 'AH0144[0-9]' "$PO/skip-lines.txt" \
    || fail "patch-only/skip-lines.txt missing AH0144x — 2.4.69 did not see the bad input"
ok "patch-only: full log present, filter engaged (AH0144x), no crash"

step "4. Capturing transcript with hashes"

FILES=(
    "$S2/00-identification/version.txt"
    "$S2/00-identification/modules.txt"
    "$S2/00-identification/config.txt"
    "$EX/trigger.txt"
    "$EX/status.txt"
    "$EX/client.txt"
    "$EX/server.log"
    "$EX/crash-lines.txt"
    "$HARD/server.log"
    "$HARD/skip-lines.txt"
    "$PO/server.log"
    "$PO/skip-lines.txt"
)

{
    printf 'Scenario 2 (CVE-2026-63686) — EVIDENCE TRANSCRIPT\n'
    printf 'Generated: %s\n' "$(date -u +%FT%TZ)"
    printf 'Machine:   %s\n\n' "$(uname -a)"
    printf 'Trigger:   %s\n' "$(sed -n 's#.*scenario?\(.*\)#\1#p' "$EX/trigger.txt" 2>/dev/null || echo unknown)"
    printf 'Control:   %s\n\n' "$(sed -n 's/^Control:  //p' "$EX/summary.txt" 2>/dev/null || echo unknown)"
    printf 'Result:\n'
    printf '  vulnerable (2.4.68, :8080):  CRASH   [AH00052 SIGSEGV]\n'
    printf '  hardened   (2.4.69, :8081):  SAFE    [ProxyHTMLEnable Off]\n'
    printf '  patch-only (2.4.69, :8081):  SAFE    [AH0144x, no crash]\n\n'
    printf '=================================================================\n\n'
    for f in "${FILES[@]}"; do
        printf '=== FILE: %s ===\n' "${f#$S2/}"
        if [ -f "$f" ]; then
            printf 'size:   %s bytes\n' "$(siz "$f")"
            printf 'lines:  %s\n' "$(lin "$f")"
            printf 'sha256: %s\n' "$(sha "$f")"
            printf -- '--- content (with line numbers) ---\n'
            cat -n "$f"
            printf -- '--- end ---\n\n'
        else
            printf '(missing)\n\n'
        fi
    done
    printf '=================================================================\n'
    printf 'END OF TRANSCRIPT\n'
} > "$TRANSCRIPT"

ok "Transcript: $TRANSCRIPT"
printf '    size:   %s bytes\n' "$(siz "$TRANSCRIPT")"
printf '    lines:  %s\n' "$(lin "$TRANSCRIPT")"
printf '    sha256: %s\n' "$(sha "$TRANSCRIPT")"

step "5. Verdict"
{
    printf 'Scenario 2 (CVE-2026-63686) — VERIFIED %s\n\n' "$(date -u +%FT%TZ)"
    printf 'Trigger:  %s\n\n' "$(sed -n 's#.*scenario?\(.*\)#\1#p' "$EX/trigger.txt" 2>/dev/null || echo unknown)"
    printf 'Results:\n'
    printf '  vulnerable (2.4.68, :8080):  CRASH   [AH00052 SIGSEGV]\n'
    printf '  hardened   (2.4.69, :8081):  SAFE    [ProxyHTMLEnable Off]\n'
    printf '  patch-only (2.4.69, :8081):  SAFE    [AH0144x, no crash]\n\n'
    printf 'Evidence integrity (full transcripts in capture-transcript.txt):\n'
    printf '  01-exploit/server.log        sha256=%s\n' "$(sha "$EX/server.log")"
    printf '  01-exploit/client.txt        sha256=%s\n' "$(sha "$EX/client.txt")"
    printf '  02-remediation/hardened/server.log    sha256=%s\n' "$(sha "$HARD/server.log")"
    printf '  02-remediation/patch-only/server.log  sha256=%s\n' "$(sha "$PO/server.log")"
    printf '  capture-transcript.txt       sha256=%s\n\n' "$(sha "$TRANSCRIPT")"
    printf 'Reproduce:\n  cat 01-exploit/trigger.txt\n'
} | tee "$S2/VERIFIED.txt"

printf '\n[+] All three tests passed. Evidence at report/evidence/scenario2/\n'
printf '    Full transcript: capture-transcript.txt\n'
printf '    Hash: %s\n' "$(sha "$TRANSCRIPT")"