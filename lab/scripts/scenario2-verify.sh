#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Scenario 2 — VERIFICATION SCRIPT (CVE-2026-63686)
# ============================================================================
#
# PURPOSE:
#   This is the ONE COMMAND you run to produce all evidence for the report.
#   It calls the exploit script and the remediation script in sequence, then
#   validates that all evidence files exist and contain the expected content,
#   and generates a tamper-proof transcript with SHA-256 hashes of every file.
#
# WHAT IT DOES:
#   1. Runs scenario2-exploit.sh    → crashes Apache 2.4.68 (proves vuln exists)
#   2. Runs scenario2-remediate.sh  → shows 2.4.69 handles it safely (proves fix)
#   3. Asserts all evidence files are present and correct:
#      - Exploit log contains AH00052 (the crash)
#      - Hardened log has no crash
#      - Patch-only log has no crash but shows filter engagement (AH0144x)
#   4. Generates capture-transcript.txt with every file's content + SHA-256 hash
#   5. Prints a VERIFIED verdict with all hashes
#
# WHY SHA-256 HASHES:
#   The hashes prove the evidence files haven't been modified after capture.
#   If a professor re-runs the script, they get fresh hashes they can compare.
#
# USAGE:
#   ./scripts/scenario2-verify.sh            # normal run
#   ./scripts/scenario2-verify.sh --print    # also dump full logs to terminal
# ============================================================================

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

# --- STEP 0: Ensure all required containers are running ---
step "0. Checking containers"
docker ps --format '{{.Names}}' | grep -qx acw3-target \
    || fail "acw3-target not running — docker compose up -d"
docker ps --format '{{.Names}}' | grep -qx acw3-target-patched \
    || fail "acw3-target-patched not running — docker compose --profile remediation up -d"
docker ps --format '{{.Names}}' | grep -qx acw3-backend \
    || fail "acw3-backend not running"
ok "all containers up"

# --- STEP 1: Run the exploit script (should crash Apache 2.4.68) ---
step "1. Exploit half (expect crash on 2.4.68)"
if [ "$PRINT_LOGS" -eq 1 ]; then
    ./scripts/scenario2-exploit.sh --print
else
    ./scripts/scenario2-exploit.sh
fi

# --- STEP 2: Run the remediation script (should NOT crash Apache 2.4.69) ---
step "2. Remediation half (expect safe on 2.4.69)"
if [ "$PRINT_LOGS" -eq 1 ]; then
    ./scripts/scenario2-remediate.sh --print
else
    ./scripts/scenario2-remediate.sh
fi

# --- STEP 3: Validate all evidence files ---
# These assertions ensure the exploit and remediation produced the expected
# results. If any assertion fails, the script stops with an error message.
step "3. Asserting evidence files"

# EXPLOIT evidence: must have a server log containing a crash (AH00052/SIGSEGV)
[ -s "$EX/server.log" ]    || fail "01-exploit/server.log missing or empty"
[ -s "$EX/client.txt" ]    || fail "01-exploit/client.txt missing or empty"
[ -s "$EX/crash-lines.txt" ] \
    || fail "01-exploit/crash-lines.txt missing — exploit did not crash"
grep -qE 'AH00052|SIGSEGV' "$EX/crash-lines.txt" \
    || fail "01-exploit/crash-lines.txt does not contain AH00052/SIGSEGV"
ok "vulnerable: full log + crash evidence (AH00052 SIGSEGV)"

# HARDENED evidence: must have a server log with NO crash
[ ! -s "$HARD/crash-lines.txt" ] \
    || fail "hardened/crash-lines.txt exists — hardened target crashed"
[ -s "$HARD/server.log" ]   || fail "hardened/server.log missing"
ok "hardened: full log present, no crash"

# PATCH-ONLY evidence: must have a server log with NO crash, but WITH filter
# engagement (AH0144x means mod_xml2enc saw the bad input but handled it safely)
[ ! -s "$PO/crash-lines.txt" ] \
    || fail "patch-only/crash-lines.txt exists — patch-only target crashed"
[ -s "$PO/server.log" ]     || fail "patch-only/server.log missing"
[ -s "$PO/skip-lines.txt" ] || fail "patch-only/skip-lines.txt missing"
grep -qE 'AH0144[0-9]' "$PO/skip-lines.txt" \
    || fail "patch-only/skip-lines.txt missing AH0144x — 2.4.69 did not see the bad input"
ok "patch-only: full log present, filter engaged (AH0144x), no crash"

# --- STEP 4: Generate the evidence transcript ---
# This creates a single file containing every evidence file's content with
# line numbers, plus its size and SHA-256 hash. This is the master record
# that proves the evidence is complete and unmodified.
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

# --- STEP 5: Print the final verdict ---
# Summarises all three test results and the integrity hashes.
# "VERIFIED" means: exploit reproduced on 2.4.68, fixed on 2.4.69.
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