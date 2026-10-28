#!/usr/bin/env bash
set -euo pipefail

# Scenario 2 patch-only verification: Apache 2.4.69 with ProxyHTMLEnable On.
# Demonstrates the binary fix, not the hardened config.
# Usage (from lab/): ./scripts/verify_xml2enc_fix.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONF=/usr/local/apache2/conf/lab-hardened.conf
cd "$LAB_DIR"

fail() { echo "[-] ERROR: $*" >&2; exit 1; }

echo "[*] Verifying patched binary version..."
if ! VERSION="$(docker exec acw3-target-patched httpd -v 2>/dev/null)"; then
  fail "acw3-target-patched is not running. Start it with:
    docker compose --profile remediation up -d --build target-patched"
fi
echo "    $VERSION"

grep -q 'Apache/2.4.69' <<<"$VERSION" \
  || fail "patched target is not Apache 2.4.69"

echo "[*] Enabling ProxyHTML in the patched container (patch-only test)..."
docker compose exec -T target-patched sed -i \
  's/ProxyHTMLEnable  Off/ProxyHTMLEnable  On/' "$CONF" \
  || fail "could not edit $CONF"

docker compose exec -T target-patched grep -q 'ProxyHTMLEnable  On' "$CONF" \
  || fail "ProxyHTMLEnable  On not present after edit — check whitespace in $CONF"

restore_hardened() {
  set +e
  echo "[*] Restoring hardened ProxyHTMLEnable Off"
  docker compose exec -T target-patched sed -i \
    's/ProxyHTMLEnable  On/ProxyHTMLEnable  Off/' "$CONF"
  docker compose restart target-patched >/dev/null 2>&1 || true
}
trap restore_hardened EXIT

docker compose restart target-patched >/dev/null

echo "[*] Running trigger probe against patched target..."
BASE_URL="http://127.0.0.1:8081" \
EVIDENCE_DIR="../report/evidence" \
LABEL="xml2enc-patch-only" \
EXPECT_RESULT="safe" \
APPLY_BACKEND_PATCH="1" \
RESTORE_BACKEND_ON_EXIT="0" \
SKIP_BACKEND_BUILD="1" \
bash "$SCRIPT_DIR/xml2enc_trigger_probe.sh"

echo "[+] FIX VERIFIED: Apache 2.4.69 handled the conversion failure without crashing."