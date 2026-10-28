#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Verifying patched binary version..."
VERSION="$(docker exec acw3-target-patched httpd -v)"
echo "    $VERSION"

if ! grep -q 'Apache/2.4.69' <<<"$VERSION"; then
  echo "[-] ERROR: Patched target is not running Apache 2.4.69."
  exit 1
fi

echo "[*] Verifying patch-only configuration (One-time nonces)..."
if ! docker exec acw3-target-patched grep -q 'AuthDigestNonceLifetime 0' /usr/local/apache2/conf/lab-hardened.conf; then
  echo "[-] ERROR: Patched target does not have AuthDigestNonceLifetime 0 set."
  echo "    Cannot perform patch-only comparison."
  exit 1
fi

echo "[*] Running replay probe against patched target..."
BASE_URL="http://127.0.0.1:8081" \
EVIDENCE_DIR="../report/evidence" \
LABEL="digest-patched" \
EXPECT_POST_STATUS="401" \
bash "$SCRIPT_DIR/digest_replay_probe.sh"

echo "[+] FIX VERIFIED: Apache 2.4.69 successfully rejected the post-GC replay."
