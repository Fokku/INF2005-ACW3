#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_PATH="/usr/local/apache2/conf/lab-hardened.conf"

echo "[*] Verifying patched binary version..."
VERSION="$(docker exec acw3-target-patched httpd -v)"
echo "    $VERSION"

if ! grep -q 'Apache/2.4.69' <<<"$VERSION"; then
  echo "[-] ERROR: Patched target is not running Apache 2.4.69."
  exit 1
fi

echo "[*] Backing up current configuration and applying patch-only test config..."
docker exec acw3-target-patched cp "$CONF_PATH" /tmp/hardened.bak
# Change to warn + auth_digest:info to ensure GC logs are captured, and set lifetime to 0
docker exec acw3-target-patched sed -i 's/^LogLevel.*/LogLevel warn auth_digest:info/' "$CONF_PATH"
docker exec acw3-target-patched sed -i 's/AuthDigestNonceLifetime 300/AuthDigestNonceLifetime 0/' "$CONF_PATH"

docker restart acw3-target-patched > /dev/null
sleep 2

echo "[*] Running replay probe against patched target..."
set +e
BASE_URL="http://127.0.0.1:8081" \
SERVICE_NAME="target-patched" \
EVIDENCE_DIR="../report/evidence" \
LABEL="digest-patched" \
EXPECT_POST_STATUS="401" \
bash "$SCRIPT_DIR/digest_replay_probe.sh"
PROBE_EXIT=$?
set -e

echo "[*] Restoring original hardened configuration..."
docker exec acw3-target-patched cp /tmp/hardened.bak "$CONF_PATH"
docker restart acw3-target-patched > /dev/null

if [ $PROBE_EXIT -ne 0 ]; then
    echo "[-] ERROR: The verification failed. Check the evidence logs above."
    exit 1
fi

echo "[+] FIX VERIFIED: Apache 2.4.69 successfully rejected the post-GC replay."
