#!/usr/bin/env bash
# =============================================================================
# INF2005 ACW3 - CVE-2026-63686 (mod_xml2enc) FIX VERIFICATION
# -----------------------------------------------------------------------------
# Companion to lab/scripts/exploit-xml2enc.sh. That script fires the trigger
# (charset=gbk, body ending on a bare 0x81 incomplete GBK lead byte) against
# the VULNERABLE target (2.4.68) and proves the worker crash (AH00052).
#
# This script replays the EXACT SAME trigger against the REMEDIATED target
# (httpd 2.4.69 + lab-hardened.conf, the `target-patched` service) and proves
# the fix holds:
#   1. target-patched is actually running the patched version (2.4.69)
#   2. the config-level mitigation is in place (ProxyHTMLEnable Off)
#   3. the control request still succeeds (proxy path itself is healthy)
#   4. the trigger that crashed 2.4.68 produces NO crash here - no
#      segfault/AH00052 in the log, and the container's restart count /
#      master process start time is unchanged (i.e. nothing died and
#      nothing had to be respawned)
#   5. the target is still serving requests immediately afterward
#
# Usage:   ./verify-fix-xml2enc.sh
#          TARGET=http://127.0.0.1:8081 CONTAINER=acw3-target-patched \
#            EXPECT_VERSION=2.4.69 ./verify-fix-xml2enc.sh
#
# Run `make remediation` first (lab/Makefile) to bring target-patched up.
# =============================================================================
set -u

TARGET="${TARGET:-http://127.0.0.1:8081}"
CONTAINER="${CONTAINER:-acw3-target-patched}"
EXPECT_VERSION="${EXPECT_VERSION:-2.4.69}"
EVDIR="${EVDIR:-$(cd "$(dirname "$0")/../../report/evidence" && pwd)}"
mkdir -p "${EVDIR}"

pass=0; fail=0
ok()  { printf '  [ PASS ] %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  [ FAIL ] %s\n' "$1"; fail=$((fail+1)); }
hdr() { printf '\n== %s ==\n' "$1"; }

container_identity() {
    # "<restart count> <main-process start time>" for the container. The
    # event MPM recycles individual worker PIDs/threads continuously even
    # under normal benign load (verified separately - it is not a crash
    # signal), so comparing raw PIDs inside the container is unreliable.
    # What a crash-and-respawn actually changes is either the container's
    # restart count (if Docker restarted it) or, if only the httpd master
    # re-execed/forked a fresh master after its children died badly, the
    # master's own start time. Either changing means something restarted.
    docker inspect -f '{{.RestartCount}} {{.State.StartedAt}}' "${CONTAINER}" 2>/dev/null
}

# --- 1. Precondition: patched binary + hardened mitigation in place ----------
hdr "Precondition: target-patched running ${EXPECT_VERSION} with the hardened config"
# The hardened config sets `ServerTokens Prod` on purpose (don't leak the exact
# build in the HTTP banner), so the version can't be read off the wire here -
# ask the binary inside the container directly instead, which is authoritative.
binver=$(docker exec "${CONTAINER}" httpd -v 2>/dev/null | head -1)
echo "  ${binver:-<could not run httpd -v in ${CONTAINER}>}"
echo "${binver}" | grep -q "${EXPECT_VERSION}" \
    && ok "httpd binary reports ${EXPECT_VERSION} (patched release)" \
    || bad "httpd binary is not ${EXPECT_VERSION} (check 'make remediation' / build arg)"

lab_conf=$(docker exec "${CONTAINER}" printenv LAB_CONF 2>/dev/null); lab_conf="${lab_conf:-lab-hardened.conf}"
proxy_html_setting=$(docker exec "${CONTAINER}" sh -c "grep -i ProxyHTMLEnable /usr/local/apache2/conf/${lab_conf}")
echo "  ${lab_conf}: ${proxy_html_setting}"
echo "${proxy_html_setting}" | grep -qi 'Off' \
    && ok "config-level mitigation present (ProxyHTMLEnable Off in ${lab_conf})" \
    || bad "ProxyHTMLEnable is not Off - hardened mitigation not applied"

if [ "${fail}" -gt 0 ]; then
    echo; echo "Precondition not met - target-patched is not actually fixed. Aborting."
    exit 1
fi

# --- 2. Control: proxy path itself is still healthy --------------------------
hdr "Control: proxy still serves the backend (expect 200, filter path healthy)"
ctrl_code=$(curl -sS -m 5 -o "${EVDIR}/xml2enc-fix-control-body.html" \
            -D "${EVDIR}/xml2enc-fix-control-headers.txt" -w '%{http_code}' \
            "${TARGET}/proxy/scenario?charset=windows-1252&mode=benign")
[ "${ctrl_code}" = "200" ] && ok "control returned 200" || bad "control returned ${ctrl_code} (expected 200)"
grep -q 'ACW3 backend' "${EVDIR}/xml2enc-fix-control-body.html" \
    && ok "control body served through the proxy" \
    || bad "control body missing expected content"

if [ "${fail}" -gt 0 ]; then
    echo; echo "Control request failed - target-patched/backend not in a known-good state. Aborting."
    exit 1
fi

# --- 3. Replay the exact trigger that crashed 2.4.68 -------------------------
hdr "Replay trigger: charset=gbk, body ends on an incomplete GBK lead byte (0x81)"
identity_before=$(container_identity)
echo "  container identity before trigger: ${identity_before:-<could not inspect ${CONTAINER}>}"

docker compose logs "${CONTAINER#acw3-}" > /tmp/xml2enc_fix_pre_trigger.log 2>&1 || \
    docker logs "${CONTAINER}" > /tmp/xml2enc_fix_pre_trigger.log 2>&1
base_lines=$(wc -l < /tmp/xml2enc_fix_pre_trigger.log)

curl -v --max-time 10 "${TARGET}/proxy/scenario?charset=gbk&mode=incomplete-fail" \
    -o "${EVDIR}/xml2enc-fix-trigger-body.bin" 2> "${EVDIR}/xml2enc-fix-trigger-client.txt"
trigger_curl_exit=$?
echo "  client curl exit code: ${trigger_curl_exit}"
sleep 1

identity_after=$(container_identity)
echo "  container identity after trigger:  ${identity_after:-<could not inspect ${CONTAINER}>}"

# --- 4. Evidence: server-side log since the trigger ---------------------------
hdr "Evidence: server-side log since the trigger"
docker compose logs "${CONTAINER#acw3-}" 2>&1 | tail -n +$((base_lines+1)) > "${EVDIR}/xml2enc-fix-target.log" || \
    docker logs "${CONTAINER}" 2>&1 | tail -n +$((base_lines+1)) > "${EVDIR}/xml2enc-fix-target.log"
cat "${EVDIR}/xml2enc-fix-target.log"

crash=$(grep -Ec 'exit signal Segmentation fault|AH00052' "${EVDIR}/xml2enc-fix-target.log")
after_code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "${TARGET}/")

[ "${crash}" -eq 0 ] && ok "no segfault/AH00052 in the log (0 crash indicator lines)" \
                      || bad "${crash} crash indicator line(s) found - fix did NOT hold"

if [ -n "${identity_before}" ] && [ -n "${identity_after}" ]; then
    [ "${identity_before}" = "${identity_after}" ] \
        && ok "container restart count / master start time unchanged - nothing crashed/respawned" \
        || bad "container identity changed (${identity_before} -> ${identity_after}) - something restarted"
else
    bad "could not inspect ${CONTAINER} - treat the restart check as inconclusive"
fi

echo "  target reachable after replay: ${after_code}"
[ "${after_code}" = "200" ] && ok "target-patched still serving requests after the replay" \
                             || bad "target-patched not responding 200 after the replay (${after_code})"

# --- Verdict -------------------------------------------------------------------
hdr "Verdict"
if [ "${fail}" -eq 0 ]; then
    echo "  CVE-2026-63686 does NOT reproduce on target-patched (${EXPECT_VERSION},"
    echo "  ${lab_conf}). Primary remediation (upgrade) and the config-level"
    echo "  mitigation (ProxyHTMLEnable Off) are both confirmed in effect."
else
    echo "  Fix verification FAILED - see the [ FAIL ] lines above before"
    echo "  claiming remediation in the report."
fi

echo
printf '  %d passed, %d failed\n' "${pass}" "${fail}"
exit "${fail}"
