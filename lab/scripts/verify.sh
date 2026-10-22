#!/usr/bin/env bash
# =============================================================================
# INF2005 ACW3 - verification harness
# -----------------------------------------------------------------------------
# Confirms the lab is built correctly and that each assessed vulnerability is
# PRESENT and REACHABLE before the team attempts exploitation. It does NOT
# exploit anything - it only proves the version, the loaded modules and the
# reachable surface for each scenario.
#
# Usage:   ./verify.sh            # checks the vulnerable target on :8080
#          TARGET=http://127.0.0.1:8081 ./verify.sh   # the patched target
# =============================================================================
set -u

TARGET="${TARGET:-http://127.0.0.1:8080}"
CONTAINER="${CONTAINER:-acw3-target}"
DAV_USER="${DAV_USER:-davuser}";       DAV_PASS="${DAV_PASS:-LabPass123}"
DIGEST_USER="${DIGEST_USER:-digestuser}"; DIGEST_PASS="${DIGEST_PASS:-LabPass123}"
EXPECT_VERSION="${EXPECT_VERSION:-2.4.68}"

pass=0; fail=0
ok()   { printf '  [ PASS ] %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  [ FAIL ] %s\n' "$1"; fail=$((fail+1)); }
hdr()  { printf '\n== %s ==\n' "$1"; }

# --- Reachability + version --------------------------------------------------
hdr "Target reachability & version banner"
banner=$(curl -s -m 5 -I "${TARGET}/" | tr -d '\r' | grep -i '^Server:')
echo "  ${banner:-<no Server header>}"
echo "${banner}" | grep -q "Apache" && ok "target responds and is Apache" \
                                      || bad "target not reachable at ${TARGET}"
echo "${banner}" | grep -q "${EXPECT_VERSION}" \
    && ok "version banner is ${EXPECT_VERSION}" \
    || bad "version banner is not ${EXPECT_VERSION} (check build arg)"

# --- Loaded modules (authoritative presence check) ---------------------------
hdr "Assessed modules loaded (httpd -M inside ${CONTAINER})"
mods=$(docker exec "${CONTAINER}" httpd -M 2>/dev/null)
if [ -z "${mods}" ]; then
    bad "could not run 'httpd -M' in ${CONTAINER} (is it running?)"
else
    for m in dav_module dav_fs_module auth_digest_module xml2enc_module proxy_html_module; do
        echo "${mods}" | grep -q "${m}" && ok "module ${m} loaded" \
                                        || bad "module ${m} NOT loaded"
    done
fi

# --- Scenario 1 : mod_dav_fs reachable (CVE-2026-93546) ----------------------
hdr "Scenario 1 - WebDAV reachable (CVE-2026-93546)"
davhdr=$(curl -s -m 5 -u "${DAV_USER}:${DAV_PASS}" -X OPTIONS "${TARGET}/webdav/" -D - -o /dev/null | tr -d '\r')
echo "${davhdr}" | grep -qi '^DAV:' && ok "OPTIONS advertises DAV capability" \
                                     || bad "no DAV header - WebDAV not active"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -u "${DAV_USER}:${DAV_PASS}" \
       -X PROPFIND -H 'Depth: 0' "${TARGET}/webdav/")
[ "${code}" = "207" ] && ok "authenticated PROPFIND returns 207 Multi-Status" \
                       || bad "PROPFIND returned ${code} (expected 207)"
unauth=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -X PROPFIND "${TARGET}/webdav/")
[ "${unauth}" = "401" ] && ok "unauthenticated access is gated (401)" \
                        || bad "unauthenticated PROPFIND returned ${unauth} (expected 401)"

# --- Scenario 2 : mod_auth_digest reachable (CVE-2026-73636) -----------------
hdr "Scenario 2 - Digest auth reachable (CVE-2026-73636)"
wa=$(curl -s -m 5 -I "${TARGET}/digest/" | tr -d '\r' | grep -i '^WWW-Authenticate:')
echo "  ${wa:-<none>}"
echo "${wa}" | grep -qi 'Digest' && ok "challenge is Digest (mod_auth_digest active)" \
                                  || bad "no Digest challenge"
echo "${wa}" | grep -qi 'nonce=' && ok "server issues a nonce" \
                                  || bad "no nonce in challenge"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' --digest \
       -u "${DIGEST_USER}:${DIGEST_PASS}" "${TARGET}/digest/")
[ "${code}" = "200" ] && ok "valid digest credentials authenticate (200)" \
                       || bad "digest auth returned ${code} (expected 200)"

# --- Scenario 3 : mod_xml2enc proxy path reachable (CVE-2026-63686) ----------
hdr "Scenario 3 - Proxy + xml2enc filter reachable (CVE-2026-63686)"
body=$(curl -s -m 5 "${TARGET}/proxy/")
echo "${body}" | grep -q "ACW3 backend" \
    && ok "reverse proxy serves the backend through the filter chain" \
    || bad "backend content not served via /proxy/ (proxy or backend down)"

# --- Summary -----------------------------------------------------------------
hdr "Summary"
printf '  %d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ] && echo "  Lab verified - ready for the exploitation phase." \
                     || echo "  One or more checks failed - see docs/02-verification-plan.md."
exit "${fail}"
