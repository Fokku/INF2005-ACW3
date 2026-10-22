#!/bin/sh
# =============================================================================
# INF2005 ACW3 - target container entrypoint
# Provisions the lab fixtures (users, content, WebDAV collection) on first boot
# then starts httpd with the selected configuration (vulnerable by default).
# =============================================================================
set -eu

APACHE="/usr/local/apache2"
CONF="${LAB_CONF:-lab-vuln.conf}"

# --- Lab credentials (override via environment in docker-compose) ------------
DAV_USER="${DAV_USER:-davuser}"
DAV_PASS="${DAV_PASS:-LabPass123}"
DIGEST_USER="${DIGEST_USER:-digestuser}"
DIGEST_PASS="${DIGEST_PASS:-LabPass123}"
DIGEST_REALM="${DIGEST_REALM:-ACW3 Restricted}"

echo "[entrypoint] httpd ${HTTPD_VERSION:-?}  config=${CONF}"

# --- Directory layout --------------------------------------------------------
mkdir -p /var/www/webdav/files /var/www/webdav/.davlock /var/www/digest
printf 'WebDAV collection - authenticated write enabled for the lab.\n' \
    > /var/www/webdav/files/readme.txt
printf '<!doctype html><title>Restricted</title><h1>ACW3 restricted area</h1>\n' \
    > /var/www/digest/index.html
chown -R daemon:daemon /var/www/webdav /var/www/digest

# --- Landing page ------------------------------------------------------------
cat > "${APACHE}/htdocs/index.html" <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>ACW3 Apache Lab Target</title></head>
<body style="font-family:Calibri,Arial,sans-serif;max-width:40em;margin:3em auto">
<h1>INF2005 ACW3 - Apache lab target</h1>
<p>Deliberately vulnerable Apache httpd. Local lab use only.</p>
<ul>
  <li><a href="/webdav/">/webdav/</a> - mod_dav_fs (CVE-2026-93546)</li>
  <li><a href="/digest/">/digest/</a> - mod_auth_digest (CVE-2026-73636)</li>
  <li><a href="/proxy/">/proxy/</a> - mod_xml2enc via reverse proxy (CVE-2026-63686)</li>
</ul>
</body></html>
HTML

# --- Scenario 1 : WebDAV basic-auth user ------------------------------------
"${APACHE}/bin/htpasswd" -bc "${APACHE}/conf/webdav.passwd" "${DAV_USER}" "${DAV_PASS}" >/dev/null 2>&1

# --- Scenario 2 : digest user -----------------------------------------------
# htdigest is interactive, so write the file in its exact on-disk format:
#   user:realm:MD5(user:realm:password)
HA1=$(printf '%s:%s:%s' "${DIGEST_USER}" "${DIGEST_REALM}" "${DIGEST_PASS}" | md5sum | cut -d' ' -f1)
printf '%s:%s:%s\n' "${DIGEST_USER}" "${DIGEST_REALM}" "${HA1}" > "${APACHE}/conf/digest.passwd"

# --- Config sanity check -----------------------------------------------------
"${APACHE}/bin/httpd" -t -f "${APACHE}/conf/${CONF}" || {
    echo "[entrypoint] configuration test FAILED" >&2
    exit 1
}

echo "[entrypoint] starting: $* -f conf/${CONF}"
exec "${APACHE}/bin/httpd" -f "${APACHE}/conf/${CONF}" -D FOREGROUND
