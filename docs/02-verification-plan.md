# 02 · Verification Plan

Goal: **before** anyone attempts exploitation, prove that the lab is built
correctly and that each vulnerability is *present* (the vulnerable module/version
is loaded) and *reachable* (the attacker box can hit the surface). This de-risks
the demo — a failed verification step here is far cheaper to fix than a failed
exploit in front of the instructor.

Run everything from the host, or from the Kali box
(`docker compose exec attacker bash`, then use `http://172.28.0.10/` instead of
`http://127.0.0.1:8080/`).

## 0. One-command check

```bash
cd lab && ./scripts/verify.sh        # or: make verify
```

`verify.sh` runs every check below and prints a PASS/FAIL line for each, exiting
non-zero if anything fails. The manual steps that follow show what each check
does and the expected output, so you can diagnose a failure and so each team
member understands the surface they will demo.

---

## 1. Reachability and version

```bash
curl -sI http://127.0.0.1:8080/ | grep -i '^server'
# Expected:  Server: Apache/2.4.68 (Unix)
docker exec acw3-target httpd -v
# Expected:  Server version: Apache/2.4.68 (Unix)
```

**Why it matters:** all three CVEs are version-bounded to ≤ 2.4.68. Confirming
2.4.68 is the single most important precondition. (The patched target reports
2.4.69.)

## 2. Assessed modules are loaded

```bash
docker exec acw3-target httpd -M 2>/dev/null | grep -E 'dav_module|dav_fs_module|auth_digest_module|xml2enc_module|proxy_html_module'
```
Expected: all five appear (`dav_module`, `dav_fs_module`, `auth_digest_module`,
`xml2enc_module`, `proxy_html_module`). This is the authoritative "present"
check — the vulnerable code is only in the binary if its module is loaded.

---

## 3. Scenario 1 — `mod_dav_fs` reachable (CVE-2026-93546)

```bash
# DAV capability is advertised
curl -s -u davuser:LabPass123 -X OPTIONS http://127.0.0.1:8080/webdav/ -D - -o /dev/null | grep -i '^DAV:'
# Expected:  DAV: 1,2,3   (or at least 1,2)

# Authenticated PROPFIND works (write-capable collection)
curl -s -o /dev/null -w '%{http_code}\n' -u davuser:LabPass123 \
     -X PROPFIND -H 'Depth: 0' http://127.0.0.1:8080/webdav/
# Expected:  207   (Multi-Status)

# Unauthenticated access is gated (the vuln needs an authenticated writer)
curl -s -o /dev/null -w '%{http_code}\n' -X PROPFIND http://127.0.0.1:8080/webdav/
# Expected:  401
```

From Kali you can also browse the collection interactively:
`cadaver http://172.28.0.10/webdav/` (login `davuser` / `LabPass123`).

**Present & reachable when:** DAV header present, authenticated PROPFIND = 207,
PROPPATCH is therefore available to the authenticated user — that PROPPATCH path
is the surface for the integer-overflow exploitation phase.

---

## 4. Scenario 2 — `mod_auth_digest` reachable (CVE-2026-73636)

```bash
# The challenge must be Digest (not Basic) and must carry a nonce
curl -sI http://127.0.0.1:8080/digest/ | grep -i '^WWW-Authenticate:'
# Expected:  WWW-Authenticate: Digest realm="ACW3 Restricted", nonce="...", ...

# Valid digest credentials authenticate
curl -s -o /dev/null -w '%{http_code}\n' --digest -u digestuser:LabPass123 \
     http://127.0.0.1:8080/digest/
# Expected:  200
```

**Present & reachable when:** the challenge is `Digest` with a `nonce`, valid
credentials return 200, and the config shows `AuthDigestNonceLifetime 0` (the
vulnerable one-time-nonce setting):

```bash
docker exec acw3-target grep -n AuthDigestNonceLifetime /usr/local/apache2/conf/lab-vuln.conf
# Expected:  AuthDigestNonceLifetime 0
```

---

## 5. Scenario 3 — proxy + `mod_xml2enc` reachable (CVE-2026-63686)

```bash
# Backend is up (internal) and reachable through the proxy
curl -s http://127.0.0.1:8080/proxy/ | grep -i 'ACW3 backend'
# Expected:  the backend's HTML, served through the proxy filter chain

# The xml2enc filter engages on charset handling; vary the declared charset:
curl -s 'http://127.0.0.1:8080/proxy/scenario?charset=utf-8' -D - -o /dev/null | grep -i '^content-type'
```

Confirm the filter chain is actually in place (not just a plain proxy):

```bash
docker exec acw3-target httpd -M | grep -E 'proxy_html|xml2enc'
# Expected:  proxy_html_module, xml2enc_module
docker exec acw3-target grep -n 'ProxyHTMLEnable' /usr/local/apache2/conf/lab-vuln.conf
# Expected:  ProxyHTMLEnable On
```

**Present & reachable when:** `/proxy/` returns backend content, both modules are
loaded, and `ProxyHTMLEnable On` is set — so backend responses pass through
`mod_xml2enc`'s charset transcoding, which is the DoS surface.

---

## 6. Verification checklist (sign off before exploitation)

| Check | Pass criteria | Owner |
|-------|---------------|-------|
| Build & start | `docker compose ps` shows target, backend, attacker up | |
| Version | banner + `httpd -v` = 2.4.68 | |
| Modules | all 5 assessed modules in `httpd -M` | |
| WebDAV | DAV header; PROPFIND 207 auth / 401 unauth | |
| Digest | Digest challenge + nonce; 200 with creds; lifetime 0 | |
| Proxy/xml2enc | `/proxy/` serves backend; both modules loaded; `ProxyHTMLEnable On` | |
| `verify.sh` | exits 0 (all PASS) | |

When every row passes, capture a screenshot of `verify.sh` output for the report
appendix and proceed to the exploitation phase (doc 03).
