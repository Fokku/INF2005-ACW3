# 04 · Remediation Research

Written up for the report's defence section. For each CVE: the root cause, the
**primary remediation** (the patched release), and **config-level mitigations**
(defence-in-depth / interim controls where an immediate upgrade is not possible).
All three are fixed by the same upgrade.

> **Primary remediation for all three: upgrade Apache HTTP Server to 2.4.69.**
> Every one of the three CVEs affects httpd 2.4.0–2.4.68 and is fixed in 2.4.69
> (released 2026-10-01). The `target-patched` service (`lab-hardened.conf` on a
> 2.4.69 build) demonstrates this. Distributions back-port fixes to their own
> package versions, so on a managed host apply the vendor's patched build and
> check the vendor advisory rather than relying on the upstream version string.

---

## CVE-2026-93546 — `mod_dav_fs` integer overflow (CVSS 8.8, CWE-190)

**Root cause.** An integer overflow in `mod_dav_fs` when handling WebDAV
`PROPPATCH` requests that declare an excessive number of XML namespaces. An
authenticated WebDAV client with write access can crash worker processes and
permanently damage the directory's property database. The NVD 8.8 vector rates
all three impacts High (`C:H/I:H/A:H`); the directly demonstrable effect is the
worker crash and property-DB corruption (integrity + availability).

**Primary remediation.** Upgrade to httpd 2.4.69.

**Config-level mitigation / defence-in-depth.**
- Disable `mod_dav_fs` (and `mod_dav`) entirely if WebDAV is not required —
  comment out the `LoadModule` lines. This removes the surface outright.
- Restrict *who* can write: require authentication and limit write methods to
  trusted users; do not expose WebDAV write to anonymous clients.
- Cap XML request bodies with `LimitXMLRequestBody` (and `LimitRequestBody`) so
  an oversized PROPPATCH body cannot be submitted (see `lab-hardened.conf`).
- Optionally restrict/deny the `PROPPATCH` method on the collection with a
  `<Limit PROPPATCH>` + `Require` block when property edits are not needed.

**Residual risk after mitigation only (no patch).** Low-privilege authenticated
writers remain a risk until patched; the body-size cap narrows but does not
formally eliminate the flaw. Patching is required to close it.

---

## CVE-2026-73636 — `mod_auth_digest` one-time-nonce replay (CVSS 8.1, CWE-294)

**Root cause.** Authentication bypass by capture-replay. When
`AuthDigestNonceLifetime` is set to `0` (intended to make each nonce single-use),
affected builds mishandle nonce validation so a captured nonce can be replayed to
authenticate, defeating the one-time-nonce guarantee.

**Primary remediation.** Upgrade to httpd 2.4.69.

**Config-level mitigation / defence-in-depth.**
- Do **not** set `AuthDigestNonceLifetime 0`; use a small positive lifetime
  (e.g. `300`) so nonce handling follows the normal, unaffected path.
- Serve Digest-protected areas over **TLS only**, so an attacker cannot capture
  the `Authorization` header off the wire to replay it in the first place.
- Prefer a stronger authentication scheme than HTTP Digest where feasible
  (e.g. form login over TLS with server-side sessions, or token auth); Digest is
  legacy and brittle.

**Residual risk after mitigation only (no patch).** A positive lifetime + TLS
greatly reduces exploitability (no cleartext capture, normal nonce path), but the
underlying code defect is only removed by the patch.

---

## CVE-2026-63686 — `mod_xml2enc` charset-conversion NULL deref (CVSS 7.5, CWE-476)

**Root cause.** A NULL-pointer dereference in `mod_xml2enc`'s charset conversion.
When httpd reverse-proxies an untrusted backend through the
`mod_proxy_html`/`mod_xml2enc` filter chain, a proxied response whose declared
charset conversion partially succeeds then fails triggers the dereference,
crashing the worker (denial of service).

**Primary remediation.** Upgrade to httpd 2.4.69.

**Config-level mitigation / defence-in-depth.**
- Only reverse-proxy **backends you control / trust**; never run the HTML
  filter chain over arbitrary upstream content.
- If HTML rewriting / charset transcoding is not needed, set
  `ProxyHTMLEnable Off` (or unload `mod_proxy_html`/`mod_xml2enc`) so the
  vulnerable filter never engages (see `lab-hardened.conf`). Note disabling
  `mod_xml2enc` breaks modules that depend on it, such as `mod_proxy_html`.
- Constrain/normalise upstream `Content-Type` charset where a proxy sits in front
  of semi-trusted content.

**Residual risk after mitigation only (no patch).** Restricting to trusted
backends removes the practical attacker, and disabling the filter removes the
surface; both are effective interim controls, but patching is the durable fix.

---

## Verification of remediation

Demonstrate the fix by replaying each trigger against the patched target:

```bash
cd lab
make remediation        # builds & starts httpd 2.4.69 on :8081 with lab-hardened.conf
make verify-patched     # confirms 2.4.69 and the hardened surface
```

For the report, show the before/after: the same input that crashes/bypasses
2.4.68 is handled safely by 2.4.69, and the hardened directives
(`lab-vuln.conf` vs `lab-hardened.conf`) are an auditable diff.

---

## Sources (official records first)

**CVE records & advisories**
- CVE-2026-93546 — cve.org: <https://www.cve.org/CVERecord?id=CVE-2026-93546> ·
  oss-security: <https://www.openwall.com/lists/oss-security/2026/10/01/30> ·
  OpenCVE: <https://app.opencve.io/cve/CVE-2026-93546> ·
  Red Hat: <https://access.redhat.com/security/cve/cve-2026-93546> ·
  Debian: <https://security-tracker.debian.org/tracker/CVE-2026-93546> ·
  SUSE: <https://www.suse.com/security/cve/CVE-2026-93546.html>
- CVE-2026-73636 — cve.org: <https://www.cve.org/CVERecord?id=CVE-2026-73636> ·
  oss-security: <https://www.openwall.com/lists/oss-security/2026/10/01/27> ·
  OpenCVE: <https://app.opencve.io/cve/CVE-2026-73636> ·
  Ubuntu: <https://ubuntu.com/security/CVE-2026-73636> ·
  Debian: <https://security-tracker.debian.org/tracker/CVE-2026-73636>
- CVE-2026-63686 — cve.org: <https://www.cve.org/CVERecord?id=CVE-2026-63686> ·
  oss-security: <https://www.openwall.com/lists/oss-security/2026/10/01/25> ·
  OpenCVE: <https://app.opencve.io/cve/CVE-2026-63686> ·
  Debian: <https://security-tracker.debian.org/tracker/CVE-2026-63686>

**Vendor / project**
- Apache httpd 2.4 vulnerabilities (authoritative advisory list):
  <https://httpd.apache.org/security/vulnerabilities_24.html>
- Apache httpd source archive (2.4.68 / 2.4.69):
  <https://archive.apache.org/dist/httpd/>

> Record-keeping note: confirm the CVSS vector and affected-range strings against
> the official records above when writing the report — third-party trackers
> occasionally disagree on severity labels (Apache rates these Low/Moderate; NVD
> scores them High). Quote the official value and note the discrepancy.
