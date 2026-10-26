# 01 · Environment Architecture

INF2005 ACW3 — Vulnerability Assessment & Remediation
Target: a single Apache HTTP Server instance exposing three assessed CVEs.

> **Scope & safety.** Everything here runs locally on team hardware (Docker on a
> laptop, or a VM). The target is deliberately vulnerable and is bound to the
> host loopback only — it must never be placed on the SIT network or the
> Internet, per the ACW3 specification.

---

## 1. Why one Apache target

The specification allows combining multiple vulnerabilities in a single target
environment and requires a cumulative CVSS of **≥ 20**. All three chosen CVEs
live in different modules of the **same** Apache HTTP Server version line, so one
`httpd` build demonstrates all three. This keeps the demo fast (one container to
start) and the remediation clean (one upgrade fixes all three).

| # | CVE | Module | Type (CWE) | Affected | Fixed | CVSS (NVD) | Severity |
|---|-----|--------|------------|----------|-------|-----------|----------|
| 1 | CVE-2026-93546 | `mod_dav_fs` | Integer overflow (CWE-190) via PROPPATCH | httpd 2.4.0–2.4.68 | 2.4.69 | **8.8** | High |
| 2 | CVE-2026-73636 | `mod_auth_digest` | Auth bypass by capture-replay (CWE-294) | httpd 2.4.0–2.4.68 | 2.4.69 | **8.1** | High |
| 3 | CVE-2026-63686 | `mod_xml2enc` | NULL-pointer dereference / DoS (CWE-476) | httpd 2.4.0–2.4.68 | 2.4.69 | **7.5** | High |

**Cumulative CVSS = 8.8 + 8.1 + 7.5 = 24.4** (≥ 20 ✔), all High.

> **Severity note for Q&A.** Apache's own advisory rates these issues *Low* to
> *Moderate*, while NVD / OpenCVE score them *High* (8.8 / 8.1 / 7.5). The
> coursework uses the CVSS figures from the instructor's CVE list, i.e. the NVD
> scale. Be ready to explain this split: Apache weights real-world
> exploitability (authentication required, MITM position required, DoS-only),
> whereas the base CVSS vector does not discount for those pre-conditions. The
> CVE-List severity is what the ≥ 20 requirement is scored against.

Sources are listed in `docs/04-remediation-research.md`.

---

## 2. Target version & build strategy

- **Vulnerable build:** Apache **httpd 2.4.68** — the last release before the fix.
- **Patched build:** Apache **httpd 2.4.69** — used by the optional
  `target-patched` service for the before/after remediation demo.

The target is **compiled from the official Apache source archive** rather than
pulled from a distribution package, because:

1. Distributions back-port fixes and pin their own version strings, so an
   `apt install apache2` may already contain the patch.
2. A source build pins the exact version and **guarantees the three assessed
   modules are compiled in** (`mod_proxy_html` and `mod_xml2enc` need
   `libxml2` at build time and are not in the default module set).

Both tarballs are confirmed available from `https://archive.apache.org/dist/httpd/`.
The same `lab/target/Dockerfile` builds either version via the `HTTPD_VERSION`
build argument.

---

## 3. Network layout & IP / port plan

A single isolated Docker bridge network, `acwnet` (`172.30.0.0/24`). The target's
web port is published to the host **loopback only** (`127.0.0.1`), so nothing is
reachable from the LAN.

```
                 host loopback
          127.0.0.1:8080 ─┐        127.0.0.1:8081 ─┐ (remediation profile)
                          │                         │
   ┌──────────────────────┼─────────────────────────┼───────────────────────┐
   │  docker network: acwnet   172.30.0.0/24  (bridge, gw 172.30.0.1)         │
   │                      │                         │                         │
   │   ┌──────────────────▼───────┐     ┌───────────▼──────────────┐          │
   │   │ target  172.30.0.10       │     │ target-patched 172.30.0.11│          │
   │   │ httpd 2.4.68 (VULN) :80   │     │ httpd 2.4.69 (FIXED) :80  │          │
   │   │  /webdav  /digest  /proxy │     │  hardened config          │          │
   │   └──────────┬────────────────┘     └───────────┬──────────────┘          │
   │              │ proxies /proxy/ ──────────────────┤                        │
   │   ┌──────────▼───────────────┐                   │                        │
   │   │ backend 172.30.0.20 :8000 │◄──────────────────┘                        │
   │   │ untrusted backend fixture │  (internal only — no host port)           │
   │   └───────────────────────────┘                                           │
   │   ┌───────────────────────────┐                                           │
   │   │ attacker 172.30.0.100      │  Kali — docker compose exec attacker bash │
   │   └───────────────────────────┘                                           │
   └───────────────────────────────────────────────────────────────────────────┘
```

| Host / service | IP | Container port | Host mapping | Role |
|----------------|----|----------------|--------------|------|
| `target` | 172.30.0.10 | 80 | `127.0.0.1:8080` | Vulnerable httpd 2.4.68 (all 3 scenarios) |
| `backend` | 172.30.0.20 | 8000 | *(none — internal)* | Untrusted backend for the proxy scenario |
| `attacker` | 172.30.0.100 | — | — | Kali assessment workstation |
| `target-patched` | 172.30.0.11 | 80 | `127.0.0.1:8081` | Patched httpd 2.4.69 (remediation demo) |

Scenario endpoints on the target (path-based, port 80):

| Path | Module(s) | CVE |
|------|-----------|-----|
| `/webdav/` | `mod_dav`, `mod_dav_fs` | CVE-2026-93546 |
| `/digest/` | `mod_auth_digest` | CVE-2026-73636 |
| `/proxy/`  | `mod_proxy`, `mod_proxy_http`, `mod_proxy_html`, `mod_xml2enc` | CVE-2026-63686 |

**Lab credentials** (lab-only; set in `lab/.env`): WebDAV `davuser:LabPass123`
(Basic), Digest `digestuser:LabPass123`, realm `ACW3 Restricted`.

---

## 4. Reproducible build files

```
lab/
├── docker-compose.yml        # topology above; `up -d --build` brings it online
├── .env.example              # copy to .env; lab credentials
├── Makefile                  # make up / verify / remediation / attacker / down
├── target/
│   ├── Dockerfile            # source-builds httpd (ARG HTTPD_VERSION)
│   ├── conf/lab-vuln.conf     # the three vulnerable scenarios
│   ├── conf/lab-hardened.conf # remediated config (diff for the report)
│   └── entrypoint.sh         # provisions users/content, config-tests, starts httpd
├── backend/{Dockerfile,app.py}   # untrusted backend fixture (xml2enc scenario)
├── attacker/Dockerfile       # Kali + focused tool set
└── scripts/verify.sh         # verification harness (see doc 02)
```

### Bring the lab up

```bash
cd lab
cp .env.example .env            # optional; defaults are fine for the lab
docker compose up -d --build    # or: make up
./scripts/verify.sh             # or: make verify
```

First build compiles httpd from source and takes a few minutes; subsequent
starts are cached and near-instant. **Build the images the day before the demo** —
the demo slots are strictly for demonstrating, not for building or debugging.

### Confirm the version

```bash
curl -sI http://127.0.0.1:8080/ | grep -i server      # Server: Apache/2.4.68 (Unix)
docker exec acw3-target httpd -v                       # Server version
docker exec acw3-target httpd -M | grep -E 'dav|digest|xml2enc|proxy_html'
```

---

## 5. Attacker box — container vs VM

The compose file ships a **Kali container** (`attacker`, 172.30.0.100) so the whole
lab is reproducible with one command and already sits on `acwnet`. Enter it with
`docker compose exec attacker bash` (or `make attacker`). It carries a focused
tool set (curl, cadaver/davtest, python3-requests, nmap, nikto); add anything
else with `apt`.

A **Kali VM** (VirtualBox/VMware) is an equally acceptable alternative per the
spec. If you use a VM, reach the target at the **host** mapping
(`http://<laptop-IP>:8080/`) or re-map the target port off loopback. The
container route is recommended for demo-day reliability because it needs no
VM networking setup.

---

## 6. Alternative: official image (faster, less control)

If a source build is impractical, the official Debian-based `httpd:2.4.68` image
is built with the full module set and `libxml2`, so the assessed modules are
present. Swap the `target` service's `build:` block for `image: httpd:2.4.68` and
mount `conf/lab-vuln.conf`, loading it with `httpd -f`. The source build remains
the recommended path because it pins the exact version and is guaranteed to
contain the vulnerable module code regardless of image tag availability.
