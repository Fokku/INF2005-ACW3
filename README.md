# INF2005 ACW3 — Vulnerability Assessment & Remediation

Self-contained lab for assessing and remediating three Apache HTTP Server
vulnerabilities, with a reproducible target, verification harness, exploitation
scaffold, remediation research, and a report skeleton.

> ⚠️ **Local lab only.** The target is deliberately vulnerable and bound to the
> host loopback. Per the ACW3 specification, never target the SIT network or any
> online host — build and run everything on your own hardware.

## The three vulnerabilities (single Apache 2.4.68 target)

| CVE | Module | Type | CVSS (NVD) | Fixed in |
|-----|--------|------|-----------|----------|
| CVE-2026-93546 | `mod_dav_fs` | Integer overflow via PROPPATCH | 8.8 High | 2.4.69 |
| CVE-2026-73636 | `mod_auth_digest` | Auth bypass by nonce replay | 8.1 High | 2.4.69 |
| CVE-2026-63686 | `mod_xml2enc` | NULL-ptr deref / DoS | 7.5 High | 2.4.69 |

Cumulative CVSS **24.4** (≥ 20 required), all High. One upgrade (→ 2.4.69) fixes
all three. *Confirm the three CVEs with the instructor before starting — the demo
rubric requires three instructor-approved vulnerabilities.*

## Quick start

```bash
cd lab
cp .env.example .env            # optional; lab-default credentials
docker compose up -d --build    # or: make up   (first build compiles httpd; a few min)
./scripts/verify.sh             # or: make verify — confirms all 3 vulns present & reachable
docker compose exec attacker bash   # or: make attacker — the Kali box

# remediation / before-after demo:
make remediation                # patched httpd 2.4.69 on :8081 with hardened config
make verify-patched
```

Target: `http://127.0.0.1:8080/` — paths `/webdav/`, `/digest/`, `/proxy/`.

## Repository layout

```
README.md
lab/        reproducible environment (Dockerfiles, compose, configs, verify.sh)
docs/       01 architecture · 02 verification · 03 exploitation scaffold ·
            04 remediation research · 05 timeline & roles
report/     Calibri 11pt report skeleton (fill in, export to PDF for submission)
```

## Documentation

1. [`docs/01-environment-architecture.md`](docs/01-environment-architecture.md) — design, verified CVE facts, network/IP/port plan, build files.
2. [`docs/02-verification-plan.md`](docs/02-verification-plan.md) — prove each vuln is present & reachable.
3. [`docs/03-exploitation-scaffold.md`](docs/03-exploitation-scaffold.md) — methodology scaffold (no worked payloads).
4. [`docs/04-remediation-research.md`](docs/04-remediation-research.md) — patched version + config mitigations, with sources.
5. [`docs/05-timeline-and-roles.md`](docs/05-timeline-and-roles.md) — 22 Oct → 9 Nov plan, roles, milestones.

## Report

`report/Report_PX-YY_SKELETON.docx` is the Calibri 11pt skeleton (cover, summary
table, per-vuln sections, references, appendix). Fill it in, then **rename and
export to PDF** as `Report_P<labgroup>-<team>.pdf` (e.g. `Report_P2-11.pdf`) for
submission. One report per team with a signed originality declaration; disclose
any GenAI assistance (SIT policy). *(`PX-YY` is a placeholder — the file uses a
Windows-safe name; set `X` = lab group, `YY` = team number.)*
