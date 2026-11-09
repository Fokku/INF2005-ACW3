# INF2005 ACW3 — Vulnerability Assessment & Remediation

Self-contained lab for assessing and remediating three Apache HTTP Server
vulnerabilities, with a reproducible target, verification harness, exploitation
scripts, and remediation research.

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

# CVE-2026-63686 (mod_xml2enc) exploit + fix verification:
./scripts/exploit-xml2enc.sh        # trigger the worker crash on the vulnerable target (:8080)
make verify-fix-xml2enc             # replay the same trigger against the patched target (:8081)
```

Target: `http://127.0.0.1:8080/` — paths `/webdav/`, `/digest/`, `/proxy/`.

## Repository layout

```
README.md
lab/        reproducible environment (Dockerfiles, compose, configs, verify.sh,
            per-CVE exploit/verify-fix scripts under lab/scripts/)
docs/       01 architecture · 02 verification · 03 exploitation scaffold ·
            04 remediation research · 05 timeline & roles
report/     evidence/ — captured curl output, headers, bodies and logs from
            exploit and remediation runs, cited from the submitted report
```

## Branches

`main` carries only the shared lab scaffold (Dockerfiles, compose, configs,
`verify.sh`) and the early consolidated evidence. Each CVE's exploit and
remediation work lives on its own feature branch off `main`:

### `main` — shared base
```
lab/scripts/verify.sh
report/Report_PX-YY_SKELETON.docx
report/evidence/            # consolidated early verification + per-scenario evidence
```

### `cve-2026-93546` — mod_dav_fs integer overflow (PROPPATCH)
```
lab/
  proppatch.xml
  scripts/
    cve-2026-93546-exploit.sh
    cve-2026-93546-exploit-and-scan.sh
    cve-2026-93546-remediate.sh
    cve-2026-93546-reset.sh
    cve-2026-93546-scan.sh
    cve-2026-93546-verify.sh
report/evidence/cve-2026-93546/
  00-identification/   config.txt · modules.txt · version.txt
  01-exploit/          control-propfind.xml · proppatch.xml · proppatch-response.xml ·
                        proppatch-headers.txt · proppatch-status.txt · damage-lines.txt ·
                        persist-resource.xml · after-resource.xml · after-collection.xml · summary.txt
  02-remediation/
    hardened/           proppatch-status.txt · proppatch-response.xml · proppatch-headers.txt ·
                         propfind-status.txt · propfind-response.xml
    patch-only/          proppatch-status.txt · proppatch-response.xml · proppatch-headers.txt ·
                         propfind-status.txt · propfind-response.xml · filter-lines.txt
    patched-version.txt · summary.txt
  03-screenshots/      A1–A10 (version, modules, config, exploit, AH00577 damage log, patched 413/207)
```

### `kannon/cve-2026-73636-digest-evidence` — mod_auth_digest nonce replay
```
lab/
  .gitignore
  scripts/
    digest_replay_probe.sh
    verify_digest_fix.sh
  target/conf/
    lab-vuln.conf, lab-hardened.conf      # updated for the digest scenario
report/evidence/
  digest-vulnerable-*.{txt,html,log}      # capture, authorization, control, replay, gc.log, full-target.log
  digest-patched-*.{txt,html,log}         # same set replayed against the patched target
  screenshots/vuln1-01…03.jpg
```

### `CVE-2026-63686-` — mod_xml2enc NULL-ptr deref
```
lab/
  Makefile                                # + verify-fix-xml2enc target
  scripts/
    exploit-xml2enc.sh
    verify-fix-xml2enc.sh
report/evidence/
  xml2enc-control-{headers.txt,body.html}
  xml2enc-trigger-{body.bin,client.txt}
  xml2enc-gbk-trigger.txt
  xml2enc-fix-control-{headers.txt,body.html}
  xml2enc-fix-trigger-{body.bin,client.txt}
  xml2enc-patch-only-{body.bin,client.txt}
  xml2enc-hardened-{body.bin,client.txt}
  s2-xml2enc-fix.txt
```

## Documentation

1. [`docs/01-environment-architecture.md`](docs/01-environment-architecture.md) — design, verified CVE facts, network/IP/port plan, build files.
2. [`docs/02-verification-plan.md`](docs/02-verification-plan.md) — prove each vuln is present & reachable.
3. [`docs/03-exploitation-scaffold.md`](docs/03-exploitation-scaffold.md) — methodology scaffold (no worked payloads).
4. [`docs/04-remediation-research.md`](docs/04-remediation-research.md) — patched version + config mitigations, with sources.
5. [`docs/05-timeline-and-roles.md`](docs/05-timeline-and-roles.md) — 22 Oct → 9 Nov plan, roles, milestones.

## Team & roles

**Group P6-8**

| Member | Student ID |
|--------|-----------|
| Ang Ke Ying | 2301545 |
| Loh Wen Xuan | 2401561 |
| Muhammad Ridwan Putra Jasni | 2401684 |
| Chng Zong Han | 2401892 |
| Yeo Kai Yuan | 2403201 |
| Kannan s/o Rajamohan | 2401517 |

Each CVE is owned by a pair: Member 1 builds the target and confirms the
exploit, Member 2 applies the fix and writes up the remediation. This maps
directly onto the feature branches above, each branch's scripts and evidence
were produced by its pair.

| Pair | CVE (branch) | Member 1 task | Member 2 task |
|------|------|----------------|----------------|
| Wen Xuan + Ke Ying | [CVE-2026-63686](https://www.cve.org/CVERecord?id=CVE-2026-63686) `mod_xml2enc`, High, CVSS 7.5 (`CVE-2026-63686-`) | Build the target; confirm the exploit manually; write the exploit script | Apply the fix; write the fix-verification script; write the report subsection |
| Ridwan + Kai Yuan | [CVE-2026-93546](https://www.cve.org/CVERecord?id=CVE-2026-93546) `mod_dav_fs`, High, CVSS 8.8 (`cve-2026-93546`) | Build the target; confirm the exploit manually; write the exploit script | Apply the fix; write the fix-verification script; write the report subsection |
| Kannan + Zong Han | [CVE-2026-73636](https://www.cve.org/CVERecord?id=CVE-2026-73636) `mod_auth_digest`, High, CVSS 8.1 (`kannon/cve-2026-73636-digest-evidence`) | Build the target; confirm the exploit manually; write the exploit script | Apply the fix; write the fix-verification script; write the report subsection |
