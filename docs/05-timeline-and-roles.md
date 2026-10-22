# 05 · Project Timeline & Role Assignments

Team size 5–6. Report due **Monday 9 Nov 2026, 23:59**; demo **Tue 10 Nov** or
**Thu 12 Nov 2026** (per the lab-group schedule in the specification). Plan runs
from **Thu 22 Oct → Mon 9 Nov 2026**.

## Roles

Assign names/student IDs to each. Owners are responsible for their deliverable;
everyone contributes to the report and must be able to demo and answer questions
(the rubric scores each member individually).

| Role | Owner | Primary responsibility |
|------|-------|------------------------|
| R1 — Team lead / report editor | | Coordination, instructor comms, report assembly, submission, originality declaration + GenAI disclosure |
| R2 — Environment / infra engineer | | Docker build, compose, networking, `verify.sh`, demo-day reliability |
| R3 — Vuln 1 owner (WebDAV / `mod_dav_fs`, CVE-2026-93546) | | Exploitation + evidence + write-up for CVE-2026-93546 |
| R4 — Vuln 2 owner (Digest / `mod_auth_digest`, CVE-2026-73636) | | Exploitation + evidence + write-up for CVE-2026-73636 |
| R5 — Vuln 3 owner (proxy / `mod_xml2enc`, CVE-2026-63686) | | Exploitation + evidence + write-up for CVE-2026-63686 |
| R6 — Remediation & demo coordinator | | Hardened config, before/after remediation demo, rehearsal, timing |

**5-person team:** fold R6 into R1 (remediation demo) and R2 (hardening config),
or have the lead also own remediation. **6-person team:** keep all six.

## Timeline

| Phase | Dates | Activities | Lead |
|-------|-------|-----------|------|
| 0. Kick-off & approval | Thu 22 – Mon 26 Oct | Confirm team & roles. **Email the instructor to get the three CVEs approved for the demo** (rubric requires 3 instructor-approved vulns). Read the specification together. | R1 |
| 1. Build environment | Mon 26 – Wed 28 Oct | Build the Docker lab (`make up`); compile httpd 2.4.68; stand up backend + Kali. | R2 |
| 2. Verification | Wed 28 – Fri 30 Oct | Run `verify.sh`; confirm version, modules and reachability for all three scenarios; sign off the doc 02 checklist. | R2 + all owners |
| 3. Exploitation dev | Fri 30 Oct – Wed 4 Nov | Each owner develops and rehearses their trigger; capture evidence/screenshots. | R3 / R4 / R5 |
| 4. Remediation | Wed 4 – Fri 6 Nov | Stand up the patched target (2.4.69, hardened config); demonstrate before/after; document defences. | R6 |
| 5. Report draft | Sat 7 – Sun 8 Nov | Fill the report skeleton: summary table, per-vuln sections, appendix; cite sources; add GenAI-use statement. | R1 + all |
| 6. Rehearsal | Sun 8 Nov | Full dry-run of the demo end-to-end (one attempt each); time it to ~20 min + 10 min Q&A; rebuild images clean. | R6 |
| 7. Finalise & submit | Mon 9 Nov (by 23:59) | Proofread, export `Report_P<lab>-<team>.pdf`, sign originality declaration, submit to xSite Dropbox. | R1 |
| 8. Demo | Tue 10 **or** Thu 12 Nov | Present; every member demos/answers. Pre-build images beforehand — slots are not for setup/debugging. | all |
| 9. Peer review (if needed) | by Fri 14 Nov | Submit peer-review form only if contribution was uneven (CC all members). | individual |

## Milestones / gates

- **M1 (26 Oct):** three CVEs approved by instructor; roles assigned.
- **M2 (30 Oct):** `verify.sh` all-green — lab proven before exploitation.
- **M3 (4 Nov):** all three triggers reproducible on demand with captured evidence.
- **M4 (6 Nov):** remediation demonstrated (2.4.69 before/after).
- **M5 (9 Nov 23:59):** report submitted.
- **M6 (10/12 Nov):** demo delivered.

## Standing reminders

- Local lab only — never target the SIT network or any online host.
- Build/rebuild images the day before the demo; verify immediately before.
- Keep each exploit to a single, scripted attempt (demo rule).
- Disclose which parts of the report were produced with GenAI tools (SIT policy).
- One report per team + one originality declaration signed by all members.
