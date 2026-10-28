# Scenario 2 evidence — CVE-2026-63686 (mod_xml2enc)

Apache HTTP Server `mod_xml2enc` NULL dereference DoS.
Vulnerable: 2.4.68.  Fixed: 2.4.69.

**Winning trigger:** `big5` charset with truncated trailing lead byte (`0xa4`)
at end of body. Conversion returns `APR_INCOMPLETE`, hits `default:` branch,
NULLs `ctx->convset`, dereferences NULL.

## Folder map

| Folder | Purpose |
|---|---|
| `00-identification/` | 2.4.68 + modules loaded + `ProxyHTMLEnable On` |
| `01-exploit/` | Worker crash on the winning trigger |
| `02-remediation/hardened/` | `ProxyHTMLEnable Off` — filter not engaged |
| `02-remediation/patch-only/` | `ProxyHTMLEnable On` — filter engages, no crash |
| `03-screenshots/` | Report appendix images |

## Quick lookup

- Winning URL: `01-exploit/trigger.txt`
- Crash proof (`AH00052 SIGSEGV`): `01-exploit/crash-lines.txt`
- Fix proof: `02-remediation/patch-only/skip-lines.txt` (`AH01444`/`AH01445`, no `AH00052`)

## Reproduce

    cd ../../../lab
    ./scripts/scenario2-exploit.sh
    ./scripts/scenario2-remediate.sh