# Datasets (BILVR+)

All datasets use the same **10-column format** so `run.py` consumes them
interchangeably:

- **CVE ID** / **CVE Description** — CVE identifier and NVD description
- **CWE ID** / **CWE Name** / **CWE Description** / **CWE Example** — from the MITRE CWE catalog
- **Programming Language** — source language
- **Vulnerable Lines** — location hints (deleted lines from the fix diff)
- **Vulnerable Code** — function-level vulnerable snippet (pre-fix)
- **Human Patch** — reference fixed function (post-fix)

## Files

| File | Rows | Description |
|------|------|-------------|
| `morefixes.csv` | 51,618 | Full extraction from MoreFixes v3 (10 languages, 364 CWEs). Superset. |
| `morefixes_20cwe.csv` | 23,879 | The paper benchmark: rows whose CWE occurs in **all 10 languages** (20 CWEs) → balanced language×CWE design. |
| `zeroday_plus.csv` | 2,750 | **Leakage-free** split: CVEs disclosed **after 2025-08-31** (the shared model cutoff). |
| `nday_plus.csv` | 21,129 | **Known** split: CVEs disclosed on/before 2025-08-31. |
| `*_dates.csv` | — | Sidecars (`CVE ID, published_date, year`) for the temporal split. Kept out of the runnable CSVs to preserve the identical format. |

`zeroday_plus` + `nday_plus` partition `morefixes_20cwe` at the cutoff 2025-08-31.

## Provenance / regeneration

Built from **MoreFixes v3** (Zenodo `records/20702039`) via, in order:
`src/data/extract_morefixes.sql` (Postgres extraction, before/after method pairing)
→ `src/data/morefixes_adapter.py` (10-column format, Vulnerable Lines from diffs,
MITRE CWE enrichment via `src/utils/cwe_catalog.py`)
→ `src/data/filter_common_cwe.py` (the 20-CWE balanced subset)
→ `src/data/temporal_split.py` (the 2025-08-31 leakage split).
