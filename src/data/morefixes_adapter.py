"""Lift the MoreFixes extraction CSV into the BILVR 10-column dataset format.

Input  : the CSV produced by `extract_morefixes.sql` (psql COPY ... CSV HEADER),
         columns: CVE ID, published_date, CVE Description, CWE ID,
                  Programming Language, start_line, end_line,
                  Vulnerable Code, Human Patch, diff_parsed
Output : data/morefixes.csv with EXACTLY the original 10 columns, in order:
         CVE ID, CVE Description, CWE ID, CWE Name, CWE Description, CWE Example,
         Programming Language, Vulnerable Lines, Vulnerable Code, Human Patch
         (identical to data/zeroday.csv → run.py works unchanged)
Sidecar: data/morefixes_dates.csv (CVE ID, published_date, year) — kept out of the
         runnable file to preserve "identical format", but needed for the per-model
         temporal holdout (evaluate each model only on post-cutoff CVEs).

Vulnerable Lines = the patch's deleted lines that fall inside the vulnerable
method's [start_line, end_line] range, mirroring the original column's intent.
"""
import ast
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.cwe_catalog import build_cwe_lookup

csv.field_size_limit(10**9)

ORIG_COLUMNS = [
    "CVE ID", "CVE Description", "CWE ID", "CWE Name", "CWE Description",
    "CWE Example", "Programming Language", "Vulnerable Lines",
    "Vulnerable Code", "Human Patch",
]
# Languages we keep (multi-language; tree-sitter/codebleu-supported set).
KEEP_LANGS = {"c", "cpp", "c++", "java", "python", "javascript", "js",
              "typescript", "go", "php", "ruby", "c#", "csharp"}


def _vulnerable_lines(diff_parsed_raw: str, start: str, end: str) -> str:
    """Deleted lines from diff_parsed whose line numbers lie within [start, end]."""
    if not diff_parsed_raw:
        return ""
    try:
        parsed = ast.literal_eval(diff_parsed_raw)
        deleted = parsed.get("deleted", [])
    except (ValueError, SyntaxError, AttributeError):
        return ""
    try:
        lo, hi = int(start), int(end)
    except (TypeError, ValueError):
        lo, hi = None, None
    picked = []
    for item in deleted:
        if not (isinstance(item, (list, tuple)) and len(item) == 2):
            continue
        lineno, content = item
        if lo is None or (isinstance(lineno, int) and lo <= lineno <= hi):
            picked.append(str(content))
    return "\n".join(picked).strip("\n")


def main(in_csv: str, cwe_xml: str, out_csv: str, dates_csv: str) -> None:
    cwe = build_cwe_lookup(cwe_xml)
    rows_out, dates, langs, years = [], {}, Counter(), Counter()
    missing_cwe = Counter()
    total = 0

    with open(in_csv, newline="") as f:
        for r in csv.DictReader(f):
            total += 1
            lang = (r["Programming Language"] or "").strip().lower()
            if lang not in KEEP_LANGS:
                continue
            cid = (r["CWE ID"] or "").strip()
            meta = cwe.get(cid)
            if not meta or not meta.get("name"):
                missing_cwe[cid] += 1
                continue
            vuln_lines = _vulnerable_lines(
                r.get("diff_parsed", ""), r.get("start_line"), r.get("end_line"))

            rows_out.append({
                "CVE ID": r["CVE ID"],
                "CVE Description": r["CVE Description"],
                "CWE ID": cid,
                "CWE Name": meta["name"],
                "CWE Description": meta["description"],
                "CWE Example": meta["example"],
                "Programming Language": lang,
                "Vulnerable Lines": vuln_lines,
                "Vulnerable Code": r["Vulnerable Code"],
                "Human Patch": r["Human Patch"],
            })
            langs[lang] += 1
            pub = (r.get("published_date") or "").strip()
            year = pub[:4] if pub[:4].isdigit() else "unknown"
            years[year] += 1
            dates[r["CVE ID"]] = pub

    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ORIG_COLUMNS)
        w.writeheader()
        w.writerows(rows_out)
    with open(dates_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["CVE ID", "published_date", "year"])
        for cve_id, pub in sorted(dates.items()):
            w.writerow([cve_id, pub, pub[:4] if pub[:4].isdigit() else "unknown"])

    n_cve = len(dates)
    print(f"input rows (CVE×func pairs)      : {total}")
    print(f"kept rows                        : {len(rows_out)}")
    print(f"unique CVEs                      : {n_cve}")
    print(f"unique CWEs                      : {len({r['CWE ID'] for r in rows_out})}")
    print(f"\nlanguages (rows):")
    for k, v in langs.most_common():
        print(f"  {k:12s} {v}")
    print(f"\nCVE year distribution (rows):")
    for y in sorted(years):
        print(f"  {y:8s} {years[y]}")
    if missing_cwe:
        print(f"\ndropped: CWE not in MITRE catalog ({sum(missing_cwe.values())} rows, "
              f"{len(missing_cwe)} distinct ids), e.g. {list(missing_cwe)[:5]}")
    print(f"\nwrote {out_csv}  +  {dates_csv}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
