"""Split a BILVR-format dataset at a fixed knowledge-cutoff date.

A single shared cutoff (default gpt-5.2's 2025-08-31) defines a leakage-free
holdout that is valid for EVERY model whose training cutoff <= that date:
  - zeroday_plus : CVEs disclosed AFTER the cutoff  -> unseen / leakage-free
  - nday_plus    : CVEs disclosed ON/BEFORE cutoff  -> known / possibly memorized
Mirrors the original zeroday/nday split. Read-only on the source; writes the two
files in the identical 10-column format (run.py works unchanged).

Usage: python src/data/temporal_split.py data/morefixes_20cwe.csv \
              data/morefixes_20cwe_dates.csv 2025-08-31 data/
"""
import csv
import sys
from collections import Counter
from pathlib import Path

csv.field_size_limit(10**9)


def main(src_csv, src_dates, cutoff, out_dir):
    out = Path(out_dir)
    cve_date = {d["CVE ID"]: (d["published_date"] or "")[:10]
                for d in csv.DictReader(open(src_dates, newline=""))}
    with open(src_csv, newline="") as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames
        rows = list(reader)

    zero, nday = [], []  # zeroday_plus (after cutoff), nday_plus (<= cutoff)
    for r in rows:
        d = cve_date.get(r["CVE ID"], "")
        (zero if d > cutoff else nday).append(r)

    for name, subset in (("zeroday_plus", zero), ("nday_plus", nday)):
        with open(out / f"{name}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(subset)
        cves = {r["CVE ID"] for r in subset}
        with open(out / f"{name}_dates.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["CVE ID", "published_date", "year"])
            for cve in sorted(cves):
                d = cve_date.get(cve, "")
                w.writerow([cve, d, d[:4] if d[:4].isdigit() else "unknown"])

        langs = Counter(r["Programming Language"] for r in subset)
        print(f"=== {name}.csv (published_date {'>' if name=='zeroday_plus' else '<='} {cutoff}) ===")
        print(f"  rows: {len(subset)} | unique CVEs: {len(cves)} | CWEs: {len({r['CWE ID'] for r in subset})}")
        print(f"  per language: {dict(langs.most_common())}")
        yrs = Counter(cve_date.get(r['CVE ID'],'?')[:4] for r in subset)
        print(f"  per year: {dict(sorted(yrs.items()))}\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
