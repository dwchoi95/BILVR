"""Filter a BILVR-format dataset to the CWEs present in EVERY language.

This yields a balanced language x CWE design: the same weakness types appear
across all languages, so language is not confounded with weakness type — ideal
for the cross-language input-selection analysis. Read-only on the source CSV;
writes a new file in the identical 10-column format (run.py works unchanged).

Usage: python src/data/filter_common_cwe.py data/morefixes.csv \
              data/morefixes_dates.csv data/morefixes_20cwe.csv \
              data/morefixes_20cwe_dates.csv
"""
import csv
import sys
from collections import Counter, defaultdict

csv.field_size_limit(10**9)


def main(src_csv, src_dates, out_csv, out_dates):
    with open(src_csv, newline="") as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames
        rows = list(reader)
    dates = {r["CVE ID"]: r for r in csv.DictReader(open(src_dates, newline=""))}

    langs = sorted({r["Programming Language"] for r in rows})
    cwe_langs = defaultdict(set)
    for r in rows:
        cwe_langs[r["CWE ID"]].add(r["Programming Language"])
    common = {c for c, ls in cwe_langs.items() if len(ls) == len(langs)}

    kept = [r for r in rows if r["CWE ID"] in common]
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(kept)

    cves = {r["CVE ID"] for r in kept}
    with open(out_dates, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["CVE ID", "published_date", "year"])
        for cve in sorted(cves):
            d = dates.get(cve)
            if d:
                w.writerow([cve, d["published_date"], d["year"]])

    years = Counter(dates[r["CVE ID"]]["year"] for r in kept if r["CVE ID"] in dates)
    print(f"languages ({len(langs)}): {langs}")
    print(f"common CWEs (in all langs): {len(common)}")
    print(f"kept rows: {len(kept)} | unique CVEs: {len(cves)}")
    print("CVE year distribution (rows):")
    for y in sorted(years):
        print(f"  {y:8s} {years[y]}")
    print(f"wrote {out_csv}  +  {out_dates}")


if __name__ == "__main__":
    main(*sys.argv[1:5])
