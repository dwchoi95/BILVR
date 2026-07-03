"""E4 — build the stratified depth sample for the 128-combination depth sweep.

Design: equal allocation 128 instances / language × 10 languages = 1,280
(Cochran n0 = 1.96^2 * 0.25 / 0.10^2 ≈ 96 per stratum at ±10%/95%, rounded up to 128).
Within each language the split (nday_plus / zeroday_plus) is sampled proportionally so
both the known and leakage-free sides are represented, and CWE diversity is preserved by
shuffling with a fixed seed. If a language has < 128 rows, all of its rows are taken.

Output: data/depth_sample.csv  (same columns as the source + a `Split` column).
Reproducible: SEED is fixed.
"""
import pandas as pd

SEED = 42
PER_LANG = 128
SRC = {"nday_plus": "data/nday_plus.csv", "zeroday_plus": "data/zeroday_plus.csv"}
OUT = "data/depth_sample.csv"

def main():
    frames = []
    for split, path in SRC.items():
        d = pd.read_csv(path)
        d["Split"] = split
        frames.append(d)
    df = pd.concat(frames, ignore_index=True)
    df["__lang"] = df["Programming Language"].astype(str).str.strip().str.lower()

    picked = []
    for lang, g in df.groupby("__lang"):
        if len(g) <= PER_LANG:
            picked.append(g)
            continue
        # proportional split allocation within the language
        rows = []
        remaining = PER_LANG
        splits = g["Split"].value_counts()
        for i, (sp, cnt) in enumerate(splits.items()):
            gs = g[g["Split"] == sp]
            if i == len(splits) - 1:
                n = remaining
            else:
                n = round(PER_LANG * cnt / len(g))
                n = min(n, len(gs))
            n = min(n, len(gs), remaining)
            rows.append(gs.sample(n=n, random_state=SEED))
            remaining -= n
        picked.append(pd.concat(rows))

    out = pd.concat(picked, ignore_index=True).drop(columns="__lang")
    out = out.sample(frac=1.0, random_state=SEED).reset_index(drop=True)  # shuffle
    out.to_csv(OUT, index=False)

    print(f"depth sample: {len(out)} rows -> {OUT}")
    print("\nper-language counts:")
    print(out.groupby([out["Programming Language"].str.lower(), "Split"]).size().unstack(fill_value=0))
    print("\nsplit totals:", out["Split"].value_counts().to_dict())
    print("distinct CWEs:", out["CWE ID"].nunique())

if __name__ == "__main__":
    main()
