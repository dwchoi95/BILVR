# BILVR+ — Does Auxiliary Input Help LLM-Based Vulnerability Repair?

A leakage-controlled study of which auxiliary inputs (CVE/CWE identifiers, descriptions, examples, vulnerable-line hints) actually help LLM-based vulnerability repair.

## Download data & results

`data/` and `results/` are too large for the repo. Download both zips from
[Google Drive](https://drive.google.com/drive/folders/1KOhE_KB7PdEkDRMpq_Yku7DlcWigckKB?usp=share_link) and unzip at the repo root
(they extract into `data/` and `results/`):

```bash
unzip data.zip && unzip results.zip
```

| File | Size | SHA256 |
| --- | --- | --- |
| `data.zip` | 188 MB | `76d44b65ad8d6c6310eebbe8d88ed5bb5912273251353558379a1c122d49f67c` |
| `results.zip` | 3.1 GB | `d80b2fac4a3c7a51edcecffd773e3ddf3f35db16831a08d53988d257cb543f88` |

## Run

```bash
python3 -m venv env && source env/bin/activate
pip install -r requirements.txt
export OPENAI_API_KEY=...   # or CLAUDE_API_KEY / OLLAMA_API_URL / LOCAL_API_URL per backend

# Breadth sweep (11 curated input combinations) on both splits
python run.py -d data/nday_plus.csv    -s results/breadth -m gpt-5.4-nano --backend gpt -c breadth
python run.py -d data/zeroday_plus.csv -s results/breadth -m gpt-5.4-nano --backend gpt -c breadth

# Depth sweep (all 128 combinations) on the stratified sample
python run.py -d data/depth_sample.csv -s results/full -m google/gemma-4-E4B-it --backend ollama -c full

# Prompting strategies (zero-shot / few-shot / CoT)
python run.py -d data/depth_sample.csv -s results/prompting -m google/gemma-4-E4B-it \
    --backend ollama --prompt-strategies zero-shot few-shot cot
```

Runs are resumable (re-invoke the same command; `-r` resets). See `python run.py --help` for all options.

## data/

Benchmark CSVs in a shared 10-column format (see [data/README.md](data/README.md)):

- `morefixes_20cwe.csv` — full benchmark: 10 languages × the 20 CWEs common to all of them, mined from MoreFixes v3
- `nday_plus.csv` — known split (CVEs disclosed ≤ 2025-08-31, the shared model cutoff)
- `zeroday_plus.csv` — leakage-controlled split (CVEs disclosed after the cutoff)
- `depth_sample.csv` — stratified 1,280-instance sample for the 128-combination depth sweep

## results/

Result CSVs, one per `<dataset>_<model>.csv`:

- `breadth/` — 11-combination sweep over the full benchmark (4 models × both splits)
- `full/` — 128-combination depth sweep on `depth_sample.csv`
- `prompting/` — zero-shot / few-shot / CoT comparison
