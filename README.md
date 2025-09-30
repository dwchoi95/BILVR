# Not All Input Helps: What Information Should We Feed to LLMs for Vulnerability Repair?

## Datasets

1. Make dataset directory

```bash
mkdir -p data/original data/derivative
```

2. Download datasets

   - CVEfixes: [https://zenodo.org/records/13118970](https://zenodo.org/records/13118970)
   - Big-Vul: [https://drive.google.com/file/d/1-0VhnHBp9IGh90s2wCNjeCMuy70HPl8X/view](https://drive.google.com/file/d/1-0VhnHBp9IGh90s2wCNjeCMuy70HPl8X/view)
   - Zero-day: [https://zenodo.org/records/14741018](https://zenodo.org/records/14741018)
   - VulMaster: [https://github.com/soarsmu/VulMaster_.git](https://github.com/soarsmu/VulMaster_.git)
3. Unzip datasets
4. Move datasets

```bash
cd "downloaded_directory"
mv CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz "our_directory"/data/original/CVEfixes.sql.gz
mv MSR_data_cleaned.csv "our_directory"/data/original
mv appatch/datasets/zeroday_repair "our_directory"/data/original
mv VulMaster_-main/VulMaster-main/CWE_data_from_homepage.csv "our_directory"/data/original
mv VulMaster_-main/VulMaster-main/ChatGPT_generated_fixes_labels.xlxs "our_directory"/data/original
```

5. Make datasets

```bash
python src/benchmark/cvefixes.py
python src/benchmark/bigvul.py
python src/benchmark/zeroday.py
```

## Installation

1. Python >= 3.13
2. (Optional) Virtual Environment

```bash
python3 -m venv env
```

3. Packages

```bash
pip install -r requirements.txt
```

4. Set LLM API Key

```bash
vim .env
OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
CLAUDE_API_KEY="YOUR_CLAUDE_API_KEY"
```

## How to Run?

1. All our experiments to run

```bash
python run.py -d data/derivative/cvefixes.csv
python run.py -d data/derivative/bigvul.csv
python run.py -d data/derivative/zeroday.csv
python run.py -d data/derivative/zeroday.csv -m claude-3-haiku-20240307
```

### Command line arguments

- `-d` flag specifies the path of Dataset directory.
- `-s` flag specifies the path of Directory where experiment results are saved, default is "results".
- `-m` flag specifies the LLM model, default is "gpt-3.5-turbo".
- `-t` flag specifies the float of LLM model temperature, default is "0.0".
- `-l` flag specifies the number of Maximum Rate Limits of LLM API calls, default is "1".
- `-r` flag specifies the Reset the Experiment results, default is "false".
