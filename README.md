# Not All Input Helps: What Information Should We Feed to LLMs for Vulnerability Repair?

<!-- ![image](./overview.png) -->
<div align="center">
  <img src="./overview.png" alt="overview"
       style="width:clamp(320px, 50%, 900px); height:auto; display:block;" />
</div>

## Installation

### Prerequisites
- Python 3.12+
- OpenAI API key (for GPT models) and/or Anthropic API key (for Claude models)

### Setup Steps

1. **Clone or navigate to the project directory:**
   ```bash
   git clone https://github.com/dwchoi95/BILVR.git
   cd /path/to/BILVR
   ```

2. **(Optional) Create and activate virtual environment:**
   ```bash
   python3 -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure API keys:**
   Create a `.env` file in the project root with your LLM API keys:
   ```bash
   cat > .env << 'EOF'
   OPENAI_API_KEY="your_openai_api_key_here"
   CLAUDE_API_KEY="your_claude_api_key_here"
   EOF
   ```

## Usage

```bash
# Run on NDay vulnerabilities with GPT-3.5-turbo (default)
python run.py -d data/nday.csv

# Run on ZeroDay vulnerabilities with GPT-3.5-turbo
python run.py -d data/zeroday.csv

# Run on ZeroDayD vulnerabilities with Claude 3 Haiku
python run.py -d data/zeroday.csv -m claude-3-haiku-20240307
```

### Command-line Arguments

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `-d` | `--dataset` | `data/zeroday.csv` | Path to the dataset CSV file |
| `-s` | `--savedir` | `results` | Directory for saving experiment results |
| `-m` | `--model` | `gpt-3.5-turbo` | LLM model identifier (e.g., `gpt-3.5-turbo`, `claude-3-haiku-20240307`) |
| `-t` | `--temperature` | `0.0` | LLM temperature (0.0 = deterministic, higher = more random) |
| `-l` | `--limit` | `1` | Max concurrent API requests (for rate limiting) |
| `-r` | `--reset` | `false` | Reset experiment results and start fresh |


## Project Structure

```
BILVR/
├── data/             # Vulnerability datasets
│   ├── nday.csv      # NDay (known) vulnerabilities
│   └── zeroday.csv   # ZeroDay (unknown) vulnerabilities
├── results/          # Experiment results (CSV outputs)
├── src/
│   ├── core/         # Core repair and validation logic
│   ├── llms/         # LLM backend implementations
│   ├── prompts/      # System prompts for repairs
│   └── utils/        # Utility functions
├── run.py            # Main entry point
├── evaluation.ipynb  # Results analysis and visualization
└── requirements.txt  # Python dependencies
```
