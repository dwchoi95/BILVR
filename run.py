import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LLM repair experiments.")
    parser.add_argument(
        "-d",
        "--dataset",
        default="data/zeroday.csv",
        help="Path to the dataset CSV file.",
    )
    parser.add_argument(
        "-s",
        "--savedir",
        default="results",
        help="Directory where experiment results are stored.",
    )
    parser.add_argument(
        "-m",
        "--model",
        default="gpt-3.5-turbo",
        help="Model identifier to use for the chosen LLM backend.",
    )
    parser.add_argument(
        "-t",
        "--temperature",
        type=float,
        default="0.0",
        help="Temperature setting for the LLM (default: 0.0).",
    )
    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=1,
        help="Maximum Rate limits of LLM API (default: 1).",
    )
    parser.add_argument(
        "-r",
        "--reset",
        action="store_true",
        help="Reset the experiment results.",
    )
    parser.add_argument(
        "-c",
        "--combinations",
        default="full",
        choices=["full", "breadth", "cveid"],
        help="Combination set: 'full' = all 128, 'breadth' = 11 curated, "
             "'cveid' = {None, CVE-ID} only (for negative-control runs on the "
             "shuffled/fake CVE-ID datasets) (default: full).",
    )
    parser.add_argument(
        "--cve-mode",
        default="real",
        choices=["real", "shuffled", "fake"],
        help="CVE-ID negative control (C1): 'real' (default), 'shuffled' (each row "
             "gets another real vuln's CVE ID), or 'fake' (nonexistent CVE-2099-9xxxx). "
             "Alters only the CVE ID column in memory; results go to a separate "
             "'<dataset>_cve<mode>_<model>.csv'. Pair with '-c cveid'.",
    )
    parser.add_argument(
        "--backend",
        default="auto",
        choices=["auto", "ollama", "vllm", "gpt", "claude"],
        help="LLM backend to use. Use 'ollama' for local Mac runs.",
    )
    parser.add_argument(
        "--output-filename",
        default=None,
        help="Override result filename under --savedir.",
    )
    parser.add_argument(
        "--prompt-strategies",
        nargs="+",
        choices=["zero-shot", "few-shot", "cot"],
        default=None,
        help="Prompting strategies to run. Omit for the original zero-shot behavior.",
    )
    parser.add_argument(
        "--fewshot-k",
        type=int,
        default=2,
        help="Number of retrieval-based exemplars for the few-shot strategy "
             "(retrieved from the NDay+ corpus by code similarity; default: 2).",
    )
    parser.add_argument(
        "--max-experiments",
        type=int,
        default=None,
        help="Limit the number of experiment cells generated for quick smoke tests.",
    )
    parser.add_argument(
        "--row-offset",
        type=int,
        default=0,
        help="Skip this many dataset rows before constructing experiment cells.",
    )
    parser.add_argument(
        "--row-limit",
        type=int,
        default=None,
        help="Limit source dataset rows before constructing experiment cells.",
    )

    args = parser.parse_args()

    from src.core import Fixer

    fixer = Fixer(
        llm=args.model,
        temperature=args.temperature,
        dataset_path=args.dataset,
        save_dir=args.savedir,
        async_limit=args.limit,
        combination_mode=args.combinations,
        cve_mode=args.cve_mode,
        backend=args.backend,
        output_filename=args.output_filename,
        prompt_strategies=args.prompt_strategies,
        fewshot_k=args.fewshot_k,
        max_experiments=args.max_experiments,
        row_offset=args.row_offset,
        row_limit=args.row_limit)
    fixer.run(reset=args.reset)


if __name__ == "__main__":
    main()
