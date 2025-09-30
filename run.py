import argparse
from src.core import Fixer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LLM repair experiments.")
    parser.add_argument(
        "-d",
        "--dataset",
        default="data/derivative/zeroday.csv",
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

    args = parser.parse_args()

    fixer = Fixer(
        llm=args.model,
        temperature=args.temperature,
        dataset_path=args.dataset, 
        save_dir=args.savedir,
        async_limit=args.limit)
    fixer.run(reset=args.reset)


if __name__ == "__main__":
    main()
