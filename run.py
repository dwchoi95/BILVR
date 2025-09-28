import argparse
from src.core import Fixer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LLM repair experiments.")
    parser.add_argument(
        "-e",
        "--experiment",
        type=int,
        default="1",
        help="Experiment to execute (default: 1).",
    )
    parser.add_argument(
        "-d",
        "--dataset",
        default="data/cvefixes_unique.csv",
        help="Path to the dataset CSV file.",
    )
    parser.add_argument(
        "-s",
        "--savedir",
        default="results",
        help="Directory where experiment outputs are stored.",
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
        "--async_limit",
        type=int,
        default=1000,
        help="Maximum number of concurrent asynchronous requests (default: 50).",
    )

    args = parser.parse_args()

    fixer = Fixer(
        llm=args.model,
        temperature=args.temperature,
        dataset_path=args.dataset, 
        save_dir=args.savedir,
        rq_num=args.experiment,
        async_limit=args.async_limit)
    fixer.run()


if __name__ == "__main__":
    main()
