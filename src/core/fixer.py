import os
import asyncio
from pathlib import Path
from time import perf_counter
import pandas as pd
from tqdm.asyncio import tqdm as tqdm_async
from itertools import combinations as comb_tools

from .metrics import Metrics
from ..llms import GPT, CLAUDE, OLLAMA, VLLM
from ..prompts import PromptManager
from ..prompts.retrieval_examples import RetrievalExemplars


class Fixer:
    def __init__(
        self,
        llm:str,
        temperature:float,
        dataset_path:str,
        save_dir:str="results",
        async_limit:int=1000,
        combination_mode:str="full",
        cve_mode:str="real",
        backend:str="auto",
        output_filename:str|None=None,
        prompt_strategies:list[str]|None=None,
        system_prompt_file:str="src/prompts/repair/zero/system.md",
        user_prompt_file:str="src/prompts/repair/zero/user.md",
        fewshot_k:int=2,
        fewshot_corpus:str="data/nday_plus.csv",
        max_experiments:int|None=None,
        row_offset:int=0,
        row_limit:int|None=None
    ):
        self.benchmark = Path(dataset_path).stem
        self.cve_mode = cve_mode
        results_dir = Path(save_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        safe_llm = llm.replace("/", "-").replace(":", "-")
        # negative-control runs get their own result file so they never collide
        # with the real-ID run (C1: shuffled / fake CVE-ID variants).
        tag = "" if cve_mode == "real" else f"_cve{cve_mode}"
        self.save_path = results_dir / (output_filename or f"{self.benchmark}{tag}_{safe_llm}.csv")

        self.backend = backend
        self.model = self._select_model(llm, temperature, backend)
        self.pm = PromptManager()
        self.system_prompt_file = system_prompt_file
        self.user_prompt_file = user_prompt_file
        self.dataset_df = self._load_data(dataset_path)
        if row_offset or row_limit is not None:
            end = None if row_limit is None else row_offset + row_limit
            self.dataset_df = self.dataset_df.iloc[row_offset:end].reset_index(drop=True)
        self.columns = self.dataset_df.columns.tolist()
        self.combinations = self._make_combinations(combination_mode)
        self.metrics = Metrics()
        self.prompt_strategy_column = prompt_strategies is not None
        self.prompt_strategies = prompt_strategies or ["zero-shot"]
        self.max_experiments = max_experiments

        # Retrieval-based few-shot (RQ3): exemplars are retrieved from the NDay+
        # ("known") corpus by code similarity. Index is built lazily/per-language
        # and cached inside RetrievalExemplars, so it is constructed once here.
        self.fewshot_k = fewshot_k
        self._retriever = RetrievalExemplars(corpus_path=fewshot_corpus)

        self.async_limit = async_limit

    async def _save_results(self, results_df:pd.DataFrame) -> None:
        await asyncio.to_thread(results_df.to_csv, self.save_path, index=False)

    def _select_model(self, llm:str, temperature:float, backend:str="auto"):
        if backend == "ollama":
            return OLLAMA(llm, temperature)
        if backend == "vllm":
            return VLLM(llm, temperature, think=False)
        if backend == "gpt":
            return GPT(llm, temperature)
        if backend == "claude":
            return CLAUDE(llm, temperature)
        if llm.startswith("gpt"):
            return GPT(llm, temperature)
        if llm.startswith("claude"):
            return CLAUDE(llm, temperature)
        # Any other identifier is treated as a locally-served vLLM model
        # (e.g. Qwen/Qwen3-Coder-30B-A3B-Instruct, google/gemma-4-E4B-it).
        # think=False: disable hybrid reasoning to keep local inference fast.
        return VLLM(llm, temperature, think=False)

    # roll offset for the shuffled negative control: a prime that is coprime to any
    # realistic row count, so every row receives a different real CVE's ID (no fixed pt).
    _CVE_ROLL = 9973

    def _load_data(self, dataset_path: str) -> pd.DataFrame:
        df = pd.read_csv(dataset_path)
        if self.cve_mode == "real":
            return df
        # C1 negative controls: alter ONLY the CVE ID column in memory (no extra files).
        df = df.copy()
        n = len(df)
        if self.cve_mode == "shuffled":          # real-but-wrong identifier
            df["CVE ID"] = pd.Series(df["CVE ID"].values).reindex(
                [(i + self._CVE_ROLL) % n for i in range(n)]).values
        elif self.cve_mode == "fake":            # syntactically valid, nonexistent
            df["CVE ID"] = [f"CVE-2099-9{i:05d}" for i in range(n)]
        else:
            raise ValueError(f"unknown cve_mode: {self.cve_mode}")
        return df

    def _make_combinations(self, mode:str="full") -> list[list[str]]:
        groups = ["CVE ID", "CVE Description",
                  "CWE ID", "CWE Name", "CWE Description", "CWE Example",
                  "Vulnerable Lines"]
        if mode == "breadth":
            # 11 curated combinations for the full-dataset breadth sweep (RQ1/RQ2):
            # None, Full, CVE-group, CWE-group, and each of the 7 single info types.
            cve_group = ["CVE ID", "CVE Description"]
            cwe_group = ["CWE ID", "CWE Name", "CWE Description", "CWE Example"]
            combinations = [[], list(groups), cve_group, cwe_group]
            combinations += [[g] for g in groups]
            return combinations
        if mode == "cveid":
            # Negative-control runs (C1): baseline + CVE-ID only. Meant to be run on
            # the shuffled / fake CVE-ID variant datasets so the CVE-ID lift can be
            # compared against the real-ID lift on the same instances.
            return [[], ["CVE ID"]]
        # mode == "full": all 2^7 = 128 combinations (depth sweep / ablation)
        combinations = [
            list(combo)
            for r in range(len(groups) + 1)
            for combo in comb_tools(groups, r)
        ]
        return combinations
            
    def _build_selected_information(self, row:pd.Series, comb:list[str]) -> str:
        return "\n\n".join(
            f"### {col}:  \n{row[col]}" if col in ["Vulnerable Lines", "CWE Example"]
            else f"### {col}: {row[col]}"
            for col in comb
        )

    def _prompt_files_for_strategy(self, strategy:str) -> tuple[str, str]:
        if strategy in ("zero-shot", "zero_shot"):
            return self.system_prompt_file, self.user_prompt_file
        if strategy in ("few-shot", "few_shot"):
            return (
                "src/prompts/repair/few/system.md",
                "src/prompts/repair/few/user.md",
            )
        if strategy in ("cot", "CoT"):
            return (
                "src/prompts/repair/cot/system.md",
                "src/prompts/repair/cot/user.md",
            )
        raise ValueError(f"unknown prompting strategy: {strategy}")

    def _build_examples_block(self, row:pd.Series, comb:list[str]) -> str:
        """Render the {examples} block for the few-shot strategy.

        Exemplars are the top-k NDay+ rows retrieved by code similarity to `row`
        (self-excluding the target's own CVE). Each exemplar shows the SAME
        auxiliary-info fields as the current combination via
        `_build_selected_information(exemplar, comb)`, and its `Human Patch` as the
        fixed code -- matching the legacy example format.
        """
        exemplars = self._retriever.top_k(
            row, k=self.fewshot_k, exclude_cve=str(row.get("CVE ID", ""))
        )
        blocks = []
        for n, ex in enumerate(exemplars, start=1):
            ex_info = self._build_selected_information(ex, comb)
            blocks.append(
                f"## Example {n}\n\n"
                f"### Vulnerable Code Snippet:\n"
                f"<vulnerable_code>\n{ex['Vulnerable Code']}\n</vulnerable_code>\n\n"
                f"### Additional Vulnerability Information:\n{ex_info}\n\n"
                f"### Fixed Code Snippet:\n"
                f"<fixed_code>\n{ex['Human Patch']}\n</fixed_code>"
            )
        return "\n\n".join(blocks)

    def _render_repair_prompt(self, row:pd.Series, comb:list[str], strategy:str) -> tuple[str, str]:
        system_file, user_file = self._prompt_files_for_strategy(strategy)
        selected_information = self._build_selected_information(row, comb)
        system = self.pm.render(file=system_file)
        render_kwargs = dict(
            file=user_file,
            vulnerable_code=row["Vulnerable Code"],
            selected_information=selected_information,
        )
        if strategy in ("few-shot", "few_shot"):
            render_kwargs["examples"] = self._build_examples_block(row, comb)
        user = self.pm.render(**render_kwargs)
        return system, user
        
    
    async def __task(self, idx:int, row:pd.Series): 
        row_dict = row.to_dict()
        comb = row['Combination'].split("+") if pd.notna(row['Combination']) and row['Combination'] != "None" else []
        strategy = row_dict.get("Prompting Strategy", "zero-shot")
        system, user = self._render_repair_prompt(row, comb, strategy)
        start = perf_counter()
        fixed = await self.model.async_run(system, user)
        output_tokens = self.metrics.token_count(fixed)
        duration = perf_counter() - start
        prompt = f"{system}\n\n{user}"
        return idx, row_dict, comb, fixed, prompt, duration, output_tokens

    async def __evaluation(self, 
        batch:list[asyncio.Task], 
        results_df:pd.DataFrame,
        pbar:tqdm_async
    ) -> None:
        for completed in asyncio.as_completed(batch):
            idx, row_dict, comb, fixed_code, prompt, duration, output_tokens = await completed
            row_dict["LLM Patch"] = fixed_code
            row_dict["Combination"] = "+".join(comb) if comb else "None"
            row_dict["Prompt"] = prompt
            row_dict["#Input Token"] = self.metrics.token_count(prompt)
            row_dict["#Output Token"] = output_tokens
            row_dict["Time (sec)"] = duration

            human_patch=row_dict["Human Patch"]
            language = row_dict.get("Programming Language", "C")
            row_dict["CodeBLEU"] = self.metrics.code_bleu(
                human_patch=human_patch,
                llm_patch=fixed_code,
                language=language
            )
            row_dict["Exact Match"] = self.metrics.exact_match(
                human_patch=human_patch,
                llm_patch=fixed_code,
                language=language
            )
            results_df.loc[idx] = row_dict
            pbar.update(1)

    async def _repair(self, results_df:pd.DataFrame, save_every:int=5000) -> pd.DataFrame:
        pbar = tqdm_async(total=len(results_df), desc="Repairing")
        batch:list[asyncio.Task] = []
        since_save = 0
        try:
            for idx, row in results_df.iterrows():
                if 'LLM Patch' in row and pd.notna(row['LLM Patch']):
                    pbar.update(1)
                    continue
                batch.append(asyncio.create_task(self.__task(idx, row)))
                if len(batch) >= self.async_limit:
                    await self.__evaluation(batch, results_df, pbar)
                    since_save += len(batch)
                    batch.clear()
                    # Periodic checkpoint so a crash loses at most ~save_every cells
                    # (repair otherwise only persists on completion).
                    if since_save >= save_every:
                        await self._save_results(results_df)
                        since_save = 0
            if batch:
                await self.__evaluation(batch, results_df, pbar)
        finally:
            pbar.close()
            await self._save_results(results_df)
        return results_df

    async def _async_run(self, reset:bool=False) -> pd.DataFrame:
        results_df = []
        if self.max_experiments is not None and self.prompt_strategy_column:
            per_strategy = max(1, self.max_experiments // len(self.prompt_strategies))
            remainder = self.max_experiments % len(self.prompt_strategies)
            quotas = {
                strategy: per_strategy + (1 if i < remainder else 0)
                for i, strategy in enumerate(self.prompt_strategies)
            }
            for strategy in self.prompt_strategies:
                added = 0
                for _, row in self.dataset_df.iterrows():
                    for comb in self.combinations:
                        if added >= quotas[strategy]:
                            break
                        row_dict = row.to_dict()
                        row_dict["Prompting Strategy"] = strategy
                        row_dict["Combination"] = "+".join(comb) if comb else "None"
                        results_df.append(row_dict)
                        added += 1
                    if added >= quotas[strategy]:
                        break
        else:
            for _, row in self.dataset_df.iterrows():
                for strategy in self.prompt_strategies:
                    for comb in self.combinations:
                        if self.max_experiments is not None and len(results_df) >= self.max_experiments:
                            break
                        row_dict = row.to_dict()
                        if self.prompt_strategy_column:
                            row_dict["Prompting Strategy"] = strategy
                        row_dict["Combination"] = "+".join(comb) if comb else "None"
                        results_df.append(row_dict)
                    if self.max_experiments is not None and len(results_df) >= self.max_experiments:
                        break
                if self.max_experiments is not None and len(results_df) >= self.max_experiments:
                    break
        results_df = pd.DataFrame(results_df)
        results_df['LLM Patch'] = None
        results_df['Prompt'] = None
        results_df['#Input Token'] = None
        results_df['#Output Token'] = None
        results_df['Time (sec)'] = None
        results_df['CodeBLEU'] = None
        results_df['Exact Match'] = None

        # Canonical output schema.
        ordered_columns = [
            'CVE ID', 'CVE Description',
            'CWE ID', 'CWE Name',
            'CWE Description', 'CWE Example',
            'Programming Language', 'Vulnerable Lines',
            'Vulnerable Code', 'Human Patch', 'LLM Patch',
            'Combination',
        ]
        if self.prompt_strategy_column:
            ordered_columns.append('Prompting Strategy')
        ordered_columns += [
            'Prompt',
            '#Input Token', '#Output Token', 'Time (sec)',
            'CodeBLEU', 'Exact Match'
        ]

        if not reset and os.path.exists(self.save_path):
            existing_df = pd.read_csv(self.save_path, low_memory=False)
            # Keep only columns that belong to the current schema; any extra
            # columns from older result files are discarded so resumed runs stay
            # self-consistent with the schema written below.
            existing_df = existing_df[[c for c in existing_df.columns if c in ordered_columns]]
            results_df = existing_df.combine_first(results_df)

        try:
            results_df = await self._repair(results_df)
        except (asyncio.CancelledError, KeyboardInterrupt):
            await self._save_results(results_df)
            raise

        results_df = results_df[ordered_columns]
        await self._save_results(results_df)
        return results_df

    def run(self, reset:bool=False) -> pd.DataFrame:
        return asyncio.run(self._async_run(reset))
