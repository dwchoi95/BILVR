import os
import asyncio
from pathlib import Path
from time import perf_counter
import pandas as pd
from tqdm.asyncio import tqdm as tqdm_async
from itertools import combinations as comb_tools

from .validation import Validation
from ..llms import GPT, CLAUDE
from ..prompts import PromptManager


class Fixer:
    def __init__(
        self, 
        llm:str, 
        temperature:float,
        dataset_path:str, 
        save_dir:str="results", 
        async_limit:int=1000,
        system_prompt_file:str="src/prompts/repair/system.md",
        user_prompt_file:str="src/prompts/repair/user.md"
    ):
        self.benchmark = Path(dataset_path).stem
        results_dir = Path(save_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        self.save_path = results_dir / f"{self.benchmark}_{llm}.csv"
        
        self.model = self._select_model(llm, temperature)
        self.pm = PromptManager()
        self.system = self.pm.render(file=system_prompt_file)
        self.user_prompt_file = user_prompt_file
        self.dataset_df = self._load_data(dataset_path)
        self.columns = self.dataset_df.columns.tolist()
        self.combinations = self._make_combinations()
        self.validation = Validation()
        
        self.async_limit = async_limit

    async def _save_results(self, results_df:pd.DataFrame) -> None:
        await asyncio.to_thread(results_df.to_csv, self.save_path, index=False)

    def _select_model(self, llm:str, temperature:float):
        if llm.startswith("gpt"):
            return GPT(llm, temperature)
        if llm.startswith("claude"):
            return CLAUDE(llm, temperature)
        raise ValueError(f"Unsupported model: {llm}")

    def _load_data(self, dataset_path: str) -> pd.DataFrame:
        return pd.read_csv(dataset_path)

    def _make_combinations(self) -> list[list[str]]:
        groups = ["CVE ID", "CVE Description", 
                  "CWE ID", "CWE Name", "CWE Description", "CWE Example", 
                  "Vulnerable Lines"]
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
        
    
    async def __task(self, idx:int, row:pd.Series): 
        row_dict = row.to_dict()
        comb = row['Combination'].split("+") if pd.notna(row['Combination']) and row['Combination'] != "None" else []
        selected_information = self._build_selected_information(row, comb)
        user = self.pm.render(
            file=self.user_prompt_file,
            vulnerable_code=row["Vulnerable Code"],
            selected_information=selected_information,
        )
        start = perf_counter()
        fixed = await self.model.async_run(self.system, user)
        duration = perf_counter() - start
        prompt = f"{self.system}\n\n{user}"
        return idx, row_dict, comb, fixed, prompt, duration

    async def __evaluation(self, 
        batch:list[asyncio.Task], 
        results_df:pd.DataFrame,
        pbar:tqdm_async
    ) -> None:
        for completed in asyncio.as_completed(batch):
            idx, row_dict, comb, fixed_code, prompt, duration = await completed
            row_dict["LLM Patch"] = fixed_code
            row_dict["Combination"] = "+".join(comb) if comb else "None"
            row_dict["Prompt"] = prompt
            row_dict["#Input Token"] = self.validation.token_count(prompt)
            row_dict["#Output Token"] = self.validation.token_count(fixed_code)
            row_dict["Time (sec)"] = duration
            
            human_patch=row_dict["Human Patch"]
            language = row_dict.get("Programming Language", "C")
            row_dict["CodeBLEU"] = self.validation.code_bleu(
                human_patch=human_patch,
                llm_patch=fixed_code,
                language=language
            )
            row_dict["Exact Match"] = self.validation.exact_match(
                human_patch=human_patch,
                llm_patch=fixed_code,
                language=language
            )
            results_df.loc[idx] = row_dict
            pbar.update(1)

    async def _repair(self, results_df:pd.DataFrame) -> pd.DataFrame:
        pbar = tqdm_async(total=len(results_df), desc="Repairing")
        batch:list[asyncio.Task] = []
        try:
            for idx, row in results_df.iterrows():
                if 'LLM Patch' in row and pd.notna(row['LLM Patch']):
                    pbar.update(1)
                    continue
                batch.append(asyncio.create_task(self.__task(idx, row)))
                if len(batch) >= self.async_limit:
                    await self.__evaluation(batch, results_df, pbar)
                    batch.clear()
            if batch:
                await self.__evaluation(batch, results_df, pbar)
        finally:
            pbar.close()
            await self._save_results(results_df)
        return results_df


    async def _validate_task(self, idx:int, row:pd.Series):
        row_dict = row.to_dict()
        human_eval = await self.validation.llm_eval(
            vulnerable_code=row_dict["Vulnerable Code"],
            additional_information=self._build_selected_information(row_dict, self.columns),
            human_patch=row_dict["Human Patch"],
            llm_patch=row_dict["LLM Patch"]
        )
        return idx, row_dict, human_eval
                
    async def __validate_run(self,
        batch:list[asyncio.Task],
        results_df:pd.DataFrame,
        pbar:tqdm_async
    ) -> None:
        for completed in asyncio.as_completed(batch):
            idx, row_dict, human_eval = await completed
            row_dict = dict(row_dict)
            row_dict["LLM Evaluation"] = human_eval
            results_df.loc[idx] = row_dict
            pbar.update(1)
    
    async def _validate(self, results_df:pd.DataFrame) -> pd.DataFrame:
        pbar = tqdm_async(total=len(results_df), desc="Validation")
        batch:list[asyncio.Task] = []
        try:
            for idx, row in results_df.iterrows():
                if 'LLM Evaluation' in row and pd.notna(row['LLM Evaluation']) and row['LLM Evaluation'] in [True, False, "true", "false", "True", "False"]:
                    pbar.update(1)
                    continue
                else:
                    batch.append(asyncio.create_task(self._validate_task(idx, row)))
                    if len(batch) >= self.async_limit:
                        await self.__validate_run(batch, results_df, pbar)
                        batch.clear()
            if batch:
                await self.__validate_run(batch, results_df, pbar)
        finally:
            pbar.close()
            await self._save_results(results_df)
        return results_df
                
    async def _async_run(self, reset:bool=False) -> pd.DataFrame:
        results_df = []
        for _, row in self.dataset_df.iterrows():
            for comb in self.combinations:
                row_dict = row.to_dict()
                row_dict["Combination"] = "+".join(comb) if comb else "None"
                results_df.append(row_dict)
        results_df = pd.DataFrame(results_df)
        results_df['LLM Patch'] = None
        results_df['Prompt'] = None
        results_df['#Input Token'] = None
        results_df['#Output Token'] = None
        results_df['Time (sec)'] = None
        results_df['CodeBLEU'] = None
        results_df['Exact Match'] = None
        results_df['LLM Evaluation'] = None
        
        if not reset and os.path.exists(self.save_path):
            existing_df = pd.read_csv(self.save_path, low_memory=False)
            if 'LLM Evaluation' not in existing_df.columns:
                existing_df['LLM Evaluation'] = None
            results_df = existing_df.combine_first(results_df)
            
        try:
            # Repair
            results_df = await self._repair(results_df)
            
            # Validation
            results_df = await self._validate(results_df)
        except (asyncio.CancelledError, KeyboardInterrupt):
            await self._save_results(results_df)
            raise
        
        # Reorder Columns
        results_df = results_df[[
            'CVE ID', 'CVE Description', 
            'CWE ID', 'CWE Name', 
            'CWE Description', 'CWE Example', 
            'Programming Language', 'Vulnerable Lines', 
            'Vulnerable Code', 'Human Patch', 'LLM Patch', 
            'Combination', 'Prompt',
            '#Input Token', '#Output Token', 'Time (sec)',
            'CodeBLEU', 'Exact Match', 'LLM Evaluation'
        ]]
        await self._save_results(results_df)
        return results_df

    def run(self, reset:bool=False) -> pd.DataFrame:
        return asyncio.run(self._async_run(reset))
