import sqlite3
import pandas as pd
from ..utils import FunctionParser


class CVEfixes:
    def __init__(self, path:str="CVEfixes.db"):
        conn = sqlite3.connect(path)
        self.method_change_df = pd.read_sql_query("SELECT * FROM method_change", conn)
        self.file_change_df = pd.read_sql_query("SELECT * FROM file_change", conn)
        self.fixes_df = pd.read_sql_query("SELECT * FROM fixes", conn)
        self.cve_df = pd.read_sql_query("SELECT * FROM cve", conn)
        self.cwe_classification_df = pd.read_sql_query("SELECT * FROM cwe_classification", conn)
        self.cwe_df = pd.read_sql_query("SELECT * FROM cwe", conn)
        conn.close()
    
    def filter_rename_columns(self):
        # Filter and rename columns
        self.f_method_change_df = self.method_change_df[
            ['file_change_id', 'code', 'name', 'before_change', 'start_line', 'end_line']]
        self.f_method_change_df = self.f_method_change_df[
            self.f_method_change_df['before_change'] == "True"]
        self.f_method_change_df = self.f_method_change_df.rename(
            columns={'code': 'Vulnerable Code'})

        self.f_file_change_df = self.file_change_df[
            ['file_change_id', 'hash', 'programming_language', 'diff_parsed', 'code_after']]
        self.f_file_change_df = self.f_file_change_df[
            self.f_file_change_df['programming_language'].isin(['C', 'C++', 'c', 'c++', 'cpp'])]

        self.f_fixes_df = self.fixes_df[['hash', 'cve_id']]
        self.f_fixes_df = self.f_fixes_df.rename(columns={'cve_id': 'CVE ID'})

        self.f_cve_df = self.cve_df[['cve_id', 'description']]
        self.f_cve_df = self.f_cve_df.rename(columns={
            'cve_id': 'CVE ID',
            'description': 'CVE Description'})

        self.f_cwe_classification_df = self.cwe_classification_df[['cve_id', 'cwe_id']]
        self.f_cwe_classification_df = self.f_cwe_classification_df.rename(
            columns={'cve_id': 'CVE ID', 'cwe_id': 'CWE ID'})

        self.f_cwe_df = self.cwe_df[['cwe_id']]
        self.f_cwe_df = self.f_cwe_df.rename(columns={'cwe_id': 'CWE ID'})

        del self.method_change_df, self.file_change_df, self.fixes_df, self.cve_df, self.cwe_classification_df, self.cwe_df

    def merge_dataframes(self):
        # Merge dataframes
        self.cvefixes_df = pd.merge(self.f_method_change_df, self.f_file_change_df, on='file_change_id')
        self.cvefixes_df = pd.merge(self.cvefixes_df, self.f_fixes_df, on='hash')
        self.cvefixes_df = pd.merge(self.cvefixes_df, self.f_cve_df, on='CVE ID')
        self.cvefixes_df = pd.merge(self.cvefixes_df, self.f_cwe_classification_df, on='CVE ID')
        self.cvefixes_df = pd.merge(self.cvefixes_df, self.f_cwe_df, on='CWE ID')
        
        del self.f_method_change_df, self.f_file_change_df, self.f_fixes_df, self.f_cve_df, self.f_cwe_classification_df, self.f_cwe_df
    
    def parse_description(self):
        from tqdm import tqdm
        tqdm.pandas(desc="CVE Description", leave=False)
        self.cvefixes_df['CVE Description'] = self.cvefixes_df['CVE Description'].progress_apply(self.__parse_description)
    
    def __parse_description(self, desc):
        try:
            desc_list = eval(desc)
            if isinstance(desc_list, list) and len(desc_list) > 0:
                return desc_list[0].get('value', desc)
        except: pass
        return desc
    
    def add_fixed_function_column(self):
        # Make 'Human Patch' column using FunctionParser
        from tqdm import tqdm
        tqdm.pandas(desc="Function Parsing", leave=False)
        self.cvefixes_df['Human Patch'] = self.cvefixes_df.progress_apply(self.__extract_fixed_function, axis=1)
    
    def __extract_fixed_function(self, row):
        language = row.get('programming_language')
        code_after = row.get('code_after')
        func_name = row.get('name')

        if not isinstance(language, str) or not isinstance(code_after, str) or not isinstance(func_name, str):
            return None

        parser = FunctionParser(language=language)
        fixed_code = parser.run(code_after, func_name)
        return fixed_code
    
    def add_changed_lines(self):
        # Extract lines before and after the change
        from tqdm import tqdm
        tqdm.pandas(desc="Vulnerable Lines", leave=False)
        self.cvefixes_df[['Vulnerable Lines']] = self.cvefixes_df.progress_apply(self.__extract_relevant_lines, axis=1)
    
    def __extract_relevant_lines(self, row):
        try:
            diff = eval(row['diff_parsed'])
        except (ValueError, SyntaxError, TypeError):
            return pd.Series({'Vulnerable Lines': ''})
        if isinstance(diff, dict):
            deleted = diff.get('deleted') or []
        else:  # fall back if the diff is stored as a list of hunks
            deleted = []
            for hunk in diff:
                deleted.extend(hunk.get('deleted', []))
        start = row['start_line']
        end = row['end_line']
        if pd.isna(start) or pd.isna(end):
            return pd.Series({'Vulnerable Lines': ''})
        start = int(start)
        end = int(end)
        def collect(lines):
            return '\n'.join(
                line for line_num, line in lines
                if start <= int(line_num) <= end
            )
        return pd.Series({'Vulnerable Lines': collect(deleted)})
    
    def add_cwe_info(self, CWE_DATA_PATH:str='CWE_data_from_homepage.csv'):
        # Add CWE information from VulMaster
        cwe_info_df = pd.read_csv(CWE_DATA_PATH)
        cwe_info_df = cwe_info_df.rename(columns={
            'cwe_id': 'CWE ID',
            'cwe_name': 'CWE Name',
            'description': 'CWE Description'})
        cwe_info_df['CWE Name'] = cwe_info_df['CWE Name'].str.split(':').str[1]
        self.cvefixes_df = pd.merge(self.cvefixes_df, cwe_info_df, on='CWE ID')
    
    def add_cwe_example(self, CWE_EXAMPLE_PATH:str='ChatGPT_generated_fixes_labels.xlxs'):
        # Add CWE fixed code examples from VulMaster
        vulnerable_fixed_df = pd.read_excel(CWE_EXAMPLE_PATH)
        vulnerable_fixed_df = vulnerable_fixed_df.rename(columns={
            'excluded as there is only non-C examples': 'CWE ID',
            'Correct': 'CWE Example'})
        self.cvefixes_df = self.cvefixes_df.rename(columns={'cwe_id': 'CWE ID'})
        self.cvefixes_df = pd.merge(self.cvefixes_df, vulnerable_fixed_df, on='CWE ID')
    
    def reorder_columns(self):
        # Reorder columns and delete duplicates dataset
        self.cvefixes_df = self.cvefixes_df.rename(columns={
            'programming_language': 'Programming Language'
        })
        self.cvefixes_df = self.cvefixes_df[[
            'CVE ID', 'CVE Description', 
            'CWE ID', 'CWE Name', 
            'CWE Description', 'CWE Example', 
            'Programming Language', 'Vulnerable Lines', 
            'Vulnerable Code', 'Human Patch']]
    
    def drop_na_duplicates(self):
        self.cvefixes_df = self.cvefixes_df.dropna()
        self.cvefixes_df = self.cvefixes_df.drop_duplicates().reset_index(drop=True)
    
    def save_to_csv(self, save_path:str='cvefixes.csv'):
        self.cvefixes_df.to_csv(save_path, index=False)
        
    def run(self, CWE_DATA_PATH:str='CWE_data_from_homepage.csv', CWE_EXAMPLE_PATH:str='ChatGPT_generated_fixes_labels.xlxs', 
            save_path:str='cvefixes.csv', save:bool=True) -> pd.DataFrame:
        self.filter_rename_columns()
        self.merge_dataframes()
        self.parse_description()
        self.add_fixed_function_column()
        self.add_changed_lines()
        self.add_cwe_info(CWE_DATA_PATH)
        self.add_cwe_example(CWE_EXAMPLE_PATH)
        self.reorder_columns()
        self.drop_na_duplicates()
        if save:
            self.save_to_csv(save_path)
        return self.cvefixes_df
