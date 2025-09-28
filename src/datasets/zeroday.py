import time
import requests
import pandas as pd
from pathlib import Path
from difflib import SequenceMatcher


class ZeroDay:
    def __init__(self, path:str="zeroday_repair/"):
        self.zeroday_df = self.files_to_dataframe(path)
    
    def files_to_dataframe(self, path:str="zeroday_repair/") -> pd.DataFrame:
        ZERODAY_PATH = Path(path)
        data = []
        for folder in ZERODAY_PATH.iterdir():
            if folder.is_dir():
                parts = folder.name.split('___')
                ext = folder.name.split('.')[-1]
                if len(parts) >= 2:
                    cwe_id = parts[0]
                    cve_id = parts[1].replace(f'.{ext}', '')
                    vul_file = folder / f'vul.{ext}'
                    nonvul_file = folder / f'nonvul.{ext}'
                    if vul_file.exists() and nonvul_file.exists():
                        with open(vul_file, 'r', encoding='utf-8', errors='ignore') as vf:
                            vul_code = vf.read()
                        with open(nonvul_file, 'r', encoding='utf-8', errors='ignore') as nvf:
                            nonvul_code = nvf.read()
                        # Use difflib to find the vulnerable lines in nonvul_code that were changed in vul_code
                        vul_lines = []
                        before_lines = nonvul_code.splitlines()
                        after_lines = vul_code.splitlines()
                        sm = SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
                        for tag, i1, i2, j1, j2 in sm.get_opcodes():
                            if tag == 'delete':
                                vul_lines.extend(before_lines[i1:i2])
                            elif tag == 'replace':
                                vul_lines.extend(before_lines[i1:i2])
                        vul_lines = '\n'.join(vul_lines)
                        data.append({
                            'CVE ID': cve_id,
                            'CVE Description': '',
                            'CWE ID': cwe_id,
                            'Vulnerable Lines': vul_lines,
                            'Vulnerable Code': vul_code,
                            'Human Patch': nonvul_code,
                            'Programming Language': ext
                        })
        return pd.DataFrame(data)
    
    def add_cve_description(self):
        from tqdm import tqdm
        tqdm.pandas(desc="CVE Description Fetching", leave=False)
        self.zeroday_df['CVE Description'] = self.zeroday_df['CVE ID'].progress_apply(self.__fetch_cve_description)
    
    def __fetch_cve_description(self, cve_id):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            descriptions = response.json()["vulnerabilities"][0]["cve"]["descriptions"][0]["value"]
            return str(descriptions)
        except Exception as e:
            # print(f"Error fetching description for {cve_id}: {e}")
            # print(url)
            time.sleep(5)  # Wait before retrying
            return self.__fetch_cve_description(cve_id)

    def add_cwe_info(self, CWE_DATA_PATH:str='CWE_data_from_homepage.csv'):
        # Add CWE information from VulMaster
        cwe_info_df = pd.read_csv(CWE_DATA_PATH)
        cwe_info_df = cwe_info_df.rename(columns={'cwe_id': 'CWE ID'})
        cwe_info_df['cwe_name'] = cwe_info_df['cwe_name'].str.split(':').str[1]
        self.zeroday_df = pd.merge(self.zeroday_df, cwe_info_df, on='CWE ID')
    
    def add_cwe_example(self, CWE_EXAMPLE_PATH:str='ChatGPT_generated_fixes_labels.xlxs'):
        # Add CWE fixed code examples from VulMaster
        vulnerable_fixed_df = pd.read_excel(CWE_EXAMPLE_PATH)
        vulnerable_fixed_df = vulnerable_fixed_df.rename(columns={'excluded as there is only non-C examples': 'CWE ID'})
        self.zeroday_df = pd.merge(self.zeroday_df, vulnerable_fixed_df[['CWE ID', 'Correct']], on='CWE ID')
    
    def reorder_columns(self):
        # Rename & Reorder Columns and delete duplicates dataset
        self.zeroday_df = self.zeroday_df.rename(columns={
            'cwe_name': 'CWE Name', 
            'description': 'CWE Description', 
            'Correct': 'CWE Example',
        })
        self.zeroday_df = self.zeroday_df[[
            'CVE ID', 'CVE Description', 
            'CWE ID', 'CWE Name', 
            'CWE Description', 'CWE Example', 
            'Programming Language', 'Vulnerable Lines', 
            'Vulnerable Code', 'Human Patch']]
    
    def drop_na_duplicates(self):
        self.zeroday_df = self.zeroday_df.dropna()
        self.zeroday_df = self.zeroday_df.drop_duplicates().reset_index(drop=True)
    
    def save_to_csv(self, save_path:str='zeroday.csv'):
        self.zeroday_df.to_csv(save_path, index=False)
        
    def run(self, CWE_DATA_PATH:str='CWE_data_from_homepage.csv', CWE_EXAMPLE_PATH:str='ChatGPT_generated_fixes_labels.xlxs', 
            save_path:str='zeroday.csv', save:bool=True) -> pd.DataFrame:
        self.add_cve_description()
        self.add_cwe_info(CWE_DATA_PATH)
        self.add_cwe_example(CWE_EXAMPLE_PATH)
        self.reorder_columns()
        self.drop_na_duplicates()
        if save:
            self.save_to_csv(save_path)
        return self.zeroday_df
