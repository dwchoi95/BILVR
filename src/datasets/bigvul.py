import pandas as pd


class BigVul:
    def __init__(self, path:str="MSR_data_cleaned.csv"):
        self.big_vul_df = pd.read_csv(path)
        self.big_vul_df = self.big_vul_df[self.big_vul_df['vul'] == 1]
        self.big_vul_df = self.big_vul_df[['CVE ID', 'Summary', 'CWE ID', 'lines_before', 'lines_after', 'func_before', 'func_after', 'lang']]
    
    def add_cwe_info(self, CWE_DATA_PATH:str='CWE_data_from_homepage.csv'):
        # Add CWE information from VulMaster
        cwe_info_df = pd.read_csv(CWE_DATA_PATH)
        cwe_info_df = cwe_info_df.rename(columns={'cwe_id': 'CWE ID'})
        cwe_info_df['cwe_name'] = cwe_info_df['cwe_name'].str.split(':').str[1]
        self.big_vul_df = pd.merge(self.big_vul_df, cwe_info_df, on='CWE ID')
    
    def add_cwe_example(self, CWE_EXAMPLE_PATH:str='ChatGPT_generated_fixes_labels.xlxs'):
        # Add CWE fixed code examples from VulMaster
        vulnerable_fixed_df = pd.read_excel(CWE_EXAMPLE_PATH)
        vulnerable_fixed_df = vulnerable_fixed_df.rename(columns={'excluded as there is only non-C examples': 'CWE ID'})
        self.big_vul_df = pd.merge(self.big_vul_df, vulnerable_fixed_df[['CWE ID', 'Correct']], on='CWE ID')
    
    def reorder_columns(self):
        # Rename & Reorder Columns and delete duplicates dataset
        self.big_vul_df = self.big_vul_df.rename(columns={
            'Summary': 'CVE Description',
            'cwe_name': 'CWE Name', 
            'description': 'CWE Description', 
            'Correct': 'CWE Example',
            'lines_before': 'Vulnerable Lines',
            'func_before': 'Vulnerable Code',
            'func_after': 'Human Patch',
            'lang': 'Programming Language'
        })
        self.big_vul_df = self.big_vul_df[[
            'CVE ID', 'CVE Description', 
            'CWE ID', 'CWE Name', 
            'CWE Description', 'CWE Example', 
            'Programming Language', 'Vulnerable Lines', 
            'Vulnerable Code', 'Human Patch']]
    
    def drop_na_duplicates(self):
        self.big_vul_df = self.big_vul_df.dropna()
        self.big_vul_df = self.big_vul_df.drop_duplicates().reset_index(drop=True)
    
    def save_to_csv(self, save_path:str='big_vul.csv'):
        self.big_vul_df.to_csv(save_path, index=False)
        
    def run(self, CWE_DATA_PATH:str='CWE_data_from_homepage.csv', CWE_EXAMPLE_PATH:str='ChatGPT_generated_fixes_labels.xlxs', 
            save_path:str='big_vul.csv', save:bool=True) -> pd.DataFrame:
        self.add_cwe_info(CWE_DATA_PATH)
        self.add_cwe_example(CWE_EXAMPLE_PATH)
        self.reorder_columns()
        self.drop_na_duplicates()
        if save:
            self.save_to_csv(save_path)
        return self.big_vul_df