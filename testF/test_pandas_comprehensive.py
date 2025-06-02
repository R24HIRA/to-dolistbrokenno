"""
Comprehensive pandas mutation test file with various operations and edge cases
"""
import pandas as pd
import numpy as np

# Basic DataFrame setup
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6], 'C': [7, 8, 9]})
df2 = pd.DataFrame({'X': [10, 20], 'Y': [30, 40]})

# 1. Basic mutations
df.drop('A', axis=1)  # HIGH severity
df.drop('B', axis=1, inplace=True)  # CRITICAL severity (inplace=True)
df.dropna()  # MEDIUM severity
df.dropna(inplace=True)  # HIGH severity (inplace=True)
df.drop_duplicates()  # LOW severity
df.drop_duplicates(inplace=True)  # MEDIUM severity (inplace=True)

# 2. Chain mutations (multiple operations in sequence)
result = df.drop('A', axis=1).dropna().drop_duplicates()
df.drop('B', axis=1).fillna(0).drop_duplicates(inplace=True)

# 3. Complex chain mutations with method chaining
processed_df = (df
                .drop(['A', 'B'], axis=1)
                .dropna()
                .drop_duplicates()
                .fillna(method='ffill'))

# 4. Mutations with variables and expressions
columns_to_drop = ['A', 'C']
df.drop(columns_to_drop, axis=1)
df.drop(df.columns[0], axis=1)
df.drop(df.columns[:2], axis=1)

# 5. Conditional mutations
if len(df) > 0:
    df.drop('A', axis=1, inplace=True)
    df.dropna(inplace=True)

# 6. Loop-based mutations
for col in ['A', 'B']:
    df.drop(col, axis=1, inplace=True)

# 7. Function-based mutations
def clean_dataframe(data):
    return data.drop('A', axis=1).dropna().drop_duplicates()

def modify_inplace(data):
    data.drop('B', axis=1, inplace=True)
    data.fillna(0, inplace=True)
    return data

# 8. Class-based mutations
class DataProcessor:
    def __init__(self, df):
        self.df = df
    
    def clean(self):
        self.df.drop('A', axis=1, inplace=True)
        self.df.dropna(inplace=True)
        return self.df
    
    def process_chain(self):
        return self.df.drop('B', axis=1).fillna(0).drop_duplicates()

# 9. Edge cases with different parameters
df.drop(index=[0, 1])  # Drop by index
df.drop(columns=['A'])  # Drop by columns parameter
df.dropna(subset=['A', 'B'])  # Drop with subset
df.dropna(how='all')  # Drop with how parameter
df.drop_duplicates(subset=['A'])  # Drop duplicates with subset
df.fillna({'A': 0, 'B': 1})  # Fill with dictionary
df.fillna(method='bfill', inplace=True)  # Fill with method and inplace

# 10. Nested function calls
result = df.drop('A', axis=1).dropna().reset_index(drop=True)
df.loc[df['A'] > 1].drop('B', axis=1, inplace=True)

# 11. Assignment with mutations
new_df = df.drop('A', axis=1)
modified_df = df.dropna().drop_duplicates()

# 12. Multiple DataFrames
df2.drop('X', axis=1, inplace=True)
combined = pd.concat([df.drop('A', axis=1), df2.dropna()])

# 13. Edge case: Empty operations
try:
    df.drop([], axis=1)  # Empty list
    df.drop('NonExistent', axis=1, errors='ignore')  # Non-existent column
except:
    pass

# 14. Complex expressions
mask = df['A'] > 1
filtered_df = df[mask].drop('B', axis=1).fillna(0)

# 15. Lambda functions with mutations
df.apply(lambda x: x.drop('A', axis=1) if len(x) > 0 else x) 