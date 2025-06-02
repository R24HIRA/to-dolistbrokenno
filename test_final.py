import pandas as pd; df = pd.DataFrame({'A': [1, 2], 'B': [3, 4]}); result = df.drop('A', axis=1).dropna().drop_duplicates()
