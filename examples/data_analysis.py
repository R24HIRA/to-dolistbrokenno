"""
Example data analysis script with various mutation operations.
This file demonstrates the types of operations that DataMut can detect.
"""

import pandas as pd
import numpy as np
import sqlite3

# Load some sample data
df = pd.read_csv("data.csv")
arr = np.array([1, 2, 3, 4, 5])

# Pandas operations that DataMut will detect
print("Original DataFrame shape:", df.shape)

# HIGH severity - removes data
df_cleaned = df.drop(columns=['unnecessary_col'])  # HIGH
df_no_dupes = df.drop_duplicates()  # HIGH
df_no_na = df.dropna()  # HIGH

# CRITICAL severity - inplace operations
df.drop(columns=['temp_col'], inplace=True)  # CRITICAL
df.fillna(0, inplace=True)  # CRITICAL

# MEDIUM severity - data transformation
df_merged = pd.merge(df, df_cleaned, on='id')  # MEDIUM
df_pivoted = df.pivot(index='date', columns='category', values='amount')  # MEDIUM

# NumPy operations
print("Original array:", arr)

# HIGH severity - array modification
arr_modified = np.delete(arr, 0)  # HIGH
arr_reshaped = np.reshape(arr, (5, 1))  # MEDIUM
arr_sorted = np.sort(arr)  # LOW

# SQL operations in strings
conn = sqlite3.connect("database.db")

# CRITICAL severity SQL operations
delete_query = """
    DELETE FROM users 
    WHERE last_login < '2023-01-01'
"""  # CRITICAL

update_query = """
    UPDATE products 
    SET price = price * 1.1 
    WHERE category = 'electronics'
"""  # HIGH

# MEDIUM severity SQL operations
insert_query = """
    INSERT INTO audit_log (action, timestamp, user_id)
    VALUES ('data_export', NOW(), 123)
"""  # MEDIUM

# Execute queries (DataMut will detect these in the strings above)
cursor = conn.cursor()
cursor.execute(delete_query)
cursor.execute(update_query)
cursor.execute(insert_query)
conn.commit()

print("Data analysis complete!") 