"""
Mixed operations test file combining pandas, numpy, and SQL with complex chains
"""
import pandas as pd
import numpy as np
import sqlite3

# Setup
df = pd.DataFrame({'A': [1, 2, 3, 4, 5], 'B': [6, 7, 8, 9, 10]})
arr = np.array([1, 2, 3, 4, 5])
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

# 1. Mixed pandas and numpy operations
def mixed_pandas_numpy():
    # Chain pandas and numpy operations
    result = df.drop('A', axis=1)  # Pandas mutation
    arr_result = np.delete(arr, 0)  # Numpy mutation
    
    # Complex chain with both
    processed = df.dropna().drop_duplicates()  # Multiple pandas mutations
    arr_processed = np.append(np.delete(arr, 0), [99, 100])  # Multiple numpy mutations
    
    return result, arr_result, processed, arr_processed

# 2. Mixed pandas and SQL operations
def mixed_pandas_sql():
    # Pandas operations followed by SQL
    cleaned_df = df.drop('A', axis=1).dropna()  # Pandas chain
    cursor.execute("DELETE FROM temp_table WHERE processed = 1")  # SQL mutation
    
    # SQL followed by pandas
    cursor.execute("UPDATE statistics SET last_updated = datetime('now')")  # SQL mutation
    final_df = cleaned_df.drop_duplicates(inplace=True)  # Pandas mutation with inplace
    
    return cleaned_df

# 3. Mixed numpy and SQL operations
def mixed_numpy_sql():
    # Numpy operations with SQL
    modified_arr = np.delete(arr, [0, 1])  # Numpy mutation
    cursor.execute("INSERT INTO processed_arrays (data) VALUES (?)", (str(modified_arr),))  # SQL mutation
    
    # Chain operations
    result_arr = np.append(np.insert(modified_arr, 0, 999), [888])  # Multiple numpy mutations
    cursor.execute("DELETE FROM old_arrays WHERE created_at < '2023-01-01'")  # SQL mutation
    
    return result_arr

# 4. Triple mixed operations (pandas + numpy + SQL)
def triple_mixed_operations():
    # Start with pandas
    df_step1 = df.drop('A', axis=1)  # Pandas mutation
    
    # Convert to numpy and modify
    arr_from_df = df_step1.values.flatten()
    arr_step1 = np.delete(arr_from_df, 0)  # Numpy mutation
    
    # Log to database
    cursor.execute("INSERT INTO operation_log (step, data_size) VALUES (?, ?)", 
                   ('numpy_delete', len(arr_step1)))  # SQL mutation
    
    # Back to pandas
    new_df = pd.DataFrame({'values': arr_step1})
    final_df = new_df.dropna().drop_duplicates()  # Multiple pandas mutations
    
    # Final cleanup in database
    cursor.execute("DELETE FROM temp_operations WHERE completed = 1")  # SQL mutation
    
    return final_df

# 5. Complex chain with all three libraries
class DataProcessor:
    def __init__(self):
        self.df = df.copy()
        self.arr = arr.copy()
        self.conn = conn
        self.cursor = cursor
    
    def process_pipeline(self):
        # Step 1: Pandas preprocessing
        self.df = self.df.drop('A', axis=1).dropna()  # Pandas chain
        
        # Step 2: Convert to numpy for numerical operations
        values = self.df.values.flatten()
        processed_values = np.delete(np.append(values, [999]), 0)  # Numpy chain
        
        # Step 3: Log intermediate results
        self.cursor.execute("INSERT INTO processing_steps (step, size) VALUES (?, ?)", 
                           ('numpy_processing', len(processed_values)))  # SQL mutation
        
        # Step 4: Back to pandas for final processing
        result_df = pd.DataFrame({'processed': processed_values})
        result_df = result_df.drop_duplicates().fillna(0)  # Pandas chain
        
        # Step 5: Final database update
        self.cursor.execute("UPDATE processing_status SET completed = 1 WHERE job_id = ?", (1,))  # SQL mutation
        
        return result_df

# 6. Conditional mixed operations
def conditional_mixed_processing(condition_type):
    if condition_type == 'pandas_heavy':
        # Heavy pandas processing
        result = (df.drop('A', axis=1)
                   .dropna()
                   .drop_duplicates()
                   .fillna(0))  # Long pandas chain
        cursor.execute("INSERT INTO pandas_operations (type) VALUES ('heavy')")  # SQL log
        
    elif condition_type == 'numpy_heavy':
        # Heavy numpy processing
        result = np.append(
            np.delete(
                np.insert(arr, 0, 999), 
                [1, 2]
            ), 
            [888, 777]
        )  # Complex numpy chain
        cursor.execute("INSERT INTO numpy_operations (type) VALUES ('heavy')")  # SQL log
        
    else:
        # Mixed processing
        df_result = df.drop('A', axis=1)  # Pandas
        arr_result = np.delete(arr, 0)  # Numpy
        cursor.execute("DELETE FROM mixed_results WHERE old = 1")  # SQL
        result = (df_result, arr_result)
    
    return result

# 7. Loop-based mixed operations
def loop_mixed_operations():
    results = []
    
    for i in range(3):
        # Pandas operation in loop
        temp_df = df.drop(df.columns[i % len(df.columns)], axis=1)  # Pandas mutation
        
        # Numpy operation in loop
        temp_arr = np.delete(arr, i)  # Numpy mutation
        
        # SQL operation in loop
        cursor.execute(f"INSERT INTO loop_results (iteration, df_cols, arr_size) VALUES (?, ?, ?)", 
                      (i, len(temp_df.columns), len(temp_arr)))  # SQL mutation
        
        results.append((temp_df, temp_arr))
    
    # Final cleanup
    cursor.execute("DELETE FROM loop_results WHERE iteration < 2")  # SQL mutation
    
    return results

# 8. Error handling with mixed operations
def error_handling_mixed():
    try:
        # Risky pandas operation
        risky_df = df.drop('NonExistent', axis=1, errors='ignore')  # Pandas mutation
        
        # Risky numpy operation
        risky_arr = np.delete(arr, 100) if len(arr) > 100 else np.delete(arr, 0)  # Numpy mutation
        
        # Log success
        cursor.execute("INSERT INTO operation_status (status) VALUES ('success')")  # SQL mutation
        
    except Exception as e:
        # Error recovery
        backup_df = df.dropna()  # Pandas mutation
        backup_arr = np.append(arr, [0])  # Numpy mutation
        cursor.execute("INSERT INTO error_log (error) VALUES (?)", (str(e),))  # SQL mutation
        
        return backup_df, backup_arr

# 9. Nested function calls with mixed operations
def nested_mixed_calls():
    def inner_pandas_processing(data):
        return data.drop(data.columns[0], axis=1).dropna()  # Pandas chain
    
    def inner_numpy_processing(data):
        return np.append(np.delete(data, 0), [999])  # Numpy chain
    
    def inner_sql_logging(message):
        cursor.execute("INSERT INTO nested_log (message) VALUES (?)", (message,))  # SQL mutation
    
    # Use nested functions
    processed_df = inner_pandas_processing(df)
    processed_arr = inner_numpy_processing(arr)
    inner_sql_logging("nested_processing_complete")
    
    return processed_df, processed_arr

# 10. Lambda functions with mixed operations
def lambda_mixed_operations():
    # Lambda with pandas
    pandas_lambda = lambda x: x.drop(x.columns[0], axis=1) if len(x.columns) > 1 else x
    result_df = pandas_lambda(df)  # Pandas mutation in lambda
    
    # Lambda with numpy
    numpy_lambda = lambda x: np.delete(x, 0) if len(x) > 0 else x
    result_arr = numpy_lambda(arr)  # Numpy mutation in lambda
    
    # SQL logging
    cursor.execute("INSERT INTO lambda_operations (pandas_cols, numpy_size) VALUES (?, ?)", 
                  (len(result_df.columns), len(result_arr)))  # SQL mutation
    
    return result_df, result_arr

# 11. Complex data flow with all three libraries
def complex_data_flow():
    # Stage 1: Initial pandas processing
    stage1 = df.drop('A', axis=1).dropna()  # Pandas mutations
    cursor.execute("INSERT INTO flow_stages (stage, description) VALUES (1, 'pandas_initial')")  # SQL log
    
    # Stage 2: Convert to numpy for mathematical operations
    values = stage1.values.flatten()
    stage2 = np.delete(np.append(values, values.mean()), 0)  # Numpy mutations
    cursor.execute("INSERT INTO flow_stages (stage, description) VALUES (2, 'numpy_math')")  # SQL log
    
    # Stage 3: Back to pandas for final formatting
    stage3_df = pd.DataFrame({'final_values': stage2})
    stage3 = stage3_df.drop_duplicates().fillna(stage2.mean())  # Pandas mutations
    cursor.execute("UPDATE flow_stages SET completed = 1")  # SQL mutation
    
    # Stage 4: Archive results
    cursor.execute("INSERT INTO archived_results SELECT * FROM current_results")  # SQL mutation
    cursor.execute("DELETE FROM current_results WHERE archived = 1")  # SQL mutation
    
    return stage3

# 12. Performance testing with mixed operations
def performance_mixed_operations():
    import time
    
    start_time = time.time()
    
    # Batch pandas operations
    for i in range(10):
        temp_df = df.drop(df.columns[i % len(df.columns)], axis=1)  # Pandas mutations
    
    # Batch numpy operations
    for i in range(10):
        temp_arr = np.delete(arr, i % len(arr))  # Numpy mutations
    
    # Batch SQL operations
    for i in range(10):
        cursor.execute("INSERT INTO performance_test (iteration, timestamp) VALUES (?, ?)", 
                      (i, time.time()))  # SQL mutations
    
    end_time = time.time()
    
    # Log performance results
    cursor.execute("INSERT INTO performance_results (duration) VALUES (?)", 
                  (end_time - start_time,))  # SQL mutation
    
    # Cleanup performance data
    cursor.execute("DELETE FROM performance_test WHERE timestamp < ?", 
                  (start_time,))  # SQL mutation

# 13. Edge case: Empty data with mixed operations
def empty_data_mixed():
    empty_df = pd.DataFrame()
    empty_arr = np.array([])
    
    try:
        # These should handle empty data gracefully
        result_df = empty_df.dropna() if not empty_df.empty else empty_df  # Pandas
        result_arr = np.append(empty_arr, [1]) if len(empty_arr) == 0 else np.delete(empty_arr, 0)  # Numpy
        cursor.execute("INSERT INTO empty_data_log (status) VALUES ('handled')")  # SQL
        
    except Exception as e:
        cursor.execute("INSERT INTO error_log (error) VALUES (?)", (str(e),))  # SQL
    
    return result_df, result_arr

# Run some test operations
if __name__ == "__main__":
    # Execute various test scenarios
    mixed_pandas_numpy()
    mixed_pandas_sql()
    mixed_numpy_sql()
    triple_mixed_operations()
    
    processor = DataProcessor()
    processor.process_pipeline()
    
    conditional_mixed_processing('mixed')
    loop_mixed_operations()
    error_handling_mixed()
    nested_mixed_calls()
    lambda_mixed_operations()
    complex_data_flow()
    performance_mixed_operations()
    empty_data_mixed()

# Close connection
conn.close() 