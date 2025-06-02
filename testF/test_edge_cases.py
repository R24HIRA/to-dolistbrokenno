"""
Edge cases test file with unusual patterns and boundary conditions
"""
import pandas as pd
import numpy as np
import sqlite3
import sys
from typing import Any, List, Dict

# Setup
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
arr = np.array([1, 2, 3, 4, 5])
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

# 1. Dynamic attribute access
def dynamic_operations():
    # Dynamic method calls
    method_name = 'drop'
    getattr(df, method_name)('A', axis=1)  # Should detect pandas.drop
    
    numpy_method = 'delete'
    getattr(np, numpy_method)(arr, 0)  # Should detect numpy.delete
    
    # Dynamic SQL execution
    sql_method = 'execute'
    getattr(cursor, sql_method)("DELETE FROM users WHERE id = 1")  # Should detect SQL

# 2. Eval and exec edge cases
def eval_exec_operations():
    # Using eval (dangerous but possible)
    try:
        eval("df.drop('A', axis=1)")  # Should detect if possible
        eval("np.delete(arr, 0)")  # Should detect if possible
        eval("cursor.execute('DELETE FROM test')")  # Should detect if possible
    except:
        pass
    
    # Using exec
    try:
        exec("df.dropna(inplace=True)")  # Should detect if possible
        exec("np.append(arr, [6, 7])")  # Should detect if possible
    except:
        pass

# 3. Monkey patching and method replacement
def monkey_patch_operations():
    # Store original methods
    original_drop = df.drop
    original_delete = np.delete
    
    # Replace with custom implementations
    def custom_drop(*args, **kwargs):
        print("Custom drop called")
        return original_drop(*args, **kwargs)
    
    df.drop = custom_drop
    
    # This should still be detected
    df.drop('A', axis=1)
    
    # Restore original
    df.drop = original_drop

# 4. Metaclass and descriptor edge cases
class MutationDescriptor:
    def __get__(self, obj, objtype=None):
        return lambda *args, **kwargs: df.drop('A', axis=1)  # Hidden mutation
    
    def __set__(self, obj, value):
        np.delete(arr, 0)  # Hidden mutation in setter

class MetaMutation(type):
    def __new__(cls, name, bases, attrs):
        # Add hidden mutations in metaclass
        def hidden_method(self):
            cursor.execute("DELETE FROM hidden_table")  # Hidden SQL mutation
        
        attrs['hidden'] = hidden_method
        return super().__new__(cls, name, bases, attrs)

class EdgeCaseClass(metaclass=MetaMutation):
    mutation_prop = MutationDescriptor()
    
    def __init__(self):
        self.data = df.copy()
    
    def process(self):
        # This triggers the descriptor
        result = self.mutation_prop()
        return result

# 5. Generator and iterator edge cases
def generator_mutations():
    def mutation_generator():
        yield df.drop('A', axis=1)  # Mutation in generator
        yield np.delete(arr, 0)  # Mutation in generator
        cursor.execute("INSERT INTO generator_log VALUES (1)")  # SQL in generator
        yield "done"
    
    # Consume generator
    for item in mutation_generator():
        pass

# 6. Context manager edge cases
class MutationContextManager:
    def __enter__(self):
        df.dropna(inplace=True)  # Mutation on enter
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        cursor.execute("DELETE FROM context_cleanup")  # SQL on exit
        np.append(arr, [999])  # Numpy on exit

def context_manager_test():
    with MutationContextManager():
        # Mutations happen in context manager
        pass

# 7. Decorator edge cases
def mutation_decorator(func):
    def wrapper(*args, **kwargs):
        # Pre-execution mutations
        df.drop('A', axis=1)  # Pandas mutation in decorator
        np.delete(arr, 0)  # Numpy mutation in decorator
        cursor.execute("INSERT INTO decorator_log VALUES (1)")  # SQL in decorator
        
        result = func(*args, **kwargs)
        
        # Post-execution mutations
        df.fillna(0, inplace=True)  # More pandas mutations
        return result
    return wrapper

@mutation_decorator
def decorated_function():
    return "function executed"

# 8. Exception handling edge cases
def exception_mutations():
    try:
        # Intentional error
        raise ValueError("Test error")
    except ValueError:
        # Mutations in exception handler
        df.drop('A', axis=1, errors='ignore')  # Pandas in except
        np.delete(arr, 0)  # Numpy in except
        cursor.execute("INSERT INTO error_log VALUES ('handled')")  # SQL in except
    finally:
        # Mutations in finally block
        df.dropna()  # Pandas in finally
        cursor.execute("DELETE FROM temp_data")  # SQL in finally

# 9. Threading and async edge cases (if applicable)
import threading
import asyncio

def threaded_mutations():
    def thread_worker():
        df.drop('A', axis=1)  # Mutation in thread
        np.delete(arr, 0)  # Mutation in thread
        cursor.execute("INSERT INTO thread_log VALUES (1)")  # SQL in thread
    
    thread = threading.Thread(target=thread_worker)
    thread.start()
    thread.join()

async def async_mutations():
    # Mutations in async function
    await asyncio.sleep(0.001)  # Minimal async operation
    df.dropna()  # Pandas mutation in async
    np.append(arr, [999])  # Numpy mutation in async
    cursor.execute("INSERT INTO async_log VALUES (1)")  # SQL in async

# 10. Property and attribute edge cases
class PropertyMutations:
    def __init__(self):
        self._data = df.copy()
    
    @property
    def data(self):
        # Mutation in property getter
        self._data.drop('A', axis=1, inplace=True)
        return self._data
    
    @data.setter
    def data(self, value):
        # Mutation in property setter
        cursor.execute("UPDATE property_log SET accessed = 1")
        self._data = value

# 11. Import and module edge cases
def import_mutations():
    # Dynamic imports with mutations
    import importlib
    
    # This is tricky to detect
    pd_module = importlib.import_module('pandas')
    np_module = importlib.import_module('numpy')
    
    # Use dynamically imported modules
    pd_module.DataFrame({'test': [1, 2, 3]}).drop('test', axis=1)
    np_module.delete(np.array([1, 2, 3]), 0)

# 12. String manipulation edge cases
def string_sql_edge_cases():
    # Complex string building for SQL
    table = "users"
    condition = "id = 1"
    action = "DELETE"
    
    # Various ways to build SQL strings
    query1 = f"{action} FROM {table} WHERE {condition}"
    cursor.execute(query1)
    
    query2 = "{} FROM {} WHERE {}".format(action, table, condition)
    cursor.execute(query2)
    
    query3 = action + " FROM " + table + " WHERE " + condition
    cursor.execute(query3)
    
    # SQL in data structures
    queries = [
        "DELETE FROM logs WHERE old = 1",
        "UPDATE settings SET value = 'new'",
        "INSERT INTO audit VALUES (1, 'test')"
    ]
    
    for q in queries:
        cursor.execute(q)

# 13. Nested data structure edge cases
def nested_structure_mutations():
    # Mutations in nested structures
    operations = {
        'pandas': [
            lambda: df.drop('A', axis=1),
            lambda: df.dropna(),
            lambda: df.drop_duplicates()
        ],
        'numpy': [
            lambda: np.delete(arr, 0),
            lambda: np.append(arr, [6]),
            lambda: np.insert(arr, 0, 0)
        ],
        'sql': [
            lambda: cursor.execute("DELETE FROM nested_test"),
            lambda: cursor.execute("UPDATE nested_test SET value = 1"),
            lambda: cursor.execute("INSERT INTO nested_test VALUES (1)")
        ]
    }
    
    # Execute nested operations
    for category, ops in operations.items():
        for op in ops:
            op()

# 14. Reflection and introspection edge cases
def reflection_mutations():
    # Using reflection to find and call methods
    import inspect
    
    # Find all methods that might be mutations
    for name, method in inspect.getmembers(df, predicate=inspect.ismethod):
        if name in ['drop', 'dropna', 'drop_duplicates']:
            try:
                if name == 'drop':
                    method('A', axis=1)  # Should detect
                else:
                    method()  # Should detect
            except:
                pass

# 15. Memory and performance edge cases
def memory_edge_cases():
    # Large data operations
    try:
        large_df = pd.DataFrame({'col' + str(i): range(1000) for i in range(100)})
        large_df.drop('col0', axis=1)  # Should detect even with large data
        
        large_arr = np.arange(10000)
        np.delete(large_arr, range(100))  # Should detect with large arrays
        
        # Batch SQL operations
        for i in range(100):
            cursor.execute(f"INSERT INTO large_test VALUES ({i})")
        
        cursor.execute("DELETE FROM large_test WHERE id < 50")  # Should detect
        
    except MemoryError:
        # Fallback for memory constraints
        cursor.execute("INSERT INTO memory_error_log VALUES ('handled')")

# 16. Unicode and encoding edge cases
def unicode_edge_cases():
    # Unicode in column names and SQL
    unicode_df = pd.DataFrame({'测试': [1, 2, 3], 'données': [4, 5, 6]})
    unicode_df.drop('测试', axis=1)  # Should detect with unicode
    
    # Unicode in SQL
    cursor.execute("DELETE FROM table_测试 WHERE name = 'données'")  # Should detect

# 17. Circular reference edge cases
class CircularRef:
    def __init__(self):
        self.ref = self
        self.data = df.copy()
    
    def mutate(self):
        self.data.drop('A', axis=1, inplace=True)  # Should detect
        self.ref.data.dropna(inplace=True)  # Should detect circular ref

# 18. Weak reference edge cases
import weakref

def weak_ref_mutations():
    def callback(ref):
        cursor.execute("INSERT INTO weakref_cleanup VALUES (1)")  # SQL in callback
    
    obj = CircularRef()
    weak_obj = weakref.ref(obj, callback)
    
    # Mutation through weak reference
    if weak_obj() is not None:
        weak_obj().mutate()

# 19. Pickle and serialization edge cases
import pickle

def serialization_mutations():
    # Mutations during serialization
    class MutatingPickle:
        def __reduce__(self):
            # Mutation during pickle
            df.drop('A', axis=1)
            cursor.execute("INSERT INTO pickle_log VALUES (1)")
            return (lambda: None, ())
    
    obj = MutatingPickle()
    try:
        pickle.dumps(obj)  # Triggers __reduce__
    except:
        pass

# 20. Signal and interrupt edge cases
import signal

def signal_mutations():
    def signal_handler(signum, frame):
        # Mutations in signal handler
        df.dropna(inplace=True)
        cursor.execute("INSERT INTO signal_log VALUES (1)")
    
    # Register signal handler (be careful in real code)
    signal.signal(signal.SIGUSR1, signal_handler)

# Run edge case tests
if __name__ == "__main__":
    try:
        dynamic_operations()
        eval_exec_operations()
        monkey_patch_operations()
        
        edge_obj = EdgeCaseClass()
        edge_obj.process()
        
        generator_mutations()
        context_manager_test()
        decorated_function()
        exception_mutations()
        threaded_mutations()
        
        # Async test (if event loop available)
        try:
            asyncio.run(async_mutations())
        except:
            pass
        
        prop_obj = PropertyMutations()
        _ = prop_obj.data  # Triggers property getter
        
        import_mutations()
        string_sql_edge_cases()
        nested_structure_mutations()
        reflection_mutations()
        memory_edge_cases()
        unicode_edge_cases()
        
        circular_obj = CircularRef()
        circular_obj.mutate()
        
        weak_ref_mutations()
        serialization_mutations()
        signal_mutations()
        
    except Exception as e:
        print(f"Edge case test error: {e}")
        cursor.execute("INSERT INTO edge_case_errors VALUES (?)", (str(e),))

# Close connection
conn.close() 