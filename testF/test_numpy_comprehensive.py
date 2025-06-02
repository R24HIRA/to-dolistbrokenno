"""
Comprehensive numpy mutation test file with various operations and edge cases
"""
import numpy as np

# Basic array setup
arr = np.array([1, 2, 3, 4, 5])
arr2d = np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]])
arr3d = np.array([[[1, 2], [3, 4]], [[5, 6], [7, 8]]])

# 1. Basic mutations - deletion operations
np.delete(arr, 0)  # MEDIUM severity
np.delete(arr, [0, 1])  # Delete multiple elements
np.delete(arr2d, 0, axis=0)  # Delete row
np.delete(arr2d, 1, axis=1)  # Delete column
np.delete(arr3d, 0, axis=2)  # Delete along 3rd axis

# 2. Basic mutations - insertion operations
np.insert(arr, 0, 99)  # MEDIUM severity
np.insert(arr, [1, 2], [10, 20])  # Insert multiple values
np.insert(arr2d, 0, [99, 98, 97], axis=0)  # Insert row
np.insert(arr2d, 1, [88, 87, 86], axis=1)  # Insert column

# 3. Basic mutations - append operations
np.append(arr, 6)  # MEDIUM severity
np.append(arr, [6, 7, 8])  # Append multiple values
np.append(arr2d, [[10, 11, 12]], axis=0)  # Append row
np.append(arr2d, [[10], [11], [12]], axis=1)  # Append column

# 4. Chain mutations with multiple operations
result1 = np.delete(np.insert(arr, 0, 99), -1)
result2 = np.append(np.delete(arr, 0), [10, 11])
result3 = np.insert(np.append(arr, 6), 0, 0)

# 5. Complex chain mutations
processed_arr = np.delete(
    np.insert(
        np.append(arr, [6, 7]), 
        0, 
        [0, -1]
    ), 
    [2, 3]
)

# 6. Mutations with variables and expressions
index_to_delete = 2
value_to_insert = 99
values_to_append = [10, 11, 12]

np.delete(arr, index_to_delete)
np.insert(arr, 0, value_to_insert)
np.append(arr, values_to_append)

# 7. Conditional mutations
if len(arr) > 3:
    arr_modified = np.delete(arr, 0)
    arr_modified = np.insert(arr_modified, 0, 99)

# 8. Loop-based mutations
for i in range(3):
    arr = np.append(arr, i * 10)

for idx in [0, 1]:
    arr = np.delete(arr, idx)

# 9. Function-based mutations
def process_array(data):
    data = np.delete(data, 0)
    data = np.insert(data, 0, 99)
    return np.append(data, 100)

def chain_operations(data):
    return np.append(np.delete(np.insert(data, 0, -1), -1), [88, 99])

# 10. Class-based mutations
class ArrayProcessor:
    def __init__(self, arr):
        self.arr = arr
    
    def clean_and_modify(self):
        self.arr = np.delete(self.arr, 0)
        self.arr = np.insert(self.arr, 0, 999)
        return self.arr
    
    def chain_process(self):
        return np.append(
            np.delete(self.arr, [0, -1]), 
            [100, 200]
        )

# 11. Edge cases with different parameters
# Empty arrays
empty_arr = np.array([])
try:
    np.delete(empty_arr, 0)  # Should handle gracefully
except:
    pass

# Out of bounds indices
try:
    np.delete(arr, 100)  # Out of bounds
except:
    pass

# Negative indices
np.delete(arr, -1)  # Delete last element
np.insert(arr, -1, 99)  # Insert before last element

# 12. Multi-dimensional array mutations
# 2D array operations
np.delete(arr2d, 0, axis=0)  # Delete first row
np.delete(arr2d, 1, axis=1)  # Delete second column
np.insert(arr2d, 1, [99, 98, 97], axis=0)  # Insert row
np.append(arr2d, [[10, 11, 12]], axis=0)  # Append row

# 3D array operations
np.delete(arr3d, 0, axis=0)
np.insert(arr3d, 1, [[[99, 98]], [[97, 96]]], axis=0)
np.append(arr3d, [[[10, 11]], [[12, 13]]], axis=0)

# 13. Complex indexing with mutations
mask = arr > 2
indices = np.where(arr > 2)[0]
np.delete(arr, indices)
np.insert(arr, indices[0], 999)

# 14. Mutations with slicing
np.delete(arr, slice(1, 3))  # Delete slice
np.insert(arr, slice(1, 2), [88, 99])  # Insert at slice

# 15. Nested function calls with mutations
result = np.append(
    np.delete(
        np.insert(arr, 0, 0), 
        -1
    ), 
    np.array([100, 200])
)

# 16. Assignment with mutations
new_arr = np.delete(arr, 0)
modified_arr = np.insert(np.append(arr, 6), 0, 0)

# 17. Multiple arrays with mutations
arr_a = np.array([1, 2, 3])
arr_b = np.array([4, 5, 6])

combined = np.append(np.delete(arr_a, 0), np.insert(arr_b, 0, 99))

# 18. Lambda functions with mutations (edge case)
arrays = [np.array([1, 2, 3]), np.array([4, 5, 6])]
processed = list(map(lambda x: np.delete(x, 0), arrays))

# 19. Mutations with broadcasting
broadcast_arr = np.ones((3, 3))
np.delete(broadcast_arr, 0, axis=0)
np.insert(broadcast_arr, 1, np.zeros(3), axis=0)
np.append(broadcast_arr, np.ones((1, 3)), axis=0)

# 20. Complex data types
complex_arr = np.array([1+2j, 3+4j, 5+6j])
np.delete(complex_arr, 1)
np.insert(complex_arr, 0, 0+0j)
np.append(complex_arr, 7+8j) 