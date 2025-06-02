"""
Debug script to examine AST structure of chained calls
"""
import libcst as cst

# Test code with a chain
code = """
result = df.drop('A', axis=1).dropna().drop_duplicates()
"""

print("Parsing code...")
tree = cst.parse_module(code)

def print_call_structure(node, depth=0):
    indent = "  " * depth
    if isinstance(node, cst.Call):
        print(f"{indent}Call:")
        print(f"{indent}  func: {type(node.func).__name__}")
        if isinstance(node.func, cst.Attribute):
            print(f"{indent}    attr: {node.func.attr.value}")
            print(f"{indent}    value: {type(node.func.value).__name__}")
            if isinstance(node.func.value, cst.Call):
                print(f"{indent}    value (Call):")
                print_call_structure(node.func.value, depth + 2)
            elif isinstance(node.func.value, cst.Name):
                print(f"{indent}    value (Name): {node.func.value.value}")
        elif isinstance(node.func, cst.Name):
            print(f"{indent}    name: {node.func.value}")

class CallVisitor(cst.CSTVisitor):
    def visit_Call(self, node: cst.Call) -> None:
        print("=== Found Call ===")
        print_call_structure(node)
        print()

print("Visiting tree...")
tree.visit(CallVisitor()) 