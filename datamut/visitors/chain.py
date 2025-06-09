"""Visitor for detecting method chaining operations."""

from typing import Dict, Optional, Set

import libcst as cst

from .base import BaseVisitor
from ..core.finding import Finding, Severity


class ChainVisitor(BaseVisitor):
    """Visitor specifically for detecting method chaining operations."""
    
    def __init__(self, file_path, rule_loader, context):
        super().__init__(file_path, rule_loader, context)
        self.variable_types: Dict[str, str] = {}  # Track variable types for method chaining
        self.processed_chains: Set[int] = set()  # Track processed chain root nodes to avoid duplicates
        self.inner_calls: Set[int] = set()  # Track calls that are inner parts of chains
    
    def visit_Assign(self, node: cst.Assign) -> None:
        """Track variable assignments for type inference."""
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target.target, cst.Name):
                var_name = target.target.value
                
                # Track variable types for method chaining
                if isinstance(node.value, cst.Call):
                    func_info = self._extract_function_info(node.value)
                    if func_info:
                        library, function_name = func_info
                        if library in ['pandas', 'numpy', 'sqlalchemy', 'sqlite3', 'psycopg2', 'pymongo']:
                            self.variable_types[var_name] = library
    
    def visit_Call(self, node: cst.Call) -> None:
        """Visit function calls to detect method chains."""
        # First pass: identify all inner calls in chains
        self._mark_inner_calls(node)
        
        # Skip if this is an inner call in a chain
        if id(node) in self.inner_calls:
            return
        
        # Check if this call is part of a chain we've already processed
        chain_root = self._get_chain_root(node)
        if id(chain_root) in self.processed_chains:
            return
        
        # Check if this is a chain of mutation functions
        chain_functions = self._extract_chain_functions(node)
        if len(chain_functions) > 1:
            # This is a chain - process it as a single finding
            self._process_chain_finding(node, chain_functions)
            self.processed_chains.add(id(chain_root))
    
    def _extract_function_info(self, node: cst.Call) -> Optional[tuple[str, str]]:
        """Extract library and function name from a call node."""
        func = node.func
        
        if isinstance(func, cst.Name):
            # Simple function call: func()
            function_name = func.value
            # Check if it's a known import
            resolved = self.context.resolve_name(function_name)
            if '.' in resolved:
                parts = resolved.split('.')
                return parts[0], parts[-1]
            return None, function_name
        
        elif isinstance(func, cst.Attribute):
            # Method call: obj.method()
            function_name = func.attr.value
            
            if isinstance(func.value, cst.Name):
                # obj.method() - check if obj is an alias or tracked variable
                obj_name = func.value.value
                
                # First check if it's a tracked variable
                if obj_name in self.variable_types:
                    library = self.variable_types[obj_name]
                    return library, function_name
                
                # Then check if it's an import alias
                resolved = self.context.resolve_name(obj_name)
                library = self.rule_loader.resolve_alias(resolved)
                if library:
                    return library, function_name
                return resolved, function_name
            
            elif isinstance(func.value, cst.Subscript):
                # obj[key].method() - check if obj is a tracked variable
                if isinstance(func.value.value, cst.Name):
                    obj_name = func.value.value.value
                    if obj_name in self.variable_types:
                        library = self.variable_types[obj_name]
                        return library, function_name
                    
                    # Check if it's an import alias
                    resolved = self.context.resolve_name(obj_name)
                    library = self.rule_loader.resolve_alias(resolved)
                    if library:
                        return library, function_name
                    
                    # For common patterns, infer from the object name
                    if obj_name.startswith(('df', 'data', 'frame')):
                        return 'pandas', function_name
                    elif obj_name.startswith(('arr', 'array', 'np_')):
                        return 'numpy', function_name
            
            elif isinstance(func.value, cst.Call):
                # Chained method call: obj.method1().method2()
                # For chained calls, we need to infer the library from the chain
                chain_library = self._infer_library_from_chain(func.value)
                if chain_library:
                    return chain_library, function_name
                return None
            
            elif isinstance(func.value, cst.Attribute):
                # module.obj.method() or similar
                full_path = self._get_full_attribute_path(func.value)
                if full_path:
                    parts = full_path.split('.')
                    if len(parts) >= 1:
                        library = self.rule_loader.resolve_alias(parts[0])
                        if library:
                            return library, function_name
                        return parts[0], function_name
        
        return None
    
    def _infer_library_from_chain(self, call_node: cst.Call) -> Optional[str]:
        """Infer the library type from a chained method call."""
        current = call_node
        
        # Traverse back through the chain to find the root
        while isinstance(current.func, cst.Attribute):
            if isinstance(current.func.value, cst.Name):
                # Found the root object
                obj_name = current.func.value.value
                
                # Check if it's a tracked variable
                if obj_name in self.variable_types:
                    return self.variable_types[obj_name]
                
                # Check if it's an import alias
                resolved = self.context.resolve_name(obj_name)
                library = self.rule_loader.resolve_alias(resolved)
                if library:
                    return library
                
                # For common patterns, infer from the object name
                if obj_name.startswith(('df', 'data', 'frame')):
                    return 'pandas'
                elif obj_name.startswith(('arr', 'array', 'np_')):
                    return 'numpy'
                
                return None
            
            elif isinstance(current.func.value, cst.Subscript):
                # Handle obj[key] pattern - check the base object
                if isinstance(current.func.value.value, cst.Name):
                    obj_name = current.func.value.value.value
                    
                    # Check if it's a tracked variable
                    if obj_name in self.variable_types:
                        return self.variable_types[obj_name]
                    
                    # Check if it's an import alias
                    resolved = self.context.resolve_name(obj_name)
                    library = self.rule_loader.resolve_alias(resolved)
                    if library:
                        return library
                    
                    # For common patterns, infer from the object name
                    if obj_name.startswith(('df', 'data', 'frame')):
                        return 'pandas'
                    elif obj_name.startswith(('arr', 'array', 'np_')):
                        return 'numpy'
                
                return None
            
            elif isinstance(current.func.value, cst.Call):
                # Continue traversing the chain
                current = current.func.value
            else:
                break
        
        return None
    
    def _get_full_attribute_path(self, node: cst.BaseExpression) -> Optional[str]:
        """Get the full dotted path from an attribute expression."""
        if isinstance(node, cst.Name):
            return self.context.resolve_name(node.value)
        elif isinstance(node, cst.Attribute):
            base = self._get_full_attribute_path(node.value)
            if base:
                return f"{base}.{node.attr.value}"
        return None
    
    def _get_chain_root(self, node: cst.Call) -> cst.Call:
        """Get the root call node of a chain."""
        current = node
        while isinstance(current.func, cst.Attribute) and isinstance(current.func.value, cst.Call):
            current = current.func.value
        return current
    
    def _extract_chain_functions(self, node: cst.Call) -> list[tuple[str, str, cst.Call]]:
        """Extract all mutation functions in a chain."""
        chain_functions = []
        current = node
        
        # Traverse the chain from the outermost call inward
        while current:
            func_info = self._extract_function_info(current)
            if func_info:
                library, function_name = func_info
                # Check if this function is a mutation (has a rule)
                rule = self.rule_loader.get_rule(library, function_name)
                if rule:
                    chain_functions.append((library, function_name, current))
            
            # Move to the next call in the chain
            if isinstance(current.func, cst.Attribute) and isinstance(current.func.value, cst.Call):
                current = current.func.value
            else:
                break
        
        # Reverse to get the chain in execution order (innermost to outermost)
        return list(reversed(chain_functions))
    
    def _process_chain_finding(self, node: cst.Call, chain_functions: list[tuple[str, str, cst.Call]]) -> None:
        """Process a chain of mutation functions as a single finding."""
        if not chain_functions:
            return
        
        # Get position of the outermost call (the one we started with)
        position = self._get_position(node)
        if not position:
            position = (1, 0)
        
        line_number, column_offset = position
        code_snippet = self._extract_code_snippet(node, line_number)
        
        # ALL CHAIN OPERATIONS ARE HIGH SEVERITY
        max_severity = Severity.HIGH
        libraries = set()
        function_names = []
        mutation_types = []
        
        for library, function_name, call_node in chain_functions:
            libraries.add(library)
            function_names.append(function_name)
            
            rule = self.rule_loader.get_rule(library, function_name)
            if rule:
                # Still apply extra checks (like inplace=True) which can escalate to CRITICAL
                if rule.extra_checks:
                    severity, _ = self._apply_extra_checks(call_node, rule, Severity.HIGH)
                    # Only allow escalation to CRITICAL, not reduction
                    if severity == Severity.CRITICAL:
                        max_severity = Severity.CRITICAL
                
                mutation_types.append(rule.mutation)
        
        # Create chain finding
        library_str = "/".join(sorted(libraries)) if len(libraries) > 1 else list(libraries)[0]
        function_names_str = " → ".join(function_names)
        mutation_types_str = ", ".join(set(mutation_types))
        
        # Create extra context with chain details
        extra_context = {
            "chain_length": len(chain_functions),
            "functions": function_names,
            "libraries": list(libraries),
            "mutation_types": list(set(mutation_types))
        }
        
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            column_offset=column_offset,
            library=library_str,
            function_name=function_names_str,
            mutation_type="method chaining with mutations",
            severity=max_severity,
            code_snippet=code_snippet,
            notes=f"Chain of {len(chain_functions)} mutation functions: {function_names_str}. "
                  f"Mutation types: {mutation_types_str}. "
                  f"Chained operations can compound data loss and make debugging difficult.",
            rule_id="chain.multiple_mutations",
            extra_context=extra_context
        )
        
        self.findings.append(finding)
    
    def _mark_inner_calls(self, node: cst.Call) -> None:
        """Mark all inner calls in a chain starting from this node."""
        current = node
        while isinstance(current.func, cst.Attribute) and isinstance(current.func.value, cst.Call):
            inner_call = current.func.value
            self.inner_calls.add(id(inner_call))
            current = inner_call
    
    def _apply_extra_checks(self, node: cst.Call, rule, default_severity: Severity) -> tuple[Severity, dict]:
        """Apply extra validation checks and potentially escalate severity."""
        extra_context = {}
        severity = default_severity
        
        if not rule.extra_checks:
            return severity, extra_context
        
        # Check for argument presence
        if rule.extra_checks.arg_present:
            arg_check = rule.extra_checks.arg_present
            arg_name = arg_check.get('name')
            expected_value = arg_check.get('value')
            
            if self._has_argument_with_value(node, arg_name, expected_value):
                extra_context['matched_arg'] = {
                    'name': arg_name,
                    'value': expected_value
                }
                # Get the severity from the arg_present check
                set_severity = arg_check.get('set_severity')
                if set_severity:
                    # Convert string to Severity enum if needed
                    if isinstance(set_severity, str):
                        severity = Severity(set_severity)
                    else:
                        severity = set_severity
        
        return severity, extra_context
    
    def _has_argument_with_value(self, node: cst.Call, arg_name: str, expected_value) -> bool:
        """Check if a call has a specific argument with a specific value."""
        for arg in node.args:
            if isinstance(arg.keyword, cst.Name) and arg.keyword.value == arg_name:
                # Check the value
                if isinstance(arg.value, cst.Name):
                    if expected_value is True and arg.value.value == "True":
                        return True
                    elif expected_value is False and arg.value.value == "False":
                        return True
                    elif isinstance(expected_value, str) and arg.value.value == expected_value:
                        return True
                elif isinstance(arg.value, (cst.Integer, cst.Float, cst.SimpleString)):
                    arg_val = arg.value.value
                    if isinstance(arg.value, cst.SimpleString):
                        # Remove quotes
                        arg_val = arg_val.strip('\'"')
                    if str(arg_val) == str(expected_value):
                        return True
        return False 