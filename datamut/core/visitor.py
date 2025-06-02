"""LibCST visitors for detecting data mutation operations."""

from pathlib import Path
from typing import List, Optional, Union, Dict

import libcst as cst
import libcst.matchers as m
from libcst.metadata import PositionProvider

from .context import AnalysisContext, SQLContext
from .finding import Finding, Severity
from .loader import RuleLoader


class MutationVisitor(cst.CSTVisitor):
    """Main visitor for detecting data mutation operations."""
    
    METADATA_DEPENDENCIES = (PositionProvider,)
    
    def __init__(self, file_path: Path, rule_loader: RuleLoader, context: AnalysisContext):
        self.file_path = file_path
        self.rule_loader = rule_loader
        self.context = context
        self.findings = []
        self.variable_types = {}  # Track variable types for method chaining
        self.sql_variables = {}  # Track variables containing SQL strings
        self.source_lines = []
        self.processed_chains = set()  # Track processed chain root nodes to avoid duplicates
        self.inner_calls = set()  # Track calls that are inner parts of chains
    
    def set_source_code(self, source_code: str) -> None:
        """Set the source code for extracting snippets."""
        self.source_lines = source_code.splitlines()
    
    def visit_Assign(self, node: cst.Assign) -> None:
        """Track variable assignments for type inference and SQL detection."""
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target.target, cst.Name):
                var_name = target.target.value
                
                # Check if the assigned value is a string that looks like SQL
                if isinstance(node.value, (cst.SimpleString, cst.ConcatenatedString)):
                    sql_text = self._extract_string_value(node.value)
                    if sql_text and self._looks_like_sql(sql_text):
                        self.sql_variables[var_name] = sql_text
                
                # Track variable types for method chaining
                if isinstance(node.value, cst.Call):
                    func_info = self._extract_function_info(node.value)
                    if func_info:
                        library, function_name = func_info
                        if library in ['pandas', 'numpy']:
                            self.variable_types[var_name] = library
    
    def visit_Call(self, node: cst.Call) -> None:
        """Visit function calls to detect mutations."""
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
            return
        
        # Single function call - process normally
        func_info = self._extract_function_info(node)
        if not func_info:
            return
        
        library, function_name = func_info
        
        # Look up rule
        rule = self.rule_loader.get_rule(library, function_name)
        if not rule:
            return
        
        # Get position information
        position = self._get_position(node)
        if not position:
            # Fallback to line 1 if position not available
            position = (1, 0)
        
        line_number, column_offset = position
        
        # Extract code snippet
        code_snippet = self._extract_code_snippet(node, line_number)
        
        # Determine severity (may be escalated by extra checks)
        severity = rule.default_severity
        extra_context = {}
        
        if rule.extra_checks:
            severity, extra_context = self._apply_extra_checks(node, rule, severity)
        
        # Create finding
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            column_offset=column_offset,
            library=library,
            function_name=function_name,
            mutation_type=rule.mutation,
            severity=severity,
            code_snippet=code_snippet,
            notes=rule.notes,
            rule_id=rule.rule_id,
            extra_context=extra_context
        )
        
        self.findings.append(finding)
    
    def visit_SimpleStatementLine(self, node: cst.SimpleStatementLine) -> None:
        """Visit simple statements to check for SQL strings."""
        for stmt in node.body:
            if isinstance(stmt, cst.Expr) and isinstance(stmt.value, cst.Call):
                self._check_sql_in_call(stmt.value, node)
    
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
        """Infer the library type from a chained method call.
        
        This traverses back through the chain to find the original object
        and determine what library it belongs to.
        """
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
    
    def _get_position(self, node: cst.CSTNode) -> Optional[tuple[int, int]]:
        """Get line and column position of a node."""
        try:
            position = self.get_metadata(PositionProvider, node)
            if position:
                return position.start.line, position.start.column
        except Exception:
            pass
        return None
    
    def _extract_code_snippet(self, node: cst.CSTNode, line_number: int) -> str:
        """Extract code snippet around the node."""
        if not self.source_lines or line_number < 1 or line_number > len(self.source_lines):
            return ""
        
        # Get the line (1-indexed to 0-indexed)
        line = self.source_lines[line_number - 1]
        return line.strip()
    
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
    
    def _check_sql_in_call(self, call_node: cst.Call, stmt_node: cst.SimpleStatementLine) -> None:
        """Check for SQL strings in function calls."""
        for arg in call_node.args:
            # Check direct string literals
            if isinstance(arg.value, (cst.SimpleString, cst.ConcatenatedString)):
                sql_text = self._extract_string_value(arg.value)
                if sql_text and self._looks_like_sql(sql_text):
                    mutations = SQLContext.analyze_sql_string(sql_text)
                    for mutation in mutations:
                        self._create_sql_finding(mutation, stmt_node, sql_text)
            
            # Check variables that contain SQL strings
            elif isinstance(arg.value, cst.Name):
                var_name = arg.value.value
                if var_name in self.sql_variables:
                    sql_text = self.sql_variables[var_name]
                    mutations = SQLContext.analyze_sql_string(sql_text)
                    for mutation in mutations:
                        self._create_sql_finding(mutation, stmt_node, sql_text)
    
    def _extract_string_value(self, node: Union[cst.SimpleString, cst.ConcatenatedString]) -> Optional[str]:
        """Extract string value from a string node."""
        if isinstance(node, cst.SimpleString):
            # Remove quotes and handle escape sequences
            value = node.value
            if value.startswith(('"""', "'''")):
                return value[3:-3]
            elif value.startswith(('"', "'")):
                return value[1:-1]
            return value
        elif isinstance(node, cst.ConcatenatedString):
            # Handle concatenated strings
            parts = []
            for part in node.left, node.right:
                if isinstance(part, (cst.SimpleString, cst.ConcatenatedString)):
                    part_value = self._extract_string_value(part)
                    if part_value:
                        parts.append(part_value)
            return ''.join(parts)
        return None
    
    def _looks_like_sql(self, text: str) -> bool:
        """Simple heuristic to determine if text looks like SQL."""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'FROM', 'WHERE']
        text_upper = text.upper()
        return any(keyword in text_upper for keyword in sql_keywords)
    
    def _create_sql_finding(self, mutation: dict, stmt_node: cst.SimpleStatementLine, sql_text: str) -> None:
        """Create a finding for SQL mutation."""
        position = self._get_position(stmt_node)
        if not position:
            return
        
        line_number, column_offset = position
        
        # Determine severity based on SQL operation
        severity_map = {
            'data insertion': Severity.MEDIUM,
            'data update': Severity.HIGH,
            'data deletion': Severity.CRITICAL,
            'schema/data drop': Severity.CRITICAL,
            'schema alteration': Severity.HIGH,
            'data truncation': Severity.CRITICAL,
            'data merge': Severity.MEDIUM,
            'data upsert': Severity.MEDIUM,
            'data replacement': Severity.HIGH
        }
        
        severity = severity_map.get(mutation['mutation_type'], Severity.MEDIUM)
        
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            column_offset=column_offset,
            library="sql",
            function_name=mutation['keyword'],
            mutation_type=mutation['mutation_type'],
            severity=severity,
            code_snippet=self._extract_code_snippet(stmt_node, line_number),
            notes=f"SQL {mutation['keyword']} operation detected in string literal",
            rule_id=f"sql.{mutation['keyword'].lower()}",
            extra_context={'sql_text': sql_text[:100] + '...' if len(sql_text) > 100 else sql_text}
        )
        
        self.findings.append(finding)
    
    def _get_chain_root(self, node: cst.Call) -> cst.Call:
        """Get the root call node of a chain."""
        current = node
        while isinstance(current.func, cst.Attribute) and isinstance(current.func.value, cst.Call):
            current = current.func.value
        return current
    
    def _extract_chain_functions(self, node: cst.Call) -> list[tuple[str, str, cst.Call]]:
        """Extract all mutation functions in a chain.
        
        Returns a list of (library, function_name, call_node) tuples for mutation functions only.
        """
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
        
        # Determine the highest severity in the chain
        max_severity = Severity.LOW
        libraries = set()
        function_names = []
        mutation_types = []
        
        for library, function_name, call_node in chain_functions:
            libraries.add(library)
            function_names.append(function_name)
            
            rule = self.rule_loader.get_rule(library, function_name)
            if rule:
                severity = rule.default_severity
                # Apply extra checks for this specific call
                if rule.extra_checks:
                    severity, _ = self._apply_extra_checks(call_node, rule, severity)
                
                # Update max severity using proper numeric comparison
                if severity.exit_code_weight > max_severity.exit_code_weight:
                    max_severity = severity
                
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
            mutation_type="multiple mutation functions chained",
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

    def _is_inner_call_in_chain(self, node: cst.Call) -> bool:
        """Check if this call is an inner call in a method chain."""
        return id(node) in self.inner_calls 