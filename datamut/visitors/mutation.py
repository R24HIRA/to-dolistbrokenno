"""Visitor for detecting pandas/numpy single mutation operations."""

from typing import Dict, Optional

import libcst as cst

from .base import BaseVisitor
from ..core.finding import Finding, Severity


class MutationVisitor(BaseVisitor):
    """Visitor for detecting individual data mutation operations in pandas, numpy, etc."""
    
    def __init__(self, file_path, rule_loader, context):
        super().__init__(file_path, rule_loader, context)
        self.variable_types: Dict[str, str] = {}  # Track variable types for method resolution
    
    def visit_Assign(self, node: cst.Assign) -> None:
        """Track variable assignments for type inference and detect boolean indexing."""
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target.target, cst.Name):
                var_name = target.target.value
                
                # Track variable types for method resolution
                if isinstance(node.value, cst.Call):
                    func_info = self._extract_function_info(node.value)
                    if func_info:
                        library, function_name = func_info
                        if library in ['pandas', 'numpy']:
                            self.variable_types[var_name] = library
                
                # Check for boolean indexing patterns: df = df[condition]
                elif isinstance(node.value, cst.Subscript):
                    self._check_boolean_indexing(node, var_name)
    
    def visit_Call(self, node: cst.Call) -> None:
        """Visit function calls to detect single mutations."""
        # Extract function information
        func_info = self._extract_function_info(node)
        if not func_info:
            return
        
        library, function_name = func_info
        
        # Only process pandas/numpy mutations here (SQL is handled separately)
        if library not in ['pandas', 'numpy']:
            return
        
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
    
    def _get_full_attribute_path(self, node: cst.BaseExpression) -> Optional[str]:
        """Get the full dotted path from an attribute expression."""
        if isinstance(node, cst.Name):
            return self.context.resolve_name(node.value)
        elif isinstance(node, cst.Attribute):
            base = self._get_full_attribute_path(node.value)
            if base:
                return f"{base}.{node.attr.value}"
        return None
    
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
    
    def _check_boolean_indexing(self, node: cst.Assign, var_name: str) -> None:
        """Check for boolean indexing patterns that filter data."""
        value = node.value
        if not isinstance(value, cst.Subscript):
            return
        
        # Check if this is indexing a DataFrame variable
        if isinstance(value.value, cst.Name):
            indexed_var = value.value.value
            
            # Check if the indexed variable is a pandas DataFrame
            if (indexed_var in self.variable_types and 
                self.variable_types[indexed_var] == 'pandas'):
                
                # This is likely boolean indexing on a DataFrame
                position = self._get_position(node)
                if not position:
                    position = (1, 0)
                
                line_number, column_offset = position
                code_snippet = self._extract_code_snippet(node, line_number)
                
                # Determine if this is likely filtering (reduces data)
                severity = Severity.MEDIUM
                mutation_type = "dataframe boolean indexing/filtering"
                notes = (f"Boolean indexing operation on DataFrame '{indexed_var}' which can "
                        f"filter out rows and reduce dataset size. "
                        f"This is a common pattern for data filtering but should be audited for data loss.")
                
                # Check if it's a negative filter (using ~) which often drops data
                if '~' in code_snippet:
                    severity = Severity.HIGH
                    notes = (f"Negative boolean indexing (using ~) on DataFrame '{indexed_var}' "
                            f"which explicitly drops/excludes rows from the dataset. "
                            f"This can result in significant data loss and should be carefully reviewed.")
                
                finding = Finding(
                    file_path=self.file_path,
                    line_number=line_number,
                    column_offset=column_offset,
                    library="pandas",
                    function_name="boolean_indexing",
                    mutation_type=mutation_type,
                    severity=severity,
                    code_snippet=code_snippet,
                    notes=notes,
                    rule_id="pandas.boolean_indexing",
                    extra_context={
                        'indexed_variable': indexed_var,
                        'target_variable': var_name,
                        'has_negation': '~' in code_snippet
                    }
                )
                
                self.findings.append(finding)
                
                # Update variable type tracking
                self.variable_types[var_name] = 'pandas' 