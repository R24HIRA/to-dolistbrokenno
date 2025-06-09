"""Visitor for detecting SQL mutation operations in string literals."""

from typing import Dict

import libcst as cst

from .base import BaseVisitor
from ..core.finding import Finding


class SQLVisitor(BaseVisitor):
    """Visitor for detecting SQL operations in string literals."""
    
    def __init__(self, file_path, rule_loader, context):
        super().__init__(file_path, rule_loader, context)
        self.sql_variables: Dict[str, str] = {}  # Track variables containing SQL strings
    
    def visit_Assign(self, node: cst.Assign) -> None:
        """Track variable assignments that contain SQL strings."""
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target.target, cst.Name):
                var_name = target.target.value
                
                # Check if the assigned value is a string that contains SQL operations
                if isinstance(node.value, (cst.SimpleString, cst.ConcatenatedString)):
                    sql_text = self._extract_string_value(node.value)
                    if sql_text and self._contains_sql_operations(sql_text):
                        self.sql_variables[var_name] = sql_text
    
    def visit_SimpleStatementLine(self, node: cst.SimpleStatementLine) -> None:
        """Visit simple statements to check for SQL strings."""
        for stmt in node.body:
            if isinstance(stmt, cst.Expr) and isinstance(stmt.value, cst.Call):
                self._check_sql_in_call(stmt.value, node)
    
    def _check_sql_in_call(self, call_node: cst.Call, stmt_node: cst.SimpleStatementLine) -> None:
        """Check for SQL strings in function calls."""
        for arg in call_node.args:
            # Check direct string literals
            if isinstance(arg.value, (cst.SimpleString, cst.ConcatenatedString)):
                sql_text = self._extract_string_value(arg.value)
                if sql_text and self._contains_sql_operations(sql_text):
                    self._process_sql_string(sql_text, stmt_node)
            
            # Check variables that contain SQL strings
            elif isinstance(arg.value, cst.Name):
                var_name = arg.value.value
                if var_name in self.sql_variables:
                    sql_text = self.sql_variables[var_name]
                    self._process_sql_string(sql_text, stmt_node)
    
    def _contains_sql_operations(self, text: str) -> bool:
        """Check if text contains SQL operations using the loaded rules."""
        if not text or len(text.strip()) < 3:
            return False
            
        # Get all SQL rules from the rule loader
        sql_bundle = None
        for bundle in self.rule_loader.bundles:
            if bundle.meta.library == 'sql':
                sql_bundle = bundle
                break
        
        if not sql_bundle:
            return False
        
        # Check if any SQL rule keywords are present in the text
        text_upper = text.upper()
        for rule in sql_bundle.rules:
            # Check if the rule function name (SQL keyword) is in the text
            if rule.func.upper() in text_upper:
                return True
        
        return False
    
    def _process_sql_string(self, sql_text: str, stmt_node: cst.SimpleStatementLine) -> None:
        """Process SQL string and create findings based on rules."""
        position = self._get_position(stmt_node)
        if not position:
            return
        
        line_number, column_offset = position
        
        # Extract SQL keywords and check against rules
        sql_upper = sql_text.upper()
        words = sql_upper.split()
        
        for word in words:
            # Check if this word matches any SQL rule
            rule = self.rule_loader.get_rule("sql", word)
            if rule:
                finding = Finding(
                    file_path=self.file_path,
                    line_number=line_number,
                    column_offset=column_offset,
                    library="sql",
                    function_name=word,
                    mutation_type=rule.mutation,
                    severity=rule.default_severity,
                    code_snippet=self._extract_code_snippet(stmt_node, line_number),
                    notes=rule.notes or f"SQL {word} operation detected in string literal",
                    rule_id=rule.rule_id,
                    extra_context={'sql_text': sql_text[:100] + '...' if len(sql_text) > 100 else sql_text}
                )
                
                self.findings.append(finding) 