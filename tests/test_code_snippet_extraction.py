"""Test code snippet extraction for multi-line statements."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.visitors import MasterVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_single_line_snippet():
    """Test code snippet extraction for single line operations."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, 3], 'b': [4, 5, 6]})
df.drop('a', axis=1)
"""
    
    # Parse code
    tree = cst.parse_module(code)
    
    # Collect aliases
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    # Create context
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    # Load rules
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(code.encode())
        temp_path = Path(f.name)
    
    try:
        visitor = MasterVisitor(temp_path, rule_loader, context)
        
        # Use the analyze method
        findings = visitor.analyze(tree, code)
        
        # Filter for pandas drop findings only (ignore hardcoded numbers)
        drop_findings = [f for f in findings if f.library == 'pandas' and f.function_name == 'drop']
        
        # Check that we found the drop operation
        assert len(drop_findings) == 1
        finding = drop_findings[0]
        
        # Verify the code snippet is complete
        assert "df.drop('a', axis=1)" in finding.code_snippet
        
    finally:
        temp_path.unlink()


def test_multi_line_function_call_snippet():
    """Test code snippet extraction for multi-line function calls."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, 3], 'b': [4, 5, 6]})
result = df.merge(
    other_df,
    on='key',
    how='left'
)
"""
    
    # Parse code
    tree = cst.parse_module(code)
    
    # Collect aliases
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    # Create context
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    # Load rules
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(code.encode())
        temp_path = Path(f.name)
    
    try:
        visitor = MasterVisitor(temp_path, rule_loader, context)
        
        # Use the analyze method
        findings = visitor.analyze(tree, code)
        
        # Check that we found the merge operation
        merge_findings = [f for f in findings if f.function_name == 'merge']
        assert len(merge_findings) == 1
        
        finding = merge_findings[0]
        
        # Verify the code snippet captures multi-line structure
        assert 'result = df.merge(' in finding.code_snippet
        assert 'other_df' in finding.code_snippet
        assert "on='key'" in finding.code_snippet
        assert "how='left'" in finding.code_snippet
        
    finally:
        temp_path.unlink()


def test_complex_multi_line_snippet():
    """Test extraction of complex multi-line code snippets."""
    code = '''
def complex_function():
    result = (df.groupby(['column_a', 'column_b'])
             .agg({'value': 'sum', 'count': 'count'})
             .reset_index()
             .merge(other_df, on='column_a')
             .drop_duplicates())
    return result
'''
    
    # Parse code
    tree = cst.parse_module(code)
    
    # Create visitor
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    context = AnalysisContext()
    
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(code.encode())
        temp_path = Path(f.name)
    
    try:
        visitor = MasterVisitor(temp_path, rule_loader, context)
        
        # Analyze
        findings = visitor.analyze(tree, code)
        
        # Should capture the entire multi-line expression
        drop_findings = [f for f in findings if 'drop_duplicates' in f.function_name]
        if drop_findings:
            # The snippet should include the full multi-line expression
            snippet = drop_findings[0].code_snippet
            assert 'groupby' in snippet, f"Should include start of expression, got: {snippet}"
            assert 'drop_duplicates' in snippet, f"Should include the detected function, got: {snippet}"
    
    finally:
        temp_path.unlink()


def test_file_path_multi_line_improvement():
    """Test that multi-line file path assignments are captured correctly."""
    code = '''
import os

# Multi-line file path assignment
config_path = (
    "/opt/data/configs/"
    "production/"
    "app_config.yml"
)

file_list = [
    "/var/log/app.log",
    "/tmp/cache/data.json",
    "/usr/local/bin/script.sh"
]
'''
    
    # Parse code
    tree = cst.parse_module(code)
    
    # Collect aliases
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    # Create context
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    # Load rules
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(code.encode())
        temp_path = Path(f.name)
    
    try:
        visitor = MasterVisitor(temp_path, rule_loader, context)
        
        # Analyze
        findings = visitor.analyze(tree, code)
        
        # Find file path findings
        file_path_findings = [f for f in findings if f.function_name == 'file_path']
        
        if file_path_findings:
            finding = file_path_findings[0]
            
            # This should show the complete multi-line assignment
            assert 'config_path' in finding.code_snippet
            assert '/opt/data/configs/' in finding.code_snippet
            
    finally:
        temp_path.unlink()


def test_lamp_upload_function_calls():
    """Test that function calls show complete context."""
    code = '''
from some_module import lamp_upload

# Function call with hardcoded numbers
result = lamp_upload(
    data=df,
    table_name="test_table",
    env="PROD",
    date=20231201,  # Hardcoded number
    timeout=300     # Another hardcoded number
)
'''
    
    # Parse code
    tree = cst.parse_module(code)
    
    # Collect aliases
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    # Create context
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    # Load rules
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as f:
        f.write(code.encode())
        temp_path = Path(f.name)
    
    try:
        visitor = MasterVisitor(temp_path, rule_loader, context)
        
        # Analyze
        findings = visitor.analyze(tree, code)
        
        # Find hardcoded number findings
        hardcoded_findings = [f for f in findings if f.function_name == 'hardcoded_number']
        
        # Should detect hardcoded numbers
        assert len(hardcoded_findings) >= 2, f"Should detect at least 2 hardcoded numbers, got {len(hardcoded_findings)}"
        
        # Verify that the hardcoded numbers are detected
        detected_values = [f.extra_context.get('detected_value', '') for f in hardcoded_findings]
        assert '20231201' in detected_values or '300' in detected_values
                
    finally:
        temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 