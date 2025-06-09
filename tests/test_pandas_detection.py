"""Test pandas mutation detection."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.visitors import MasterVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_pandas_drop_detection():
    """Test detection of pandas drop operations."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, 3], 'b': [4, 5, 6]})
df.drop('a', axis=1, inplace=True)  # Should be detected as CRITICAL
df2 = df.drop('b', axis=1)  # Should be detected as HIGH
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
        master_visitor = MasterVisitor(temp_path, rule_loader, context)
        findings = master_visitor.analyze(tree, code)
        
        # Filter for pandas-specific findings only (ignore hardcoded magic numbers)
        pandas_findings = [f for f in findings if f.library == 'pandas' and f.function_name == 'drop']
        
        # Check findings
        assert len(pandas_findings) == 2
        
        # Check that inplace=True escalates severity
        inplace_finding = next(f for f in pandas_findings if 'inplace=True' in f.code_snippet)
        assert inplace_finding.severity == Severity.CRITICAL
        
        # Check that regular drop is HIGH
        regular_finding = next(f for f in pandas_findings if 'inplace=True' not in f.code_snippet)
        assert regular_finding.severity == Severity.HIGH
        
    finally:
        temp_path.unlink()


def test_pandas_merge_detection():
    """Test detection of pandas merge operations."""
    code = """
import pandas as pd

df1 = pd.DataFrame({'key': [1, 2], 'val1': ['a', 'b']})
df2 = pd.DataFrame({'key': [1, 3], 'val2': ['x', 'y']})
result = df1.merge(df2, on='key')  # Should be detected
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
        master_visitor = MasterVisitor(temp_path, rule_loader, context)
        findings = master_visitor.analyze(tree, code)
        
        # Filter for pandas merge findings only (ignore hardcoded magic numbers)
        merge_findings = [f for f in findings if f.library == 'pandas' and f.function_name == 'merge']
        
        # Check findings
        assert len(merge_findings) == 1
        finding = merge_findings[0]
        assert finding.function_name == 'merge'
        assert finding.mutation_type == 'row-set merge'
        assert finding.severity == Severity.HIGH
        
    finally:
        temp_path.unlink()


def test_alias_resolution():
    """Test that aliases are properly resolved."""
    code = """
import pandas as pd
import numpy as np

df = pd.DataFrame({'a': [1, 2, 3]})
arr = np.array([1, 2, 3])

df.drop('a', axis=1)  # Should detect pandas
arr = np.delete(arr, 0)  # Should detect numpy
"""
    
    # Parse code
    tree = cst.parse_module(code)
    
    # Collect aliases
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    # Verify aliases were collected
    assert 'pd' in alias_collector.aliases
    assert alias_collector.aliases['pd'] == 'pandas'
    assert 'np' in alias_collector.aliases
    assert alias_collector.aliases['np'] == 'numpy'
    
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
        master_visitor = MasterVisitor(temp_path, rule_loader, context)
        findings = master_visitor.analyze(tree, code)
        
        # Filter for pandas/numpy specific findings only (ignore hardcoded magic numbers)
        mutation_findings = [f for f in findings if f.library in ['pandas', 'numpy'] and f.function_name in ['drop', 'delete']]
        
        # Check findings
        assert len(mutation_findings) == 2
        
        # Check libraries were resolved correctly
        libraries = {f.library for f in mutation_findings}
        assert 'pandas' in libraries
        assert 'numpy' in libraries
        
    finally:
        temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__]) 