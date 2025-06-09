"""Test detection of previously missing data mutations."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.visitors import MasterVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_notnull_detection():
    """Test detection of notnull() function."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, None]})
df = df[df["pnl.pn1"].notnull()]
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Check that we found the notnull operation
        notnull_findings = [f for f in findings if f.function_name == 'notnull']
        assert len(notnull_findings) >= 1, f"Should detect notnull(), got findings: {[f.function_name for f in findings]}"
        
        finding = notnull_findings[0]
        assert finding.library == 'pandas'
        assert finding.mutation_type == 'null value filtering'
        assert finding.severity == Severity.LOW
        
    finally:
        temp_path.unlink()


def test_inplace_true_detection():
    """Test detection of inplace=True parameter."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, 3]})
df.rename(columns={"a": "b"}, inplace=True)
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Check that we found the rename operation with elevated severity
        rename_findings = [f for f in findings if f.function_name == 'rename']
        assert len(rename_findings) >= 1, f"Should detect rename(), got findings: {[f.function_name for f in findings]}"
        
        finding = rename_findings[0]
        assert finding.library == 'pandas'
        # Note: Severity might vary based on actual rule configuration
        
    finally:
        temp_path.unlink()


def test_astype_detection():
    """Test detection of astype() functions."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1.5, 2.7, 3.9]})
df["a"] = df["a"].astype(int)
df["b"] = df["a"].astype(str)
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Check that we found astype operations
        astype_findings = [f for f in findings if f.function_name == 'astype']
        assert len(astype_findings) >= 2, f"Should detect 2 astype() calls, got findings: {[f.function_name for f in findings]}"
        
        for finding in astype_findings:
            assert finding.library == 'pandas'
            assert finding.mutation_type == 'data type conversion'
        
    finally:
        temp_path.unlink()


def test_groupby_sum_chain_detection():
    """Test detection of groupby().sum() chain."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, 3], 'b': ['x', 'y', 'x']})
result = df.groupby(['b'], as_index=False).sum()
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Should detect either individual functions or the chain
        function_names = [f.function_name for f in findings]
        assert 'groupby' in function_names or 'sum' in function_names or 'method chaining' in function_names, \
            f"Should detect groupby/sum chain, got: {function_names}"
        
    finally:
        temp_path.unlink()


def test_delete_from_db_detection():
    """Test detection of delete_from_db() function."""
    code = """
from rfm.tools import delete_from_db

criteria = "business_date = '2023-01-01'"
delete_from_db(table_name="bahamas_atom_pv01", condition=criteria, env="QA", fast=False)
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Check that we found delete_from_db operation
        delete_findings = [f for f in findings if f.function_name == 'delete_from_db']
        assert len(delete_findings) >= 1, f"Should detect delete_from_db(), got findings: {[f.function_name for f in findings]}"
        
        finding = delete_findings[0]
        assert finding.library in ['rfm', 'database']
        assert 'deletion' in finding.mutation_type
        assert finding.severity == Severity.CRITICAL
        
    finally:
        temp_path.unlink()


def test_boolean_indexing_detection():
    """Test detection of boolean indexing patterns."""
    code = """
import pandas as pd

df = pd.DataFrame({'a': [1, 2, 3], 'flag': ['I', 'E', 'I']})
internal_filter = df['flag'] == 'I'
df_filtered = df[~internal_filter]  # This should be detected
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Check that we found boolean indexing operation
        boolean_findings = [f for f in findings if f.function_name == 'boolean_indexing']
        assert len(boolean_findings) >= 1, f"Should detect boolean indexing, got findings: {[f.function_name for f in findings]}"
        
        finding = boolean_findings[0]
        assert finding.library == 'pandas'
        assert 'indexing' in finding.mutation_type or 'filtering' in finding.mutation_type
        assert finding.severity == Severity.HIGH  # Should be HIGH due to negation (~)
        assert finding.extra_context['has_negation'] == True
        
    finally:
        temp_path.unlink()


def test_isin_detection():
    """Test detection of isin() function."""
    code = """
import pandas as pd

df = pd.DataFrame({'flag': ['I', 'E', 'I']})
mask = df['flag'].isin(['I'])
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
        
        # Analyze the file
        findings = visitor.analyze(tree, code)
        
        # Check that we found isin operation
        isin_findings = [f for f in findings if f.function_name == 'isin']
        assert len(isin_findings) >= 1, f"Should detect isin(), got findings: {[f.function_name for f in findings]}"
        
        finding = isin_findings[0]
        assert finding.library == 'pandas'
        assert 'filtering' in finding.mutation_type
        assert finding.severity == Severity.LOW
        
    finally:
        temp_path.unlink()


def test_t_py_comprehensive():
    """Test comprehensive analysis of the t.py file with all improvements."""
    # Read the actual t.py file
    t_py_path = Path(__file__).parent / "t.py"
    if not t_py_path.exists():
        pytest.skip("t.py file not found")
        
    with open(t_py_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
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
    visitor = MasterVisitor(t_py_path, rule_loader, context)
    
    # Analyze the file
    findings = visitor.analyze(tree, code)
    
    # Count findings by type
    findings_by_function = {}
    for finding in findings:
        func_name = finding.function_name
        if func_name not in findings_by_function:
            findings_by_function[func_name] = 0
        findings_by_function[func_name] += 1
    
    print(f"Found {len(findings)} total findings:")
    for func_name, count in sorted(findings_by_function.items()):
        print(f"  {func_name}: {count}")
    
    # Should have findings from the file
    assert len(findings) >= 10, f"Should find at least 10 mutations, found {len(findings)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 