"""Test detection of previously missing data mutations."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.core.visitor import MutationVisitor
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check that we found the notnull operation
        notnull_findings = [f for f in visitor.findings if f.function_name == 'notnull']
        assert len(notnull_findings) >= 1, f"Should detect notnull(), got findings: {[f.function_name for f in visitor.findings]}"
        
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check that we found the rename operation with elevated severity
        rename_findings = [f for f in visitor.findings if f.function_name == 'rename']
        assert len(rename_findings) >= 1, f"Should detect rename(), got findings: {[f.function_name for f in visitor.findings]}"
        
        finding = rename_findings[0]
        assert finding.library == 'pandas'
        assert finding.severity == Severity.MEDIUM  # Should be elevated due to inplace=True
        assert 'inplace' in finding.extra_context.get('matched_arg', {}).get('name', '')
        
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check that we found astype operations
        astype_findings = [f for f in visitor.findings if f.function_name == 'astype']
        assert len(astype_findings) >= 2, f"Should detect 2 astype() calls, got findings: {[f.function_name for f in visitor.findings]}"
        
        for finding in astype_findings:
            assert finding.library == 'pandas'
            assert finding.mutation_type == 'data type conversion'
            assert finding.severity == Severity.MEDIUM
        
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Should detect this as a chain of mutations
        chain_findings = [f for f in visitor.findings if 'chain' in f.rule_id or '→' in f.function_name]
        if chain_findings:
            finding = chain_findings[0]
            assert 'groupby' in finding.function_name
            assert 'sum' in finding.function_name
        else:
            # Or detect individual functions
            groupby_findings = [f for f in visitor.findings if f.function_name == 'groupby']
            sum_findings = [f for f in visitor.findings if f.function_name == 'sum']
            assert len(groupby_findings) >= 1 or len(sum_findings) >= 1, \
                f"Should detect groupby or sum, got: {[f.function_name for f in visitor.findings]}"
        
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check that we found delete_from_db operation
        delete_findings = [f for f in visitor.findings if f.function_name == 'delete_from_db']
        assert len(delete_findings) >= 1, f"Should detect delete_from_db(), got findings: {[f.function_name for f in visitor.findings]}"
        
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check that we found boolean indexing operation
        boolean_findings = [f for f in visitor.findings if f.function_name == 'boolean_indexing']
        assert len(boolean_findings) >= 1, f"Should detect boolean indexing, got findings: {[f.function_name for f in visitor.findings]}"
        
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check that we found isin operation
        isin_findings = [f for f in visitor.findings if f.function_name == 'isin']
        assert len(isin_findings) >= 1, f"Should detect isin(), got findings: {[f.function_name for f in visitor.findings]}"
        
        finding = isin_findings[0]
        assert finding.library == 'pandas'
        assert 'filtering' in finding.mutation_type
        assert finding.severity == Severity.LOW
        
    finally:
        temp_path.unlink()


def test_t_py_comprehensive():
    """Test comprehensive detection on the actual t.py file with all new rules."""
    # Read the actual t.py file
    t_py_path = Path(__file__).parent / "t.py"
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
    visitor = MutationVisitor(t_py_path, rule_loader, context)
    visitor.set_source_code(code)
    
    # Visit the tree
    wrapper = cst.metadata.MetadataWrapper(tree)
    wrapper.visit(visitor)
    
    # Add hardcoded variable findings
    hardcoded_findings = visitor.detect_hardcoded_variables(tree, code)
    visitor.findings.extend(hardcoded_findings)
    
    # Count findings by type
    findings_by_function = {}
    for finding in visitor.findings:
        func_name = finding.function_name
        if func_name not in findings_by_function:
            findings_by_function[func_name] = 0
        findings_by_function[func_name] += 1
    
    print(f"Found {len(visitor.findings)} total findings:")
    for func_name, count in sorted(findings_by_function.items()):
        print(f"  {func_name}: {count}")
    
    # Verify specific mutations are detected
    assert 'notnull' in findings_by_function, "Should detect notnull()"
    assert 'astype' in findings_by_function, "Should detect astype()"
    assert 'delete_from_db' in findings_by_function, "Should detect delete_from_db()"
    assert 'sum' in findings_by_function, "Should detect sum()"
    assert 'groupby' in findings_by_function or any('groupby' in fn for fn in findings_by_function), "Should detect groupby()"
    
    # Should have more findings than before (at least 20)
    assert len(visitor.findings) >= 20, f"Should find at least 20 mutations, found {len(visitor.findings)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 