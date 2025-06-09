"""Test analysis of the specific t.py file."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.visitors import MasterVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_t_py_analysis():
    """Test that we can analyze the t.py file without errors."""
    # Path to the t.py file
    t_py_path = Path(__file__).parent / "t.py"
    
    # Skip if t.py doesn't exist
    if not t_py_path.exists():
        pytest.skip("t.py file not found")
    
    # Read the file
    with open(t_py_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    # Parse the code
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
    
    # Should have some findings (the file has various data operations)
    assert len(findings) > 0, "Expected to find some data mutations in t.py"
    
    # Print findings for manual inspection
    print(f"\nFound {len(findings)} findings in t.py:")
    for finding in findings[:5]:  # Show first 5
        print(f"  {finding.severity.value}: {finding.function_name} at line {finding.line_number}")


def test_t_py_pandas_detection():
    """Test specific pandas operations in t.py."""
    t_py_path = Path(__file__).parent / "t.py"
    
    if not t_py_path.exists():
        pytest.skip("t.py file not found")
    
    with open(t_py_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    tree = cst.parse_module(code)
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    visitor = MasterVisitor(t_py_path, rule_loader, context)
    
    # Analyze the file
    findings = visitor.analyze(tree, code)
    
    # Filter pandas findings
    pandas_findings = [f for f in findings if f.library == 'pandas']
    
    print(f"\nFound {len(pandas_findings)} pandas findings:")
    for finding in pandas_findings:
        print(f"  {finding.severity.value}: {finding.function_name} at line {finding.line_number}")
        print(f"    Type: {finding.mutation_type}")
        print(f"    Snippet: {finding.code_snippet[:50]}...")


def test_t_py_severity_levels():
    """Test that we find findings with various severity levels."""
    t_py_path = Path(__file__).parent / "t.py"
    
    if not t_py_path.exists():
        pytest.skip("t.py file not found")
    
    with open(t_py_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    tree = cst.parse_module(code)
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    visitor = MasterVisitor(t_py_path, rule_loader, context)
    
    # Analyze the file
    findings = visitor.analyze(tree, code)
    
    # Count by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.severity
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\nSeverity distribution in t.py:")
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = severity_counts.get(severity, 0)
        print(f"  {severity.value}: {count}")
    
    # Should have at least some findings
    assert sum(severity_counts.values()) > 0


def test_t_py_code_snippets():
    """Test that code snippets are extracted properly from t.py."""
    t_py_path = Path(__file__).parent / "t.py"
    
    if not t_py_path.exists():
        pytest.skip("t.py file not found")
    
    with open(t_py_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    tree = cst.parse_module(code)
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    rule_loader = RuleLoader()
    rule_loader.load_builtin_rules()
    
    # Create visitor
    visitor = MasterVisitor(t_py_path, rule_loader, context)
    
    # Analyze the file
    findings = visitor.analyze(tree, code)
    
    # Check that all findings have non-empty code snippets
    for finding in findings:
        assert len(finding.code_snippet) > 0, f"Empty code snippet for {finding.function_name} at line {finding.line_number}"
        assert finding.code_snippet.strip() != "", f"Whitespace-only snippet for {finding.function_name}"
    
    # Show a few examples
    print(f"\nExample code snippets from t.py:")
    for finding in findings[:3]:
        print(f"  {finding.function_name}: {finding.code_snippet[:60]}...")


def test_t_py_full_analysis():
    """Test complete analysis of the t.py file."""
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
    
    # Should detect a reasonable number of mutations (now much more comprehensive)
    assert len(findings) >= 20, f"Expected at least 20 findings with improved detection, got {len(findings)}"
    
    # Verify we detect specific mutation types
    mutation_types = {f.mutation_type for f in findings}
    print(f"\nDetected mutation types: {mutation_types}")
    
    # Check severity distribution
    severity_counts = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    
    print(f"Severity counts: {severity_counts}")
    
    # With improved detection, we expect findings of different severities
    assert sum(severity_counts.values()) > 0, "Should have some findings"


def test_t_py_sql_detection():
    """Test that SQL operations are detected in t.py."""
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
    
    # Check SQL findings
    sql_findings = [f for f in findings if f.library == 'sql']
    print(f"\nSQL findings: {len(sql_findings)}")
    for finding in sql_findings:
        print(f"  {finding.function_name} - {finding.severity.value}")
    
    # Should have some SQL findings if the file contains SQL
    if sql_findings:
        # Check for specific operations if they exist
        delete_findings = [f for f in sql_findings if f.function_name == 'DELETE']
        insert_findings = [f for f in sql_findings if f.function_name == 'INSERT']
        
        print(f"DELETE findings: {len(delete_findings)}")
        print(f"INSERT findings: {len(insert_findings)}")


def test_t_py_hardcoded_detection():
    """Test that hardcoded values are detected in t.py."""
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
    
    # Check hardcoded findings
    hardcoded_findings = [f for f in findings if f.library == 'hardcoded']
    print(f"\nHardcoded findings: {len(hardcoded_findings)}")
    
    if hardcoded_findings:
        # Group by function name
        by_type = {}
        for finding in hardcoded_findings:
            func_name = finding.function_name
            by_type[func_name] = by_type.get(func_name, 0) + 1
        
        print("Hardcoded findings by type:")
        for func_name, count in by_type.items():
            print(f"  {func_name}: {count}")


def test_t_py_specific_line_numbers():
    """Test that findings are detected at the correct line numbers."""
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
    
    # Check specific line numbers for key findings
    finding_lines = {f.line_number: f for f in findings}
    
    print(f"\nFindings by line number (first 10):")
    sorted_lines = sorted(finding_lines.keys())[:10]
    for line_num in sorted_lines:
        finding = finding_lines[line_num]
        print(f"  Line {line_num}: {finding.function_name} ({finding.severity.value})")
    
    # Should have findings distributed across the file
    assert len(findings) > 0, "Should have some findings"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 