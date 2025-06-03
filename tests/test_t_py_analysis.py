"""Test analysis of the specific t.py file."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.core.visitor import MutationVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_t_py_full_analysis():
    """Test complete analysis of the t.py file."""
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
    
    # Verify we found the expected number of findings
    assert len(visitor.findings) == 16, f"Expected 16 findings, got {len(visitor.findings)}"
    
    # Check severity distribution
    severity_counts = {}
    for finding in visitor.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    
    assert severity_counts[Severity.CRITICAL] == 1, f"Expected 1 CRITICAL, got {severity_counts.get(Severity.CRITICAL, 0)}"
    assert severity_counts[Severity.MEDIUM] == 4, f"Expected 4 MEDIUM, got {severity_counts.get(Severity.MEDIUM, 0)}"
    assert severity_counts[Severity.LOW] == 11, f"Expected 11 LOW, got {severity_counts.get(Severity.LOW, 0)}"


def test_t_py_sql_detection():
    """Test that SQL operations are detected in t.py."""
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
    
    # Check SQL findings
    sql_findings = [f for f in visitor.findings if f.library == 'sql']
    assert len(sql_findings) == 2, f"Expected 2 SQL findings, got {len(sql_findings)}"
    
    # Check for DELETE operation (should be CRITICAL)
    delete_findings = [f for f in sql_findings if f.function_name == 'DELETE']
    assert len(delete_findings) == 1
    assert delete_findings[0].severity == Severity.CRITICAL
    assert delete_findings[0].mutation_type == 'data deletion'
    
    # Check for INSERT operation (should be MEDIUM)
    insert_findings = [f for f in sql_findings if f.function_name == 'INSERT']
    assert len(insert_findings) == 1
    assert insert_findings[0].severity == Severity.MEDIUM
    assert insert_findings[0].mutation_type == 'data insertion'


def test_t_py_hardcoded_detection():
    """Test that hardcoded values are detected in t.py."""
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
    
    # Add hardcoded variable findings
    hardcoded_findings = visitor.detect_hardcoded_variables(tree, code)
    visitor.findings.extend(hardcoded_findings)
    
    # Check hardcoded findings
    hardcoded_findings_filtered = [f for f in visitor.findings if f.library == 'hardcoded']
    assert len(hardcoded_findings_filtered) == 14, f"Expected 14 hardcoded findings, got {len(hardcoded_findings_filtered)}"
    
    # Check for URL detection
    url_findings = [f for f in hardcoded_findings_filtered if f.function_name == 'url_endpoint']
    assert len(url_findings) == 2
    for finding in url_findings:
        assert finding.severity == Severity.MEDIUM
        assert 'https://ends.cs.rbc.com' in finding.extra_context['detected_value']
    
    # Check for file path detection
    file_path_findings = [f for f in hardcoded_findings_filtered if f.function_name == 'file_path']
    assert len(file_path_findings) == 1
    assert file_path_findings[0].severity == Severity.MEDIUM
    assert 'castvsfg6.fg.rbc.com' in file_path_findings[0].extra_context['detected_value']
    
    # Check for magic numbers
    magic_number_findings = [f for f in hardcoded_findings_filtered if f.function_name == 'magic_number']
    assert len(magic_number_findings) == 11
    
    # Verify specific magic numbers are detected
    detected_values = {f.extra_context['detected_value'] for f in magic_number_findings}
    expected_numbers = {'365', '3500000000', '5314', '12361', '12362', '12363', '12364', '12365', '12366', '12367'}
    assert len(expected_numbers.intersection(detected_values)) >= 9, f"Expected magic numbers not found. Got: {detected_values}"


def test_t_py_specific_line_numbers():
    """Test that findings are detected at the correct line numbers."""
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
    
    # Check specific line numbers for key findings
    finding_lines = {f.line_number: f for f in visitor.findings}
    
    # Check that we have findings around expected lines
    # These are approximate since line numbers might shift slightly
    expected_ranges = [
        (140, 150),  # SQL operations around line 147-149
        (160, 170),  # URL around line 163
        (175, 180),  # Large number around line 177
        (185, 190),  # Function call with number around line 188
        (190, 210),  # Multiple lamp_upload calls with magic numbers
        (200, 210),  # File path around line 205
        (220, 230),  # Final lamp_upload around line 226
    ]
    
    findings_in_ranges = 0
    for start, end in expected_ranges:
        range_findings = [line for line in finding_lines.keys() if start <= line <= end]
        if range_findings:
            findings_in_ranges += 1
    
    # We should have findings in most of these ranges
    assert findings_in_ranges >= 5, f"Expected findings in at least 5 ranges, found in {findings_in_ranges}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 