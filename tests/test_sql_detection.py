"""Test SQL mutation detection."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext
from datamut.core.loader import RuleLoader
from datamut.visitors import MasterVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_sql_delete_detection():
    """Test detection of SQL DELETE operations."""
    code = '''
import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute("DELETE FROM users WHERE active = 0")
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
        master_visitor = MasterVisitor(temp_path, rule_loader, context)
        findings = master_visitor.analyze(tree, code)
        
        # Check findings
        assert len(findings) == 1
        finding = findings[0]
        assert finding.function_name == 'DELETE'
        assert finding.mutation_type == 'data deletion'
        assert finding.severity == Severity.CRITICAL
        assert finding.library == 'sql'
        
    finally:
        temp_path.unlink()


def test_sql_insert_detection():
    """Test detection of SQL INSERT operations."""
    code = '''
import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
sql = "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')"
cursor.execute(sql)
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
        master_visitor = MasterVisitor(temp_path, rule_loader, context)
        findings = master_visitor.analyze(tree, code)
        
        # Check findings - should detect both the variable assignment and the execute call
        findings = [f for f in findings if f.function_name == 'INSERT']
        assert len(findings) >= 1
        
        finding = findings[0]
        assert finding.mutation_type == 'data insertion'
        assert finding.severity == Severity.MEDIUM
        assert finding.library == 'sql'
        
    finally:
        temp_path.unlink()


def test_multiple_sql_operations():
    """Test detection of multiple SQL operations in one file."""
    code = '''
import sqlite3

conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

# Create table
cursor.execute("CREATE TABLE users (id INTEGER, name TEXT)")

# Insert data
cursor.execute("INSERT INTO users VALUES (1, 'Alice')")

# Update data  
cursor.execute("UPDATE users SET name = 'Bob' WHERE id = 1")

# Delete data
cursor.execute("DELETE FROM users WHERE id = 1")

# Drop table
cursor.execute("DROP TABLE users")
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
        master_visitor = MasterVisitor(temp_path, rule_loader, context)
        findings = master_visitor.analyze(tree, code)
        
        # Check findings
        assert len(findings) >= 5  # CREATE, INSERT, UPDATE, DELETE, DROP
        
        # Check that we detected all expected operations
        detected_ops = {f.function_name for f in findings}
        expected_ops = {'CREATE', 'INSERT', 'UPDATE', 'DELETE', 'DROP'}
        assert expected_ops.issubset(detected_ops)
        
        # Check severity levels
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 2  # DELETE and DROP should be CRITICAL
        
    finally:
        temp_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__]) 