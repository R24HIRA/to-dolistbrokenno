"""Test SQL mutation detection."""

import tempfile
from pathlib import Path

import pytest

from datamut.core.context import AliasCollector, AnalysisContext, SQLContext
from datamut.core.loader import RuleLoader
from datamut.core.visitor import MutationVisitor
from datamut.core.finding import Severity

import libcst as cst


def test_sql_keyword_detection():
    """Test detection of SQL mutation keywords."""
    sql_statements = [
        ("INSERT INTO table VALUES (1, 2)", "data insertion"),
        ("UPDATE table SET col = 1", "data update"),
        ("DELETE FROM table WHERE id = 1", "data deletion"),
        ("DROP TABLE table", "schema/data drop"),
        ("TRUNCATE TABLE table", "data truncation"),
    ]
    
    for sql, expected_mutation in sql_statements:
        mutations = SQLContext.analyze_sql_string(sql)
        assert len(mutations) >= 1
        assert any(m['mutation_type'] == expected_mutation for m in mutations)


def test_sql_in_python_code():
    """Test detection of SQL in Python string literals."""
    code = '''
import sqlite3

conn = sqlite3.connect("test.db")
cursor = conn.cursor()

# This should be detected
cursor.execute("DELETE FROM users WHERE active = 0")

# This should also be detected
query = """
    UPDATE products 
    SET price = price * 1.1 
    WHERE category = 'electronics'
"""
cursor.execute(query)

# This should be detected too
cursor.execute("DROP TABLE temp_data")
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
        visitor = MutationVisitor(temp_path, rule_loader, context)
        visitor.set_source_code(code)
        
        # Visit the tree
        wrapper = cst.metadata.MetadataWrapper(tree)
        wrapper.visit(visitor)
        
        # Check findings
        assert len(visitor.findings) >= 3  # DELETE, UPDATE, DROP
        
        # Check that SQL operations are detected
        sql_functions = {f.function_name for f in visitor.findings if f.library == 'sql'}
        assert 'DELETE' in sql_functions
        assert 'UPDATE' in sql_functions
        assert 'DROP' in sql_functions
        
        # Check severities
        delete_finding = next(f for f in visitor.findings if f.function_name == 'DELETE')
        assert delete_finding.severity == Severity.CRITICAL
        
        update_finding = next(f for f in visitor.findings if f.function_name == 'UPDATE')
        assert update_finding.severity == Severity.HIGH
        
        drop_finding = next(f for f in visitor.findings if f.function_name == 'DROP')
        assert drop_finding.severity == Severity.CRITICAL
        
    finally:
        temp_path.unlink()


def test_sql_context_analysis():
    """Test SQL context analysis functionality."""
    # Test simple SQL parsing
    sql = "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')"
    mutations = SQLContext.analyze_sql_string(sql)
    
    assert len(mutations) == 1
    assert mutations[0]['keyword'] == 'INSERT'
    assert mutations[0]['mutation_type'] == 'data insertion'
    
    # Test complex SQL with multiple operations
    complex_sql = """
    BEGIN TRANSACTION;
    DELETE FROM temp_table;
    INSERT INTO main_table SELECT * FROM temp_table;
    DROP TABLE temp_table;
    COMMIT;
    """
    
    mutations = SQLContext.analyze_sql_string(complex_sql)
    keywords = {m['keyword'] for m in mutations}
    
    assert 'DELETE' in keywords
    assert 'INSERT' in keywords
    assert 'DROP' in keywords


def test_sql_looks_like_detection():
    """Test the heuristic for detecting SQL-like strings."""
    from datamut.core.visitor import MutationVisitor
    
    # Create a dummy visitor to test the method
    visitor = MutationVisitor(Path("dummy.py"), RuleLoader(), AnalysisContext())
    
    # These should be detected as SQL
    assert visitor._looks_like_sql("SELECT * FROM table")
    assert visitor._looks_like_sql("INSERT INTO users VALUES (1, 'test')")
    assert visitor._looks_like_sql("UPDATE table SET col = 1 WHERE id = 2")
    assert visitor._looks_like_sql("DELETE FROM table WHERE condition")
    assert visitor._looks_like_sql("CREATE TABLE test (id INT)")
    
    # These should not be detected as SQL
    assert not visitor._looks_like_sql("This is just a regular string")
    assert not visitor._looks_like_sql("print('Hello, world!')")
    assert not visitor._looks_like_sql("def function_name():")


if __name__ == "__main__":
    pytest.main([__file__]) 