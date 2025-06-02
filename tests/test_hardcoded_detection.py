"""Tests for hardcoded variable detection."""

import tempfile
from pathlib import Path

from datamut.cli import analyze_file
from datamut.core.loader import RuleLoader
from datamut.core.finding import Severity


def test_hardcoded_credentials_detection():
    """Test detection of hardcoded credentials."""
    code = '''
username = "admin"
password = "secret123"
api_key = "sk-1234567890abcdef1234567890abcdef"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded credentials
        credential_findings = [f for f in findings if f.library == "hardcoded" and f.function_name in ["credentials", "api_key"]]
        assert len(credential_findings) >= 2, f"Expected at least 2 credential findings, got {len(credential_findings)}"
        
        # Check severity levels
        critical_findings = [f for f in credential_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 2, f"Expected at least 2 critical findings, got {len(critical_findings)}"


def test_hardcoded_database_connection():
    """Test detection of hardcoded database connections."""
    code = '''
db_url = "mysql://user:password@localhost:3306/mydb"
connection_string = "postgresql://admin:secret@192.168.1.100:5432/production"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded database connections
        db_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "database_connection"]
        assert len(db_findings) >= 2, f"Expected at least 2 database connection findings, got {len(db_findings)}"
        
        # Check severity levels
        high_findings = [f for f in db_findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 2, f"Expected at least 2 high severity findings, got {len(high_findings)}"


def test_hardcoded_file_paths():
    """Test detection of hardcoded file paths."""
    code = '''
config_file = "/etc/myapp/config.json"
log_path = "C:\\\\Program Files\\\\MyApp\\\\logs\\\\app.log"
data_directory = "/var/data/uploads"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded file paths
        path_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "file_path"]
        assert len(path_findings) >= 2, f"Expected at least 2 file path findings, got {len(path_findings)}"


def test_hardcoded_urls():
    """Test detection of hardcoded URLs."""
    code = '''
api_endpoint = "https://api.example.com/v1/users"
webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
base_url = "http://localhost:8080"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded URLs
        url_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "url_endpoint"]
        assert len(url_findings) >= 3, f"Expected at least 3 URL findings, got {len(url_findings)}"


def test_magic_numbers():
    """Test detection of magic numbers."""
    code = '''
timeout_seconds = 300
buffer_size = 4096
max_file_size = 10485760
connection_pool_size = 50

# These should not trigger
count = 0
index = 1
percentage = 0.5
small_number = 10
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find magic numbers
        magic_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "magic_number"]
        assert len(magic_findings) >= 3, f"Expected at least 3 magic number findings, got {len(magic_findings)}"
        
        # Check that small safe numbers are not flagged
        for finding in magic_findings:
            assert "count = 0" not in finding.code_snippet
            assert "index = 1" not in finding.code_snippet
            assert "small_number = 10" not in finding.code_snippet


def test_email_addresses():
    """Test detection of hardcoded email addresses."""
    code = '''
admin_email = "admin@company.com"
support_email = "support@example.org"
notification_recipient = "alerts@company.com"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded email addresses
        email_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "email_address"]
        assert len(email_findings) >= 3, f"Expected at least 3 email findings, got {len(email_findings)}"


def test_ip_addresses():
    """Test detection of hardcoded IP addresses."""
    code = '''
server_ip = "192.168.1.50"
database_host = "10.0.0.100"
external_api = "203.0.113.1"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded IP addresses
        ip_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "ip_address"]
        assert len(ip_findings) >= 2, f"Expected at least 2 IP address findings, got {len(ip_findings)}"


def test_false_positive_reduction():
    """Test that common legitimate values don't trigger false positives."""
    code = '''
app_name = "DataMut"
version = "1.0.0"
status = "active"
debug = True
count = 0
index = 1
percentage = 0.5
small_timeout = 10
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should have minimal or no hardcoded findings for legitimate values
        hardcoded_findings = [f for f in findings if f.library == "hardcoded"]
        
        # Check that common safe values are not flagged
        for finding in hardcoded_findings:
            assert "app_name" not in finding.code_snippet
            assert "version" not in finding.code_snippet
            assert "status" not in finding.code_snippet
            assert "count = 0" not in finding.code_snippet
            assert "index = 1" not in finding.code_snippet


def test_hardcoded_in_function_calls():
    """Test detection of hardcoded values in function calls."""
    code = '''
import sqlite3

def connect_to_database():
    conn = sqlite3.connect("/tmp/app.db")
    return conn

def send_notification():
    recipient = "alerts@company.com"
    return f"Sending notification to {recipient}"
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded values in function calls
        hardcoded_findings = [f for f in findings if f.library == "hardcoded"]
        assert len(hardcoded_findings) >= 1, f"Expected at least 1 hardcoded finding, got {len(hardcoded_findings)}" 