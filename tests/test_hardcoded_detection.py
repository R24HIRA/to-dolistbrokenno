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
        
        # Check severity levels - ALL should be CRITICAL now
        critical_findings = [f for f in db_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 2, f"Expected at least 2 critical severity findings, got {len(critical_findings)}"


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
        
        # Should find hardcoded file paths - ALL CRITICAL
        path_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "file_path"]
        assert len(path_findings) >= 2, f"Expected at least 2 file path findings, got {len(path_findings)}"
        
        # ALL should be CRITICAL
        critical_findings = [f for f in path_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 2, f"Expected all file path findings to be CRITICAL, got {len(critical_findings)}"


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
        
        # Should find hardcoded URLs - ALL CRITICAL
        url_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "url_endpoint"]
        assert len(url_findings) >= 3, f"Expected at least 3 URL findings, got {len(url_findings)}"
        
        # ALL should be CRITICAL
        critical_findings = [f for f in url_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 3, f"Expected all URL findings to be CRITICAL, got {len(critical_findings)}"


def test_hardcoded_numbers():
    """Test detection of hardcoded numbers - AGGRESSIVE for financial institutions."""
    code = '''
timeout_seconds = 300
buffer_size = 4096
max_file_size = 10485760
connection_pool_size = 50

# Only these basic values should not trigger
count = 0
index = 1
negative_flag = -1

# These SHOULD trigger in financial context
small_number = 10       # Could be financial amount
percentage = 0.5        # Could be financial percentage
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should find hardcoded numbers - more aggressive than before
        hardcoded_number_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "hardcoded_number"]
        assert len(hardcoded_number_findings) >= 5, f"Expected at least 5 hardcoded number findings (including 10 and 0.5), got {len(hardcoded_number_findings)}"
        
        # Check that ONLY the most basic safe numbers are not flagged
        flagged_snippets = [f.code_snippet for f in hardcoded_number_findings]
        
        # These should NOT be flagged (basic safe values)
        assert not any("count = 0" in snippet for snippet in flagged_snippets)
        assert not any("index = 1" in snippet for snippet in flagged_snippets)  
        assert not any("negative_flag = -1" in snippet for snippet in flagged_snippets)
        
        # These SHOULD be flagged in financial context
        assert any("small_number = 10" in snippet for snippet in flagged_snippets), "10 should be flagged in financial context"
        assert any("percentage = 0.5" in snippet for snippet in flagged_snippets), "0.5 should be flagged as potential financial percentage"


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
        
        # Should find hardcoded email addresses - ALL CRITICAL
        email_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "email_address"]
        assert len(email_findings) >= 3, f"Expected at least 3 email findings, got {len(email_findings)}"
        
        # ALL should be CRITICAL
        critical_findings = [f for f in email_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 3, f"Expected all email findings to be CRITICAL, got {len(critical_findings)}"


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
        
        # Should find hardcoded IP addresses - ALL CRITICAL
        ip_findings = [f for f in findings if f.library == "hardcoded" and f.function_name == "ip_address"]
        assert len(ip_findings) >= 2, f"Expected at least 2 IP address findings, got {len(ip_findings)}"
        
        # ALL should be CRITICAL
        critical_findings = [f for f in ip_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 2, f"Expected all IP address findings to be CRITICAL, got {len(critical_findings)}"


def test_false_positive_reduction():
    """Test that only basic safe values don't trigger false positives in financial context."""
    code = '''
app_name = "DataMut"
version = "1.0.0"
status = "active"
debug = True

# Only these should not trigger in financial context
count = 0
index = 1
error_flag = -1

# This SHOULD trigger since any other number could be financial
timeout = 10
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        
        rule_loader = RuleLoader()
        rule_loader.load_builtin_rules()
        
        findings = analyze_file(Path(f.name), rule_loader)
        
        # Should have at least one finding for the timeout value
        hardcoded_findings = [f for f in findings if f.library == "hardcoded"]
        assert len(hardcoded_findings) >= 1, f"Expected at least 1 hardcoded finding for timeout, got {len(hardcoded_findings)}"
        
        # Check that only the most basic safe values are not flagged
        flagged_snippets = [f.code_snippet for f in hardcoded_findings]
        
        # These should NOT be flagged
        assert not any("app_name" in snippet for snippet in flagged_snippets)
        assert not any("version" in snippet for snippet in flagged_snippets)
        assert not any("status" in snippet for snippet in flagged_snippets)
        assert not any("count = 0" in snippet for snippet in flagged_snippets)
        assert not any("index = 1" in snippet for snippet in flagged_snippets)
        assert not any("error_flag = -1" in snippet for snippet in flagged_snippets)
        
        # This SHOULD be flagged in financial context
        assert any("timeout = 10" in snippet for snippet in flagged_snippets), "10 should be flagged as potential financial value"


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
        
        # Should find hardcoded values in function calls - ALL CRITICAL
        hardcoded_findings = [f for f in findings if f.library == "hardcoded"]
        assert len(hardcoded_findings) >= 1, f"Expected at least 1 hardcoded finding, got {len(hardcoded_findings)}"
        
        # ALL should be CRITICAL
        critical_findings = [f for f in hardcoded_findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 1, f"Expected at least 1 CRITICAL hardcoded finding, got {len(critical_findings)}" 