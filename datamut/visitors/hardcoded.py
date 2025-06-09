"""LibCST visitor for detecting hardcoded variables and values."""

import re
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

import libcst as cst
from libcst.metadata import PositionProvider

from .base import BaseVisitor
from ..core.finding import Finding, Severity
from ..core.loader import RuleLoader


class HardcodedVisitor(BaseVisitor):
    """Visitor for detecting hardcoded variables and values."""
    
    def __init__(self, file_path: Path, rule_loader: RuleLoader, context=None):
        super().__init__(file_path, rule_loader, context)
        
        # Patterns for different types of hardcoded values
        self.patterns = {
            'database_connection': [
                r'(?i)(mysql|postgresql|sqlite|mongodb|redis)://[^\s]+',
                r'(?i)server\s*=\s*["\'][^"\']+["\']',
                r'(?i)database\s*=\s*["\'][^"\']+["\']',
                r'(?i)host\s*=\s*["\'][^"\']+["\']',
            ],
            'credentials': [
                r'(?i)(password|pwd|pass)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(username|user|uid)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(secret|token|key)\s*=\s*["\'][^"\']+["\']',
            ],
            'api_key': [
                r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(access[_-]?token|accesstoken)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(bearer[_-]?token|bearertoken)\s*=\s*["\'][^"\']+["\']',
                r'["\'][A-Za-z0-9]{32,}["\']',  # Long alphanumeric strings (potential keys)
            ],
            'url_endpoint': [
                r'https?://[^\s"\']+',
                r'(?i)(endpoint|url|uri)\s*=\s*["\']https?://[^"\']+["\']',
            ],
            'file_path': [
                r'["\'][C-Z]:\\[^"\']*["\']',  # Windows absolute paths
                r'["\']\/[^"\']*["\']',        # Unix absolute paths
                r'(?i)(path|file|dir|directory)\s*=\s*["\'][^"\']+["\']',
            ],
            'email_address': [
                r'["\'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']',
            ],
            'ip_address': [
                r'["\'](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)["\']',
            ],
            'port_number': [
                r'(?i)(port)\s*=\s*["\']?[0-9]{1,5}["\']?',
            ],
        }
        
        # Common variable names that often contain hardcoded values
        self.suspicious_var_names = {
            'database_connection': {'db_url', 'database_url', 'connection_string', 'db_connection'},
            'credentials': {'password', 'pwd', 'pass', 'username', 'user', 'secret'},
            'api_key': {'api_key', 'apikey', 'access_token', 'token', 'bearer_token'},
            'url_endpoint': {'endpoint', 'url', 'uri', 'base_url', 'api_url'},
            'file_path': {'file_path', 'filepath', 'path', 'directory', 'dir'},
            'email_address': {'email', 'email_address', 'sender', 'recipient'},
            'ip_address': {'ip', 'ip_address', 'host', 'server'},
            'port_number': {'port', 'port_number'},
        }
        
        # Magic number thresholds
        self.magic_number_threshold = 100  # Numbers above this are considered suspicious
        self.common_safe_numbers = {0, 1, 2, 3, 4, 5, 10, 100, 1000}  # Common safe numbers
    
    def visit_Assign(self, node: cst.Assign) -> None:
        """Check variable assignments for hardcoded values."""
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target.target, cst.Name):
                var_name = target.target.value.lower()
                
                # Check string assignments
                if isinstance(node.value, (cst.SimpleString, cst.ConcatenatedString)):
                    string_value = self._extract_string_value(node.value)
                    if string_value:
                        self._check_hardcoded_string(node, var_name, string_value)
                
                # Check numeric assignments
                elif isinstance(node.value, (cst.Integer, cst.Float)):
                    self._check_magic_number(node, var_name, node.value)
    
    def visit_SimpleString(self, node: cst.SimpleString) -> None:
        """Check standalone string literals for hardcoded values."""
        string_value = self._extract_string_value(node)
        if string_value:
            self._check_hardcoded_string(node, None, string_value)
    
    def visit_Integer(self, node: cst.Integer) -> None:
        """Check standalone integers for magic numbers."""
        self._check_magic_number(node, None, node)
    
    def visit_Float(self, node: cst.Float) -> None:
        """Check standalone floats for magic numbers."""
        self._check_magic_number(node, None, node)
    
    def _extract_string_value(self, node) -> Optional[str]:
        """Extract string value from a string node."""
        if isinstance(node, cst.SimpleString):
            value = node.value
            if value.startswith(('"""', "'''")):
                return value[3:-3]
            elif value.startswith(('"', "'")):
                return value[1:-1]
            return value
        elif isinstance(node, cst.ConcatenatedString):
            # Handle concatenated strings
            parts = []
            for part in [node.left, node.right]:
                if isinstance(part, (cst.SimpleString, cst.ConcatenatedString)):
                    part_value = self._extract_string_value(part)
                    if part_value:
                        parts.append(part_value)
            return ''.join(parts)
        return None
    
    def _check_hardcoded_string(self, node: cst.CSTNode, var_name: Optional[str], string_value: str) -> None:
        """Check if a string contains hardcoded values."""
        # Skip very short strings or common values
        if len(string_value) < 3 or string_value.lower() in {'', 'none', 'null', 'true', 'false'}:
            return
        
        # Check against patterns
        for category, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, string_value):
                    self._create_hardcoded_finding(node, category, string_value, var_name)
                    return
        
        # Check variable names for suspicious patterns
        if var_name:
            for category, var_names in self.suspicious_var_names.items():
                if any(suspicious in var_name for suspicious in var_names):
                    # Additional checks to reduce false positives
                    if self._is_likely_hardcoded_value(string_value, category):
                        self._create_hardcoded_finding(node, category, string_value, var_name)
                        return
    
    def _check_magic_number(self, node: cst.CSTNode, var_name: Optional[str], value_node) -> None:
        """Check if a number is a magic number."""
        try:
            if isinstance(value_node, cst.Integer):
                value = int(value_node.value)
            elif isinstance(value_node, cst.Float):
                value = float(value_node.value)
            else:
                return
            
            # Skip common safe numbers
            if value in self.common_safe_numbers:
                return
            
            # Check for suspicious large numbers
            if abs(value) > self.magic_number_threshold:
                self._create_hardcoded_finding(node, 'magic_number', str(value), var_name)
            
            # Check for suspicious decimal numbers
            elif isinstance(value, float) and value not in {0.0, 1.0, 0.5}:
                self._create_hardcoded_finding(node, 'magic_number', str(value), var_name)
                
        except (ValueError, TypeError):
            pass
    
    def _is_likely_hardcoded_value(self, value: str, category: str) -> bool:
        """Additional heuristics to determine if a value is likely hardcoded."""
        if category == 'credentials':
            # Skip obvious placeholders
            placeholders = {'password', 'username', 'secret', 'token', 'key', 'placeholder', 'example'}
            return value.lower() not in placeholders and len(value) > 3
        
        elif category == 'file_path':
            # Check for actual path-like structures
            return ('/' in value or '\\' in value) and not value.startswith(('http', 'ftp'))
        
        elif category == 'url_endpoint':
            # Must be a valid URL structure
            return value.startswith(('http://', 'https://')) and len(value) > 10
        
        elif category == 'email_address':
            # Must contain @ and domain
            return '@' in value and '.' in value.split('@')[-1]
        
        elif category == 'ip_address':
            # Must be valid IP format
            parts = value.split('.')
            return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        
        return True
    
    def _create_hardcoded_finding(self, node: cst.CSTNode, category: str, value: str, var_name: Optional[str]) -> None:
        """Create a finding for a hardcoded value."""
        position = self._get_position(node)
        if not position:
            position = (1, 0)
        
        line_number, column_offset = position
        
        # Get rule for this category
        rule = self.rule_loader.get_rule('hardcoded', category)
        if not rule:
            # Create a default rule if not found
            severity = self._get_default_severity(category)
            mutation_type = f"hardcoded {category.replace('_', ' ')}"
            notes = f"Detected hardcoded {category.replace('_', ' ')}: {value[:50]}..."
            rule_id = f"hardcoded.{category}"
        else:
            severity = rule.default_severity
            mutation_type = rule.mutation
            notes = rule.notes
            rule_id = rule.rule_id
        
        # Create extra context
        extra_context = {
            'detected_value': value[:100] + '...' if len(value) > 100 else value,
            'category': category,
            'variable_name': var_name
        }
        
        # Truncate sensitive values in the snippet
        display_value = self._sanitize_value_for_display(value, category)
        
        finding = Finding(
            file_path=self.file_path,
            line_number=line_number,
            column_offset=column_offset,
            library="hardcoded",
            function_name=category,
            mutation_type=mutation_type,
            severity=severity,
            code_snippet=self._extract_code_snippet(node, line_number),
            notes=notes,
            rule_id=rule_id,
            extra_context=extra_context
        )
        
        self.findings.append(finding)
    
    def _get_default_severity(self, category: str) -> Severity:
        """Get default severity for a category."""
        severity_map = {
            'credentials': Severity.CRITICAL,
            'api_key': Severity.CRITICAL,
            'database_connection': Severity.HIGH,
            'ip_address': Severity.HIGH,
            'url_endpoint': Severity.MEDIUM,
            'file_path': Severity.MEDIUM,
            'email_address': Severity.MEDIUM,
            'port_number': Severity.MEDIUM,
            'config_value': Severity.MEDIUM,
            'magic_number': Severity.LOW,
        }
        return severity_map.get(category, Severity.MEDIUM)
    
    def _sanitize_value_for_display(self, value: str, category: str) -> str:
        """Sanitize sensitive values for display in reports."""
        if category in {'credentials', 'api_key'}:
            if len(value) > 4:
                return value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                return '*' * len(value)
        return value
    
    def _get_position(self, node: cst.CSTNode) -> Optional[tuple[int, int]]:
        """Get line and column position of a node."""
        try:
            position = self.get_metadata(PositionProvider, node)
            if position:
                return position.start.line, position.start.column
        except Exception:
            pass
        return None
