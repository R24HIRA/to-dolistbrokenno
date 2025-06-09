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
        
        # Track processed nodes to avoid double detection
        self._processed_nodes: Set[int] = set()
        
        # Patterns for different types of hardcoded values
        self.patterns = {
            'database_connection': [
                r'(?i)(mysql|postgresql|sqlite|mongodb|redis|oracle|mssql)://[^\s]+',
                r'(?i)server\s*=\s*["\'][^"\']+["\']',
                r'(?i)database\s*=\s*["\'][^"\']+["\']',
                r'(?i)host\s*=\s*["\'][^"\']+["\']',
                r'(?i)(dsn|data_source)\s*=\s*["\'][^"\']+["\']',  # Data Source Names
                r'(?i)connection_string\s*=\s*["\'][^"\']+["\']',
            ],
            'credentials': [
                r'(?i)(password|pwd|pass|passwd)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(username|user|uid|login)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(secret|token|key|auth)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(client_secret|api_secret)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(private_key|public_key)\s*=\s*["\'][^"\']+["\']',
            ],
            'api_key': [
                r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(access[_-]?token|accesstoken)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(bearer[_-]?token|bearertoken)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(oauth[_-]?token|refresh[_-]?token)\s*=\s*["\'][^"\']+["\']',
                r'["\'][A-Za-z0-9]{32,}["\']',  # Long alphanumeric strings (potential keys)
                r'["\']sk-[A-Za-z0-9]{32,}["\']',  # OpenAI-style API keys
                r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']',  # Base64-encoded keys
            ],
            'url_endpoint': [
                r'https?://[^\s"\']+',
                r'(?i)(endpoint|url|uri|base_url)\s*=\s*["\']https?://[^"\']+["\']',
                r'(?i)(webhook|callback)_url\s*=\s*["\'][^"\']+["\']',
                r'ftp://[^\s"\']+',  # FTP URLs
                r'sftp://[^\s"\']+',  # SFTP URLs
            ],
            'file_path': [
                r'["\'][C-Z]:\\[^"\']*["\']',  # Windows absolute paths
                r'["\']\/[^"\']*["\']',        # Unix absolute paths
                r'(?i)(path|file|dir|directory|folder)\s*=\s*["\'][^"\']+["\']',
                r'["\'][^"\']*\.(log|config|conf|ini|json|xml|yaml|yml|cert|key|pem)["\']',  # Config files
                r'["\'][^"\']*(/var|/tmp|/home|/usr|/opt)[^"\']*["\']',  # Common Unix paths
            ],
            'email_address': [
                r'["\'][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}["\']',
            ],
            'ip_address': [
                r'["\'](?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)["\']',
                r'["\'][0-9a-fA-F:]+::[0-9a-fA-F:]*["\']',  # IPv6 addresses
            ],
            'port_number': [
                r'(?i)(port)\s*=\s*["\']?[0-9]{1,5}["\']?',
            ],
            'financial_data': [  # New category for financial-specific patterns
                r'(?i)(account[_-]?number|acct[_-]?num)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(routing[_-]?number|aba[_-]?number)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(swift[_-]?code|bic[_-]?code)\s*=\s*["\'][^"\']+["\']',
                r'(?i)(iban|sort[_-]?code)\s*=\s*["\'][^"\']+["\']',
                r'["\'][0-9]{10,20}["\']',  # Long numeric strings (account numbers)
            ],
            'crypto_data': [  # New category for cryptocurrency
                r'(?i)(private[_-]?key|mnemonic|seed[_-]?phrase)\s*=\s*["\'][^"\']+["\']',
                r'["\'][13][a-km-zA-HJ-NP-Z1-9]{25,34}["\']',  # Bitcoin addresses
                r'["\']0x[a-fA-F0-9]{40}["\']',  # Ethereum addresses
            ],
        }
        
        # Common variable names that often contain hardcoded values
        self.suspicious_var_names = {
            'database_connection': {'db_url', 'database_url', 'connection_string', 'db_connection', 'dsn', 'conn_str'},
            'credentials': {'password', 'pwd', 'pass', 'username', 'user', 'secret', 'auth', 'login', 'passwd'},
            'api_key': {'api_key', 'apikey', 'access_token', 'token', 'bearer_token', 'oauth_token', 'client_secret'},
            'url_endpoint': {'endpoint', 'url', 'uri', 'base_url', 'api_url', 'webhook_url', 'callback_url'},
            'file_path': {'file_path', 'filepath', 'path', 'directory', 'dir', 'config_path', 'log_path', 'cert_path'},
            'email_address': {'email', 'email_address', 'sender', 'recipient', 'from_email', 'to_email'},
            'ip_address': {'ip', 'ip_address', 'host', 'server', 'hostname', 'server_ip'},
            'port_number': {'port', 'port_number', 'server_port', 'listen_port'},
            'financial_data': {'account_number', 'account_num', 'routing_number', 'swift_code', 'iban', 'sort_code'},
            'crypto_data': {'private_key', 'wallet_address', 'mnemonic', 'seed_phrase', 'btc_address', 'eth_address'},
        }
        
        # For financial institutions - VERY aggressive magic number detection
        # Only allow the most basic numbers to avoid flagging financial values
        self.common_safe_numbers = {0, 1, -1}  # Only absolutely essential numbers
        
        # Financial context: catch any meaningful numeric values
        # This includes percentages, dollar amounts, counts, etc.
    
    def visit_Assign(self, node: cst.Assign) -> None:
        """Check variable assignments for hardcoded values."""
        if len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target.target, cst.Name):
                var_name = target.target.value.lower()
                
                # Check string assignments (simple and concatenated)
                if isinstance(node.value, (cst.SimpleString, cst.ConcatenatedString)):
                    string_value = self._extract_string_value(node.value)
                    if string_value:
                        self._check_hardcoded_string(node, var_name, string_value)
                
                # Check binary operations for string concatenation (e.g., "a" + "b" + "c")
                elif isinstance(node.value, cst.BinaryOperation):
                    string_value = self._extract_binary_string_concatenation(node.value)
                    if string_value:
                        self._check_hardcoded_string(node, var_name, string_value)
                
                # Check numeric assignments - track node to avoid double detection
                elif isinstance(node.value, (cst.Integer, cst.Float)):
                    node_id = id(node.value)
                    if node_id not in self._processed_nodes:
                        self._processed_nodes.add(node_id)
                        self._check_magic_number(node, var_name, node.value)
    
    def visit_SimpleString(self, node: cst.SimpleString) -> None:
        """Check standalone string literals for hardcoded values."""
        # Only process if not already processed in an assignment
        node_id = id(node)
        if node_id not in self._processed_nodes:
            string_value = self._extract_string_value(node)
            if string_value:
                self._check_hardcoded_string(node, None, string_value)
    
    def visit_Integer(self, node: cst.Integer) -> None:
        """Check standalone integers for magic numbers."""
        # Only process if not already processed in an assignment
        node_id = id(node)
        if node_id not in self._processed_nodes:
            self._processed_nodes.add(node_id)
            self._check_magic_number(node, None, node)
    
    def visit_Float(self, node: cst.Float) -> None:
        """Check standalone floats for magic numbers."""
        # Only process if not already processed in an assignment
        node_id = id(node)
        if node_id not in self._processed_nodes:
            self._processed_nodes.add(node_id)
            self._check_magic_number(node, None, node)
    
    def visit_FormattedString(self, node: cst.FormattedString) -> None:
        """Check formatted string literals (f-strings) for hardcoded values."""
        # Only process if not already processed
        node_id = id(node)
        if node_id not in self._processed_nodes:
            self._processed_nodes.add(node_id)
            
            # Extract the string parts from f-string
            string_parts = []
            for part in node.parts:
                if isinstance(part, cst.FormattedStringText):
                    string_parts.append(part.value)
                elif isinstance(part, cst.FormattedStringExpression):
                    # For expressions, we can still check if they contain hardcoded patterns
                    if hasattr(part.expression, 'value'):
                        string_parts.append(str(part.expression.value))
            
            if string_parts:
                combined_string = ''.join(string_parts)
                if combined_string:
                    self._check_hardcoded_string(node, None, combined_string)
    
    def visit_ConcatenatedString(self, node: cst.ConcatenatedString) -> None:
        """Check concatenated string literals for hardcoded values."""
        # Only process if not already processed
        node_id = id(node)
        if node_id not in self._processed_nodes:
            self._processed_nodes.add(node_id)
            string_value = self._extract_string_value(node)
            if string_value:
                self._check_hardcoded_string(node, None, string_value)
    
    def _extract_string_value(self, node) -> Optional[str]:
        """Extract string value from a string node with recursive concatenation support."""
        if isinstance(node, cst.SimpleString):
            value = node.value
            if value.startswith(('"""', "'''")):
                return value[3:-3]
            elif value.startswith(('"', "'")):
                return value[1:-1]
            return value
        elif isinstance(node, cst.ConcatenatedString):
            # Recursively handle all concatenated string parts
            return self._extract_concatenated_string_recursive(node)
        return None
    
    def _extract_concatenated_string_recursive(self, node: cst.ConcatenatedString) -> str:
        """Recursively extract all parts of a concatenated string."""
        def extract_all_parts(node):
            """Extract all string parts from any concatenation structure."""
            if isinstance(node, cst.SimpleString):
                value = node.value
                if value.startswith(('"""', "'''")):
                    return [value[3:-3]]
                elif value.startswith(('"', "'")):
                    return [value[1:-1]]
                return [value]
            elif isinstance(node, cst.ConcatenatedString):
                # Recursively get parts from both sides
                left_parts = extract_all_parts(node.left)
                right_parts = extract_all_parts(node.right)
                return left_parts + right_parts
            else:
                return []
        
        # Get all parts and join them
        all_parts = extract_all_parts(node)
        return ''.join(all_parts)
    
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
        """Check if a number is a magic number - AGGRESSIVE for financial context."""
        try:
            if isinstance(value_node, cst.Integer):
                value = int(value_node.value)
            elif isinstance(value_node, cst.Float):
                value = float(value_node.value)
            else:
                return
            
            # For financial institutions: flag almost all numeric values
            # Only skip the most basic numbers (0, 1, -1)
            if value in self.common_safe_numbers:
                return
            
            # Flag ANY other numeric value as potentially hardcoded financial data
            # This includes: dollar amounts, percentages, counts, IDs, etc.
            severity = self._get_financial_severity(value, var_name)
            self._create_hardcoded_finding(node, 'magic_number', str(value), var_name, severity)
                
        except (ValueError, TypeError):
            pass
    
    def _get_financial_severity(self, value, var_name: Optional[str]) -> Severity:
        """Determine severity based on financial context - ALL CRITICAL."""
        # In financial context, ALL numeric hardcoded values are CRITICAL risks:
        # - Could be dollar amounts, interest rates, limits
        # - Could be account numbers, transaction IDs  
        # - Could be regulatory thresholds, risk parameters
        # - Lack of configurability is a compliance risk
        return Severity.CRITICAL
    
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
    
    def _create_hardcoded_finding(self, node: cst.CSTNode, category: str, value: str, var_name: Optional[str], severity: Optional[Severity] = None) -> None:
        """Create a finding for a hardcoded value."""
        position = self._get_position(node)
        if not position:
            position = (1, 0)
        
        line_number, column_offset = position
        
        # Get rule for this category
        rule = self.rule_loader.get_rule('hardcoded', category)
        if not rule:
            # Create a default rule if not found
            if severity is None:
                severity = self._get_default_severity(category)
            mutation_type = f"hardcoded {category.replace('_', ' ')}"
            notes = f"Detected hardcoded {category.replace('_', ' ')}: {value[:50]}..."
            rule_id = f"hardcoded.{category}"
        else:
            if severity is None:
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
    
    def _get_default_severity(self, category: str) -> Severity:
        """Get default severity for a category - ALL CRITICAL for financial institutions."""
        # In financial institutions, ANY hardcoded value is a critical risk:
        # - Security vulnerability (credentials, tokens, IPs)
        # - Compliance violation (hardcoded amounts, rates, limits)
        # - Operational risk (paths, URLs, configurations)
        # - Audit trail issues (magic numbers, undocumented values)
        return Severity.CRITICAL

    def _extract_binary_string_concatenation(self, node: cst.BinaryOperation) -> Optional[str]:
        """Extract concatenated string from binary operations like 'a' + 'b' + 'c'."""
        # Only handle string concatenation (+ operator)
        if not isinstance(node.operator, cst.Add):
            return None
        
        def extract_string_from_expr(expr) -> Optional[str]:
            """Extract string value from any expression if it's a string."""
            if isinstance(expr, cst.SimpleString):
                value = expr.value
                if value.startswith(('"""', "'''")):
                    return value[3:-3]
                elif value.startswith(('"', "'")):
                    return value[1:-1]
                return value
            elif isinstance(expr, cst.ConcatenatedString):
                return self._extract_string_value(expr)
            elif isinstance(expr, cst.BinaryOperation) and isinstance(expr.operator, cst.Add):
                # Recursively handle nested binary operations
                return self._extract_binary_string_concatenation(expr)
            return None
        
        # Extract left and right parts
        left_value = extract_string_from_expr(node.left)
        right_value = extract_string_from_expr(node.right)
        
        # Only return if both sides are strings
        if left_value is not None and right_value is not None:
            return left_value + right_value
        
        return None
