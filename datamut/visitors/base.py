"""Base visitor class with common functionality."""

from pathlib import Path
from typing import List, Optional, Union

import libcst as cst
from libcst.metadata import PositionProvider

from ..core.finding import Finding
from ..core.loader import RuleLoader
from ..core.context import AnalysisContext


class BaseVisitor(cst.CSTVisitor):
    """Base visitor class with common functionality for all sub-visitors."""
    
    METADATA_DEPENDENCIES = (PositionProvider,)
    
    def __init__(self, file_path: Path, rule_loader: RuleLoader, context: AnalysisContext):
        self.file_path = file_path
        self.rule_loader = rule_loader
        self.context = context
        self.findings: List[Finding] = []
        self.source_lines: List[str] = []
    
    def set_source_code(self, source_code: str) -> None:
        """Set the source code for extracting snippets."""
        self.source_lines = source_code.splitlines()
    
    def _get_position(self, node: cst.CSTNode) -> Optional[tuple[int, int]]:
        """Get line and column position of a node."""
        try:
            position = self.get_metadata(PositionProvider, node)
            if position:
                return position.start.line, position.start.column
        except Exception:
            pass
        return None
    
    def _extract_code_snippet(self, node: cst.CSTNode, line_number: int) -> str:
        """Extract code snippet around the node, capturing multi-line context when needed."""
        if not self.source_lines or line_number < 1 or line_number > len(self.source_lines):
            return ""
        
        # Try to get position metadata for more accurate extraction
        start_line = line_number
        end_line = line_number
        
        try:
            position = self.get_metadata(PositionProvider, node)
            if position:
                start_line = position.start.line
                end_line = position.end.line
        except Exception:
            pass
        
        # For multi-line expressions, capture the full range
        if end_line > start_line:
            lines = []
            for i in range(start_line, min(end_line + 1, len(self.source_lines) + 1)):
                if i > 0 and i <= len(self.source_lines):
                    lines.append(self.source_lines[i - 1].rstrip())
            return '\n'.join(lines).strip()
        
        # For single line, try to capture more context for incomplete lines
        current_line = self.source_lines[line_number - 1].strip()
        
        # If the line appears to be incomplete (ends with comma, open paren, etc.)
        # try to find the complete statement
        if (current_line.endswith((',', '(', '[', '{')) or 
            current_line.count('(') != current_line.count(')') or
            current_line.count('[') != current_line.count(']') or
            current_line.count('{') != current_line.count('}')):
            
            # Look backwards to find the start of the statement
            statement_start = line_number
            for i in range(line_number - 1, 0, -1):
                prev_line = self.source_lines[i - 1].strip()
                if (not prev_line.endswith((',', '(', '[', '{', '\\')) and
                    prev_line.count('(') == prev_line.count(')') and
                    prev_line.count('[') == prev_line.count(']')):
                    break
                statement_start = i
            
            # Look forwards to find the end of the statement
            statement_end = line_number
            for i in range(line_number, len(self.source_lines)):
                next_line = self.source_lines[i].strip()
                if (not next_line.endswith((',', '(', '[', '{', '\\')) and
                    current_line.count('(') == current_line.count(')') and
                    current_line.count('[') == current_line.count(']')):
                    statement_end = i + 1
                    break
                current_line += ' ' + next_line
            
            # Extract the complete statement
            if statement_end > statement_start:
                lines = []
                for i in range(statement_start, min(statement_end + 1, len(self.source_lines) + 1)):
                    if i > 0 and i <= len(self.source_lines):
                        lines.append(self.source_lines[i - 1].rstrip())
                return '\n'.join(lines).strip()
        
        return current_line
    
    def _extract_string_value(self, node: Union[cst.SimpleString, cst.ConcatenatedString]) -> Optional[str]:
        """Extract string value from a string node."""
        if isinstance(node, cst.SimpleString):
            # Remove quotes and handle escape sequences
            value = node.value
            if value.startswith(('"""', "'''")):
                return value[3:-3]
            elif value.startswith(('"', "'")):
                return value[1:-1]
            return value
        elif isinstance(node, cst.ConcatenatedString):
            # Handle concatenated strings
            parts = []
            for part in node.left, node.right:
                if isinstance(part, (cst.SimpleString, cst.ConcatenatedString)):
                    part_value = self._extract_string_value(part)
                    if part_value:
                        parts.append(part_value)
            return ''.join(parts)
        return None 