"""Pydantic models for findings and severity levels."""

from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, ConfigDict


class Severity(str, Enum):
    """Severity levels for mutation findings."""
    
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
    @property
    def color_class(self) -> str:
        """Bootstrap color class for this severity."""
        mapping = {
            self.LOW: "secondary",
            self.MEDIUM: "warning", 
            self.HIGH: "danger",
            self.CRITICAL: "dark"
        }
        return mapping[self]
    
    @property
    def exit_code_weight(self) -> int:
        """Numeric weight for determining exit codes."""
        mapping = {
            self.LOW: 0,
            self.MEDIUM: 1,
            self.HIGH: 2,
            self.CRITICAL: 3
        }
        return mapping[self]


class Finding(BaseModel):
    """A single data mutation finding from static analysis."""
    
    model_config = ConfigDict(
        json_encoders={Path: str}
    )
    
    file_path: Path = Field(..., description="Path to the file containing the finding")
    line_number: int = Field(..., description="Line number where the finding occurs", ge=1)
    column_offset: int = Field(default=0, description="Column offset within the line", ge=0)
    library: str = Field(..., description="Library or module name (e.g., 'pandas', 'numpy')")
    function_name: str = Field(..., description="Function or method name that causes mutation")
    mutation_type: str = Field(..., description="Type of mutation (e.g., 'row-set merge', 'row/col drop')")
    severity: Severity = Field(..., description="Severity level of this finding")
    code_snippet: str = Field(..., description="Code snippet showing the mutation")
    notes: Optional[str] = Field(default=None, description="Additional notes about this finding")
    rule_id: Optional[str] = Field(default=None, description="ID of the rule that triggered this finding")
    extra_context: Dict[str, Any] = Field(default_factory=dict, description="Additional context data")
    
    @property
    def display_path(self) -> str:
        """Human-readable file path for display."""
        return str(self.file_path)
    
    @property
    def unique_id(self) -> str:
        """Unique identifier for this finding."""
        return f"{self.file_path}:{self.line_number}:{self.column_offset}:{self.function_name}"
    
    def to_sarif_result(self) -> Dict[str, Any]:
        """Convert finding to SARIF result format."""
        return {
            "ruleId": self.rule_id or f"{self.library}.{self.function_name}",
            "message": {
                "text": f"{self.mutation_type}: {self.function_name}",
                "markdown": f"**{self.mutation_type}**: `{self.function_name}`\n\n{self.notes or ''}"
            },
            "level": self._sarif_level(),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(self.file_path)
                    },
                    "region": {
                        "startLine": self.line_number,
                        "startColumn": self.column_offset + 1,  # SARIF uses 1-based columns
                        "snippet": {
                            "text": self.code_snippet
                        }
                    }
                }
            }],
            "properties": {
                "library": self.library,
                "mutationType": self.mutation_type,
                "severity": self.severity.value,
                "extraContext": self.extra_context
            }
        }
    
    def _sarif_level(self) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error", 
            Severity.CRITICAL: "error"
        }
        return mapping[self.severity] 