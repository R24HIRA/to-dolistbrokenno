"""YAML rule bundle loader and validation."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from .finding import Severity


class ExtraCheck(BaseModel):
    """Extra validation check for a rule."""
    
    arg_present: Optional[Dict[str, Any]] = Field(default=None, description="Check for argument presence")
    set_severity: Optional[Severity] = Field(default=None, description="Override severity if check passes")


class Rule(BaseModel):
    """A single mutation detection rule."""
    
    func: str = Field(..., description="Function name to match")
    mutation: str = Field(..., description="Type of mutation this function performs")
    default_severity: Severity = Field(..., description="Default severity level")
    notes: Optional[str] = Field(default=None, description="Additional notes about this rule")
    extra_checks: Optional[ExtraCheck] = Field(default=None, description="Additional validation checks")
    
    @property
    def rule_id(self) -> str:
        """Generate a rule ID for this rule."""
        return f"{self.func}.{self.mutation.replace(' ', '_').replace('-', '_')}"


class RuleMeta(BaseModel):
    """Metadata for a rule bundle."""
    
    library: str = Field(..., description="Library name (e.g., 'pandas', 'numpy')")
    alias_regex: str = Field(..., description="Regex pattern for common aliases")
    
    @field_validator('alias_regex')
    @classmethod
    def validate_regex(cls, v):
        """Validate that alias_regex is a valid regex pattern."""
        try:
            re.compile(v)
            return v
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")


class RuleBundle(BaseModel):
    """A complete rule bundle loaded from YAML."""
    
    meta: RuleMeta = Field(..., description="Bundle metadata")
    rules: List[Rule] = Field(..., description="List of rules in this bundle")
    
    @property
    def compiled_alias_regex(self) -> re.Pattern:
        """Compiled regex pattern for alias matching."""
        return re.compile(self.meta.alias_regex)


class RuleLoader:
    """Loads and manages rule bundles from YAML files."""
    
    def __init__(self):
        self.bundles: List[RuleBundle] = []
        self._rule_lookup: Dict[str, Dict[str, Rule]] = {}
    
    def load_builtin_rules(self) -> None:
        """Load built-in rule bundles."""
        rules_dir = Path(__file__).parent.parent / "rules"
        for yaml_file in rules_dir.glob("*.yml"):
            self.load_bundle(yaml_file)
    
    def load_bundle(self, yaml_path: Path) -> RuleBundle:
        """Load a single rule bundle from a YAML file."""
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            bundle = RuleBundle(**data)
            self.bundles.append(bundle)
            
            # Build lookup index
            if bundle.meta.library not in self._rule_lookup:
                self._rule_lookup[bundle.meta.library] = {}
            
            for rule in bundle.rules:
                self._rule_lookup[bundle.meta.library][rule.func] = rule
            
            return bundle
            
        except Exception as e:
            raise ValueError(f"Failed to load rule bundle from {yaml_path}: {e}")
    
    def get_rule(self, library: str, function: str) -> Optional[Rule]:
        """Get a rule for a specific library and function."""
        return self._rule_lookup.get(library, {}).get(function)
    
    def resolve_alias(self, alias: str) -> Optional[str]:
        """Resolve an alias to a canonical library name."""
        for bundle in self.bundles:
            if bundle.compiled_alias_regex.match(alias):
                return bundle.meta.library
        return None
    
    def get_all_libraries(self) -> List[str]:
        """Get all known library names."""
        return list(self._rule_lookup.keys())
    
    def get_functions_for_library(self, library: str) -> List[str]:
        """Get all function names for a specific library."""
        return list(self._rule_lookup.get(library, {}).keys())
    
    def get_bundle_for_library(self, library: str) -> Optional[RuleBundle]:
        """Get the rule bundle for a specific library."""
        for bundle in self.bundles:
            if bundle.meta.library == library:
                return bundle
        return None 