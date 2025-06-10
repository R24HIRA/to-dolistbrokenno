"""YAML and Excel rule bundle loader and validation."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

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
    """A complete rule bundle loaded from YAML or Excel."""
    
    meta: RuleMeta = Field(..., description="Bundle metadata")
    rules: List[Rule] = Field(..., description="List of rules in this bundle")
    
    @property
    def compiled_alias_regex(self) -> re.Pattern:
        """Compiled regex pattern for alias matching."""
        return re.compile(self.meta.alias_regex)


class RuleLoader:
    """Loads and manages rule bundles from YAML and Excel files."""
    
    def __init__(self):
        self.bundles: List[RuleBundle] = []
        self._rule_lookup: Dict[str, Dict[str, Rule]] = {}
    
    def load_builtin_rules(self) -> None:
        """Load built-in rule bundles from both YAML and Excel files."""
        rules_dir = Path(__file__).parent.parent / "rules"
        
        # Load YAML files
        for yaml_file in rules_dir.glob("*.yml"):
            self.load_bundle(yaml_file)
        
        # Load Excel files if pandas is available
        if PANDAS_AVAILABLE:
            for excel_file in rules_dir.glob("*.xlsx"):
                self.load_bundle(excel_file)
            for excel_file in rules_dir.glob("*.xls"):
                self.load_bundle(excel_file)
    
    def load_bundle(self, file_path: Path) -> RuleBundle:
        """Load a rule bundle from either YAML or Excel file."""
        if file_path.suffix.lower() in ['.xlsx', '.xls']:
            return self.load_excel_bundle(file_path)
        else:
            return self.load_yaml_bundle(file_path)
    
    def load_yaml_bundle(self, yaml_path: Path) -> RuleBundle:
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
            raise ValueError(f"Failed to load YAML rule bundle from {yaml_path}: {e}")
    
    def load_excel_bundle(self, excel_path: Path) -> RuleBundle:
        """Load a rule bundle from an Excel file."""
        if not PANDAS_AVAILABLE:
            raise ValueError("pandas is required to load Excel rule files. Install with: pip install pandas")
        
        try:
            # Try to read both sheets or a single sheet
            excel_data = pd.ExcelFile(excel_path)
            
            if len(excel_data.sheet_names) >= 2 and 'meta' in excel_data.sheet_names and 'rules' in excel_data.sheet_names:
                # Multi-sheet format
                return self._load_excel_multisheet(excel_path, excel_data)
            else:
                # Single sheet format
                return self._load_excel_singlesheet(excel_path, excel_data)
                
        except Exception as e:
            raise ValueError(f"Failed to load Excel rule bundle from {excel_path}: {e}")
    
    def _load_excel_multisheet(self, excel_path: Path, excel_data) -> RuleBundle:
        """Load Excel file with separate 'meta' and 'rules' sheets."""
        # Load metadata sheet
        meta_df = pd.read_excel(excel_path, sheet_name='meta')
        if len(meta_df) == 0:
            raise ValueError("Meta sheet is empty")
        
        # Extract meta information (expecting key-value pairs)
        meta_dict = {}
        for _, row in meta_df.iterrows():
            if len(row) >= 2 and pd.notna(row.iloc[0]) and pd.notna(row.iloc[1]):
                meta_dict[str(row.iloc[0]).strip()] = str(row.iloc[1]).strip()
        
        # Load rules sheet
        rules_df = pd.read_excel(excel_path, sheet_name='rules')
        return self._create_bundle_from_dataframes(meta_dict, rules_df, excel_path)
    
    def _load_excel_singlesheet(self, excel_path: Path, excel_data) -> RuleBundle:
        """Load Excel file with single sheet containing both meta and rules."""
        # Read the first (or only) sheet
        sheet_name = excel_data.sheet_names[0]
        df = pd.read_excel(excel_path, sheet_name=sheet_name)
        
        # Look for meta information in the first few rows or specific columns
        meta_dict = {}
        rules_df = df
        
        # Try to find library and alias_regex in the data
        # Method 1: Look for specific columns
        if 'library' in df.columns:
            library_values = df['library'].dropna().unique()
            if len(library_values) > 0:
                meta_dict['library'] = str(library_values[0])
        
        if 'alias_regex' in df.columns:
            alias_values = df['alias_regex'].dropna().unique()
            if len(alias_values) > 0:
                meta_dict['alias_regex'] = str(alias_values[0])
        
        # Fallback: use filename as library name
        if 'library' not in meta_dict:
            meta_dict['library'] = excel_path.stem.lower()
            meta_dict['alias_regex'] = self._get_default_alias_regex(meta_dict['library'])
        
        return self._create_bundle_from_dataframes(meta_dict, rules_df, excel_path)
    
    def _create_bundle_from_dataframes(self, meta_dict: Dict, rules_df, excel_path: Path) -> RuleBundle:
        """Create a RuleBundle from meta dictionary and rules DataFrame."""
        # Validate required meta fields
        if 'library' not in meta_dict:
            raise ValueError(f"Excel file {excel_path} missing required 'library' field")
        if 'alias_regex' not in meta_dict:
            meta_dict['alias_regex'] = self._get_default_alias_regex(meta_dict['library'])
        
        # Create meta object
        meta = RuleMeta(
            library=meta_dict['library'],
            alias_regex=meta_dict['alias_regex']
        )
        
        # Parse rules from DataFrame
        rules = []
        required_columns = ['func', 'mutation', 'default_severity']
        
        # Check for required columns
        missing_columns = [col for col in required_columns if col not in rules_df.columns]
        if missing_columns:
            raise ValueError(f"Excel file {excel_path} missing required columns: {missing_columns}")
        
        for _, row in rules_df.iterrows():
            # Skip empty rows
            if pd.isna(row['func']) or row['func'] == '':
                continue
                
            try:
                # Basic rule fields
                rule_data = {
                    'func': str(row['func']).strip(),
                    'mutation': str(row['mutation']).strip(),
                    'default_severity': str(row['default_severity']).strip().upper()
                }
                
                # Optional fields
                if 'notes' in row and pd.notna(row['notes']):
                    rule_data['notes'] = str(row['notes']).strip()
                
                # Handle extra checks - look for inplace_critical column
                if 'inplace_critical' in row and pd.notna(row['inplace_critical']):
                    inplace_val = str(row['inplace_critical']).lower()
                    if inplace_val in ['true', 'yes', '1']:
                        rule_data['extra_checks'] = ExtraCheck(
                            arg_present={'name': 'inplace', 'value': True},
                            set_severity=Severity.CRITICAL
                        )
                
                # Create and validate rule
                rule = Rule(**rule_data)
                rules.append(rule)
                
            except Exception as e:
                raise ValueError(f"Error parsing rule in row {row.name + 2}: {e}")
        
        if not rules:
            raise ValueError(f"No valid rules found in Excel file {excel_path}")
        
        # Create bundle
        bundle = RuleBundle(meta=meta, rules=rules)
        self.bundles.append(bundle)
        
        # Build lookup index
        if bundle.meta.library not in self._rule_lookup:
            self._rule_lookup[bundle.meta.library] = {}
        
        for rule in bundle.rules:
            self._rule_lookup[bundle.meta.library][rule.func] = rule
        
        return bundle
    
    def _get_default_alias_regex(self, library: str) -> str:
        """Get default alias regex for common libraries."""
        defaults = {
            'pandas': '^(pd|pandas)$',
            'numpy': '^(np|numpy)$',
            'sql': '^(sql|SQL)$',
            'database': '^(db|database)$',
            'hardcoded': '^(hardcoded)$'
        }
        return defaults.get(library.lower(), f'^({library})$')
    
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