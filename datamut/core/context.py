"""
Context collection for analysis.
Handles alias resolution and analysis context management.
"""

import re
from typing import Dict, List, Set, Optional, Union

import libcst as cst
import sqlparse
from sqlparse import keywords, tokens


class AliasCollector(cst.CSTVisitor):
    """Collects import aliases for libraries we're interested in."""
    
    def __init__(self):
        self.aliases: Dict[str, str] = {}  # alias -> library name
        self.direct_imports: Set[str] = set()  # direct imports like 'import pandas'
        
    def visit_Import(self, node: cst.Import) -> None:
        """Handle 'import pandas as pd' style imports."""
        for name in node.names:
            if isinstance(name, cst.ImportAlias):
                module_name = self._get_full_name(name.name)
                if name.asname:
                    alias = self._get_full_name(name.asname.name)
                    self.aliases[alias] = module_name
                else:
                    self.direct_imports.add(module_name)
    
    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        """Handle 'from pandas import DataFrame' style imports."""
        if node.module:
            module_name = self._get_full_name(node.module)
            
            # Handle star imports
            if isinstance(node.names, cst.ImportStar):
                self.direct_imports.add(module_name)
                return
            
            # Handle specific imports
            if isinstance(node.names, (list, tuple)):
                for name in node.names:
                    if isinstance(name, cst.ImportAlias):
                        imported_name = self._get_full_name(name.name)
                        if name.asname:
                            alias = self._get_full_name(name.asname.name)
                            self.aliases[alias] = f"{module_name}.{imported_name}"
                        else:
                            self.aliases[imported_name] = f"{module_name}.{imported_name}"
    
    def _get_full_name(self, node: Union[cst.Name, cst.Attribute, cst.Dot]) -> str:
        """Extract the full dotted name from a CST node."""
        if isinstance(node, cst.Name):
            return node.value
        elif isinstance(node, cst.Attribute):
            return f"{self._get_full_name(node.value)}.{node.attr.value}"
        elif isinstance(node, cst.Dot):
            return "."
        else:
            return str(node)
    
    def resolve_library(self, name: str) -> Optional[str]:
        """Resolve a name to its library."""
        # Check direct aliases first
        if name in self.aliases:
            return self.aliases[name].split('.')[0]
        
        # Check if it's a direct import
        if name in self.direct_imports:
            return name
        
        # Check if it's a known library name
        known_libraries = {'pandas', 'numpy', 'np', 'pd'}
        if name in known_libraries:
            return 'pandas' if name in ['pd', 'pandas'] else 'numpy'
        
        return None


class SQLContext:
    """Context for SQL analysis within Python strings."""
    
    def __init__(self, sql_content: str, line_number: int, column_offset: int):
        self.sql_content = sql_content.strip()
        self.line_number = line_number
        self.column_offset = column_offset
    
    @staticmethod
    def analyze_sql_string(sql_content: str) -> List[Dict]:
        """Analyze SQL string and return list of mutations found."""
        mutations = []
        
        # Define mutation keywords and their types
        mutation_keywords = {
            'INSERT': 'data insertion',
            'UPDATE': 'data update', 
            'DELETE': 'data deletion',
            'DROP': 'schema/data drop',
            'TRUNCATE': 'data truncation',
            'ALTER': 'schema modification',
            'CREATE': 'schema creation',
            'MERGE': 'data merge',
            'UPSERT': 'data upsert',
            'REPLACE': 'data replacement'
        }
        
        # Convert to uppercase for keyword matching
        upper_content = sql_content.upper()
        
        # Find all mutation keywords in the SQL
        for keyword, mutation_type in mutation_keywords.items():
            if keyword in upper_content:
                mutations.append({
                    'keyword': keyword,
                    'mutation_type': mutation_type,
                    'sql_content': sql_content
                })
        
        return mutations
    
    def looks_like_sql(self) -> bool:
        """Heuristic to determine if a string looks like SQL."""
        sql_keywords = {
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 
            'ALTER', 'TRUNCATE', 'MERGE', 'UPSERT', 'REPLACE'
        }
        
        # Convert to uppercase and check for SQL keywords
        upper_content = self.sql_content.upper()
        
        # Must contain at least one SQL keyword
        has_keyword = any(keyword in upper_content for keyword in sql_keywords)
        
        # Additional heuristics
        has_from = 'FROM' in upper_content
        has_where = 'WHERE' in upper_content
        has_semicolon = ';' in self.sql_content
        
        # Simple scoring system
        score = 0
        if has_keyword:
            score += 2
        if has_from or has_where:
            score += 1
        if has_semicolon:
            score += 1
        if len(self.sql_content.split()) >= 3:  # At least 3 words
            score += 1
            
        return score >= 2
    
    def extract_keywords(self) -> Set[str]:
        """Extract SQL keywords from the content."""
        words = re.findall(r'\b\w+\b', self.sql_content.upper())
        found_keywords = set()
        
        for word in words:
            if word in {'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TRUNCATE', 'ALTER',
                        'CREATE', 'MERGE', 'UPSERT', 'REPLACE', 'LOAD', 'IMPORT',
                        'EXPORT', 'COPY', 'BACKUP', 'RESTORE', 'REINDEX', 'VACUUM',
                        'ANALYZE', 'CLUSTER'}:
                found_keywords.add(word)
        
        return found_keywords


class AnalysisContext:
    """Maintains context during analysis including aliases and SQL findings."""
    
    def __init__(self):
        self.aliases: Dict[str, str] = {}
        self.imports: Set[str] = set()
        self.sql_mutations: List[Dict] = []
    
    def update_from_collector(self, collector: AliasCollector) -> None:
        """Update context from an alias collector."""
        self.aliases.update(collector.aliases)
        self.imports.update(collector.direct_imports)
    
    def resolve_name(self, name: str) -> str:
        """Resolve a name through aliases to its canonical form."""
        return self.aliases.get(name, name)
    
    def is_known_import(self, name: str) -> bool:
        """Check if a name is a known import."""
        return name in self.imports or name in self.aliases.values()
    
    def add_sql_mutation(self, mutation: Dict) -> None:
        """Add a SQL mutation finding."""
        self.sql_mutations.append(mutation) 