"""
Context collection for analysis.
Handles alias resolution and analysis context management.
"""

import re
from typing import Dict, List, Set, Optional, Union

import libcst as cst


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


class AnalysisContext:
    """Maintains context during analysis including aliases."""
    
    def __init__(self):
        self.aliases: Dict[str, str] = {}
        self.imports: Set[str] = set()
    
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