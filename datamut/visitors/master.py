"""Master visitor that coordinates all sub-visitors."""

from pathlib import Path
from typing import List

import libcst as cst

from .mutation import MutationVisitor
from .sql import SQLVisitor
from .hardcoded import HardcodedVisitor
from ..core.finding import Finding
from ..core.loader import RuleLoader
from ..core.context import AnalysisContext


class MasterVisitor:
    """Master visitor that coordinates all sub-visitors for data mutation analysis."""
    
    def __init__(self, file_path: Path, rule_loader: RuleLoader, context: AnalysisContext):
        self.file_path = file_path
        self.rule_loader = rule_loader
        self.context = context
        self.findings: List[Finding] = []
        
        # Initialize all sub-visitors
        self.mutation_visitor = MutationVisitor(file_path, rule_loader, context)
        self.sql_visitor = SQLVisitor(file_path, rule_loader, context)
        self.hardcoded_visitor = HardcodedVisitor(file_path, rule_loader, context)
    
    def set_source_code(self, source_code: str) -> None:
        """Set the source code for all sub-visitors."""
        self.mutation_visitor.set_source_code(source_code)
        self.sql_visitor.set_source_code(source_code)
        self.hardcoded_visitor.set_source_code(source_code)
    
    def analyze(self, tree: cst.Module, source_code: str) -> List[Finding]:
        """Run all visitors on the AST and collect findings."""
        self.set_source_code(source_code)
        
        # Create metadata wrapper for position information
        wrapper = cst.metadata.MetadataWrapper(tree)
        
        # Run mutation visitor (pandas, numpy, method chaining)
        try:
            wrapper.visit(self.mutation_visitor)
            self.findings.extend(self.mutation_visitor.findings)
        except Exception as e:
            print(f"Error in mutation visitor: {e}")
        
        # Run SQL visitor
        try:
            wrapper.visit(self.sql_visitor)
            self.findings.extend(self.sql_visitor.findings)
        except Exception as e:
            print(f"Error in SQL visitor: {e}")
        
        # Run hardcoded visitor
        try:
            wrapper.visit(self.hardcoded_visitor)
            self.findings.extend(self.hardcoded_visitor.findings)
        except Exception as e:
            print(f"Error in hardcoded visitor: {e}")
        
        return self.findings
    
    def get_findings_by_library(self, library: str) -> List[Finding]:
        """Get findings filtered by library."""
        return [f for f in self.findings if f.library == library]
    
    def get_findings_by_severity(self, severity) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_summary(self) -> dict:
        """Get a summary of all findings."""
        summary = {
            'total_findings': len(self.findings),
            'by_library': {},
            'by_severity': {},
            'by_mutation_type': {}
        }
        
        for finding in self.findings:
            # Count by library
            library = finding.library
            summary['by_library'][library] = summary['by_library'].get(library, 0) + 1
            
            # Count by severity
            severity = finding.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by mutation type
            mutation_type = finding.mutation_type
            summary['by_mutation_type'][mutation_type] = summary['by_mutation_type'].get(mutation_type, 0) + 1
        
        return summary 