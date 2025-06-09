"""Master visitor that coordinates all sub-visitors."""

import logging
from pathlib import Path
from typing import List

import libcst as cst

from .mutation import MutationVisitor
from .chain import ChainVisitor
from .sql import SQLVisitor
from .hardcoded import HardcodedVisitor
from ..core.finding import Finding
from ..core.loader import RuleLoader
from ..core.context import AnalysisContext

# Set up logging
logger = logging.getLogger(__name__)


class MasterVisitor:
    """Master visitor that coordinates all sub-visitors for data mutation analysis."""
    
    def __init__(self, file_path: Path, rule_loader: RuleLoader, context: AnalysisContext):
        self.file_path = file_path
        self.rule_loader = rule_loader
        self.context = context
        self.findings: List[Finding] = []
        
        # Initialize all sub-visitors
        try:
            self.mutation_visitor = MutationVisitor(file_path, rule_loader, context)
            self.chain_visitor = ChainVisitor(file_path, rule_loader, context)
            self.sql_visitor = SQLVisitor(file_path, rule_loader, context)
            self.hardcoded_visitor = HardcodedVisitor(file_path, rule_loader, context)
            logger.debug(f"Initialized all sub-visitors for {file_path}")
        except Exception as e:
            logger.error(f"Failed to initialize sub-visitors for {file_path}: {e}")
            raise
    
    def analyze(self, tree: cst.Module, source_code: str) -> List[Finding]:
        """Perform complete analysis using all sub-visitors."""
        all_findings = []
        
        try:
            logger.debug(f"Starting analysis of {self.file_path}")
            
            # Set source code for all visitors
            for visitor in [self.mutation_visitor, self.chain_visitor, self.sql_visitor, self.hardcoded_visitor]:
                try:
                    visitor.set_source_code(source_code)
                except Exception as e:
                    logger.warning(f"Failed to set source code for {visitor.__class__.__name__}: {e}")
            
            # Run each visitor with error handling
            visitors_to_run = [
                ("mutation", self.mutation_visitor),
                ("chain", self.chain_visitor), 
                ("sql", self.sql_visitor),
                ("hardcoded", self.hardcoded_visitor)
            ]
            
            for visitor_name, visitor in visitors_to_run:
                try:
                    logger.debug(f"Running {visitor_name} visitor")
                    
                    # Create metadata wrapper and visit
                    wrapper = cst.metadata.MetadataWrapper(tree)
                    wrapper.visit(visitor)
                    
                    # Collect findings
                    visitor_findings = visitor.findings
                    all_findings.extend(visitor_findings)
                    
                    logger.debug(f"{visitor_name} visitor found {len(visitor_findings)} findings")
                    
                except Exception as e:
                    logger.error(f"Error in {visitor_name} visitor: {e}")
                    # Continue with other visitors even if one fails
                    continue
            
            logger.info(f"Analysis complete: {len(all_findings)} total findings in {self.file_path}")
            return all_findings
            
        except Exception as e:
            logger.error(f"Critical error during analysis of {self.file_path}: {e}")
            raise
    
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