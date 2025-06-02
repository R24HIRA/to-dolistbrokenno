"""
datamut - Production-grade tool for scanning Python code for data mutation operations.

This package provides static analysis capabilities to detect potential data mutation
operations in Python code, including pandas, numpy, and SQL operations.
"""

__version__ = "0.1.0"
__author__ = "datamut contributors"

from .core.finding import Finding, Severity
from .core.loader import RuleLoader

__all__ = ["Finding", "Severity", "RuleLoader", "__version__"] 