"""Visitor package for DataMut static analysis."""

from .master import MasterVisitor
from .base import BaseVisitor

__all__ = ['MasterVisitor', 'BaseVisitor'] 