"""Plugin system for datamut.

This package provides the plugin infrastructure for extending datamut
with additional rule bundles and visitors for other libraries.

Third-party packages can register plugins using setuptools entry points:

[options.entry_points]
datamut.plugins =
    my_plugin = my_package.datamut_plugin

The plugin module should provide one or both of:
- get_visitors() -> List[Type[libcst.CSTVisitor]]
- get_rule_bundles() -> List[Path]
"""

import importlib
from pathlib import Path
from typing import List, Type

import libcst as cst
import pkg_resources


def load_plugin_visitors() -> List[Type[cst.CSTVisitor]]:
    """Load visitor classes from all registered plugins."""
    visitors = []
    
    for entry_point in pkg_resources.iter_entry_points('datamut.plugins'):
        try:
            plugin_module = entry_point.load()
            if hasattr(plugin_module, 'get_visitors'):
                plugin_visitors = plugin_module.get_visitors()
                if isinstance(plugin_visitors, list):
                    visitors.extend(plugin_visitors)
        except Exception as e:
            # Log warning but don't fail
            print(f"Warning: Failed to load plugin {entry_point.name}: {e}")
    
    return visitors


def load_plugin_rule_bundles() -> List[Path]:
    """Load rule bundle paths from all registered plugins."""
    rule_bundles = []
    
    for entry_point in pkg_resources.iter_entry_points('datamut.plugins'):
        try:
            plugin_module = entry_point.load()
            if hasattr(plugin_module, 'get_rule_bundles'):
                plugin_bundles = plugin_module.get_rule_bundles()
                if isinstance(plugin_bundles, list):
                    rule_bundles.extend(plugin_bundles)
        except Exception as e:
            # Log warning but don't fail
            print(f"Warning: Failed to load plugin {entry_point.name}: {e}")
    
    return rule_bundles 