"""Output emitters for different report formats."""

import json
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader

from .finding import Finding


class BaseEmitter(ABC):
    """Base class for all output emitters."""
    
    def __init__(self, findings: List[Finding]):
        self.findings = findings
    
    @abstractmethod
    def emit(self, output_path: Path) -> None:
        """Emit the report to the specified path."""
        pass
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for the findings."""
        stats = {
            'total_findings': len(self.findings),
            'by_severity': {},
            'by_library': {},
            'by_mutation_type': {},
            'files_analyzed': len(set(f.file_path for f in self.findings))
        }
        
        for finding in self.findings:
            # By severity
            severity = finding.severity.value
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # By library
            library = finding.library
            stats['by_library'][library] = stats['by_library'].get(library, 0) + 1
            
            # By mutation type
            mutation = finding.mutation_type
            stats['by_mutation_type'][mutation] = stats['by_mutation_type'].get(mutation, 0) + 1
        
        return stats


class HTMLEmitter(BaseEmitter):
    """Emits interactive HTML reports with Bootstrap and htmx."""
    
    def emit(self, output_path: Path) -> None:
        """Generate and write HTML report."""
        template_dir = Path(__file__).parent.parent / "render"
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html")
        
        # Prepare file list for dropdown
        file_stats = {}
        for finding in self.findings:
            file_path = str(finding.file_path)
            if file_path not in file_stats:
                file_stats[file_path] = {
                    'path': file_path,
                    'name': Path(file_path).name,
                    'findings_count': 0
                }
            file_stats[file_path]['findings_count'] += 1
        
        file_list = sorted(file_stats.values(), key=lambda x: x['findings_count'], reverse=True)
        
        # Create findings with display_path for template
        findings_with_display_path = []
        for finding in self.findings:
            finding_dict = {
                'file_path': finding.file_path,
                'display_path': str(finding.file_path),
                'line_number': finding.line_number,
                'column_offset': finding.column_offset,
                'library': finding.library,
                'function_name': finding.function_name,
                'mutation_type': finding.mutation_type,
                'severity': finding.severity,
                'code_snippet': finding.code_snippet,
                'notes': finding.notes,
                'rule_id': finding.rule_id,
                'extra_context': finding.extra_context
            }
            findings_with_display_path.append(finding_dict)
        
        # Generate JavaScript data for charts
        summary_stats = self.get_summary_stats()
        severity_js_data = []
        for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            count = summary_stats['by_severity'].get(severity, 0)
            severity_js_data.append(f"severityData['{severity}'] = {count};")
        
        # Prepare data for template
        context = {
            'findings': findings_with_display_path,
            'summary': summary_stats,
            'generated_at': datetime.now().isoformat(),
            'total_files': len(set(f.file_path for f in self.findings)),
            'severities': ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            'severity_js_assignments': '\n            '.join(severity_js_data),
            'file_list': file_list
        }
        
        # Render template
        html_content = template.render(**context)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)


class JSONEmitter(BaseEmitter):
    """Emits JSON reports for programmatic consumption."""
    
    def emit(self, output_path: Path) -> None:
        """Generate and write JSON report."""
        report = {
            'metadata': {
                'tool': 'datamut',
                'version': '0.1.0',
                'generated_at': datetime.now().isoformat(),
                'summary': self.get_summary_stats()
            },
            'findings': [self._finding_to_dict(f) for f in self.findings]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert a Finding to a dictionary."""
        return {
            'file_path': str(finding.file_path),
            'line_number': finding.line_number,
            'column_offset': finding.column_offset,
            'library': finding.library,
            'function_name': finding.function_name,
            'mutation_type': finding.mutation_type,
            'severity': finding.severity.value,
            'code_snippet': finding.code_snippet,
            'notes': finding.notes,
            'rule_id': finding.rule_id,
            'extra_context': finding.extra_context
        }


class SARIFEmitter(BaseEmitter):
    """Emits SARIF reports for GitHub Advanced Security integration."""
    
    def emit(self, output_path: Path) -> None:
        """Generate and write SARIF report."""
        sarif_report = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'datamut',
                        'version': '0.1.0',
                        'informationUri': 'https://github.com/datamut/datamut',
                        'rules': self._generate_rules()
                    }
                },
                'results': [finding.to_sarif_result() for finding in self.findings],
                'invocations': [{
                    'executionSuccessful': True,
                    'endTimeUtc': datetime.now().isoformat() + 'Z'
                }]
            }]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)
    
    def _generate_rules(self) -> List[Dict[str, Any]]:
        """Generate SARIF rule definitions from findings."""
        rules = {}
        
        for finding in self.findings:
            rule_id = finding.rule_id or f"{finding.library}.{finding.function_name}"
            if rule_id not in rules:
                rules[rule_id] = {
                    'id': rule_id,
                    'name': f"{finding.library}.{finding.function_name}",
                    'shortDescription': {
                        'text': finding.mutation_type
                    },
                    'fullDescription': {
                        'text': finding.notes or f"Detects {finding.mutation_type} operations"
                    },
                    'defaultConfiguration': {
                        'level': finding._sarif_level()
                    },
                    'properties': {
                        'category': 'data-mutation',
                        'library': finding.library
                    }
                }
        
        return list(rules.values())


def create_emitter(format_type: str, findings: List[Finding]) -> BaseEmitter:
    """Factory function to create appropriate emitter."""
    emitters = {
        'html': HTMLEmitter,
        'json': JSONEmitter,
        'sarif': SARIFEmitter
    }
    
    if format_type not in emitters:
        raise ValueError(f"Unsupported format: {format_type}. Supported: {list(emitters.keys())}")
    
    return emitters[format_type](findings) 