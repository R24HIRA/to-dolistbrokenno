"""Command-line interface for datamut using Typer."""

import sys
from pathlib import Path
from typing import List, Optional

import libcst as cst
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .core.context import AliasCollector, AnalysisContext
from .core.emitter import create_emitter
from .core.finding import Severity
from .core.loader import RuleLoader
from .visitors import MasterVisitor

app = typer.Typer(
    name="datamut",
    help="Production-grade tool for scanning Python code for data mutation operations",
    add_completion=False
)

console = Console()


def collect_python_files(paths: List[Path]) -> List[Path]:
    """Collect all Python files from the given paths."""
    python_files = []
    
    for path in paths:
        if path.is_file() and path.suffix == '.py':
            python_files.append(path)
        elif path.is_dir():
            python_files.extend(path.rglob('*.py'))
    
    return python_files


def analyze_file(file_path: Path, rule_loader: RuleLoader) -> List:
    """Analyze a single Python file for mutations."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
    except Exception as e:
        console.print(f"[red]Error reading {file_path}: {e}[/red]")
        return []
    
    try:
        # Parse the source code
        tree = cst.parse_module(source_code)
    except Exception as e:
        console.print(f"[red]Error parsing {file_path}: {e}[/red]")
        return []
    
    # First pass: collect aliases
    alias_collector = AliasCollector()
    tree.visit(alias_collector)
    
    # Create analysis context
    context = AnalysisContext()
    context.update_from_collector(alias_collector)
    
    # Use the master visitor to coordinate all analysis
    master_visitor = MasterVisitor(file_path, rule_loader, context)
    
    try:
        all_findings = master_visitor.analyze(tree, source_code)
    except Exception as e:
        console.print(f"[red]Error analyzing {file_path}: {e}[/red]")
        return []

    return all_findings


@app.command()
def audit(
    inputs: List[Path] = typer.Argument(
        ...,
        help="Input files or directories to analyze",
        exists=True,
        resolve_path=True
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (default: report.html)"
    ),
    format: str = typer.Option(
        "html",
        "--format", "-f",
        help="Output format: html, json, or sarif"
    ),
    min_severity: str = typer.Option(
        "MEDIUM",
        "--min-severity",
        help="Minimum severity level for exit code (LOW, MEDIUM, HIGH, CRITICAL)"
    ),
    rules_dir: Optional[Path] = typer.Option(
        None,
        "--rules-dir",
        help="Additional directory containing custom rule YAML files",
        exists=True,
        file_okay=False,
        dir_okay=True
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output"
    )
):
    """Audit Python files for data mutation operations."""
    
    # Validate format
    if format not in ["html", "json", "sarif"]:
        console.print(f"[red]Error: Unsupported format '{format}'. Use html, json, or sarif.[/red]")
        raise typer.Exit(1)
    
    # Validate severity
    try:
        min_severity_enum = Severity(min_severity.upper())
    except ValueError:
        console.print(f"[red]Error: Invalid severity '{min_severity}'. Use LOW, MEDIUM, HIGH, or CRITICAL.[/red]")
        raise typer.Exit(1)
    
    # Set default output filename
    if output is None:
        extensions = {"html": ".html", "json": ".json", "sarif": ".sarif"}
        output = Path(f"datamut-report{extensions[format]}")
    
    console.print("[bold blue]DataMut - Data Mutation Analysis Tool[/bold blue]")
    console.print(f"Analyzing {len(inputs)} input path(s)...")
    
    # Load rules
    rule_loader = RuleLoader()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        # Load built-in rules
        task = progress.add_task("Loading built-in rules...", total=None)
        try:
            rule_loader.load_builtin_rules()
            progress.update(task, description=f"Loaded {len(rule_loader.bundles)} rule bundles")
        except Exception as e:
            console.print(f"[red]Error loading built-in rules: {e}[/red]")
            raise typer.Exit(1)
        
        # Load custom rules if specified
        if rules_dir:
            progress.update(task, description="Loading custom rules...")
            for yaml_file in rules_dir.glob("*.yml"):
                try:
                    rule_loader.load_bundle(yaml_file)
                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to load {yaml_file}: {e}[/yellow]")
        
        progress.remove_task(task)
        
        # Collect Python files
        task = progress.add_task("Collecting Python files...", total=None)
        python_files = collect_python_files(inputs)
        progress.update(task, description=f"Found {len(python_files)} Python files")
        progress.remove_task(task)
        
        if not python_files:
            console.print("[yellow]No Python files found to analyze.[/yellow]")
            raise typer.Exit(0)
        
        # Analyze files
        all_findings = []
        task = progress.add_task("Analyzing files...", total=len(python_files))
        
        for i, file_path in enumerate(python_files):
            if verbose:
                progress.update(task, description=f"Analyzing {file_path.name}...")
            
            findings = analyze_file(file_path, rule_loader)
            all_findings.extend(findings)
            
            progress.update(task, advance=1)
        
        progress.remove_task(task)
        
        # Generate report
        task = progress.add_task("Generating report...", total=None)
        try:
            emitter = create_emitter(format, all_findings)
            emitter.emit(output)
            progress.update(task, description=f"Report saved to {output}")
        except Exception as e:
            console.print(f"[red]Error generating report: {e}[/red]")
            raise typer.Exit(1)
        
        progress.remove_task(task)
    
    # Display summary
    console.print("\n[bold green]Analysis Complete![/bold green]")
    
    if all_findings:
        # Create summary table
        table = Table(title="Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="magenta")
        
        table.add_row("Total Findings", str(len(all_findings)))
        table.add_row("Files Analyzed", str(len(python_files)))
        table.add_row("Files with Findings", str(len(set(f.file_path for f in all_findings))))
        
        # Count by severity
        severity_counts = {}
        for finding in all_findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in severity_counts:
                table.add_row(f"{severity} Severity", str(severity_counts[severity]))
        
        console.print(table)
        
        # Show top findings
        if verbose and all_findings:
            console.print("\n[bold]Top Findings:[/bold]")
            sorted_findings = sorted(all_findings, key=lambda f: f.severity.exit_code_weight, reverse=True)
            for finding in sorted_findings[:5]:
                console.print(f"  {finding.severity.value}: {finding.file_path}:{finding.line_number} - {finding.function_name} ({finding.mutation_type})")
    else:
        console.print("[green]No data mutation operations found![/green]")
    
    console.print(f"\nReport saved to: [bold]{output}[/bold]")
    
    # Determine exit code based on severity
    exit_code = 0
    if all_findings:
        max_severity_weight = max(f.severity.exit_code_weight for f in all_findings)
        if max_severity_weight >= min_severity_enum.exit_code_weight:
            exit_code = 1
            if verbose:
                console.print(f"[yellow]Exit code 1: Found findings with severity >= {min_severity}[/yellow]")
    
    raise typer.Exit(exit_code)


@app.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"datamut version {__version__}")


@app.command()
def list_rules(
    library: Optional[str] = typer.Option(
        None,
        "--library", "-l",
        help="Filter rules by library (pandas, numpy, sql)"
    )
):
    """List available mutation detection rules."""
    rule_loader = RuleLoader()
    
    try:
        rule_loader.load_builtin_rules()
    except Exception as e:
        console.print(f"[red]Error loading rules: {e}[/red]")
        raise typer.Exit(1)
    
    console.print("[bold blue]Available Mutation Detection Rules[/bold blue]\n")
    
    for bundle in rule_loader.bundles:
        if library and bundle.meta.library != library:
            continue
            
        console.print(f"[bold cyan]{bundle.meta.library.upper()}[/bold cyan] (alias pattern: {bundle.meta.alias_regex})")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Function", style="cyan")
        table.add_column("Mutation Type", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Notes", style="dim", max_width=50)
        
        for rule in bundle.rules:
            notes = rule.notes.strip().replace('\n', ' ') if rule.notes else ""
            if len(notes) > 47:
                notes = notes[:47] + "..."
            
            table.add_row(
                rule.func,
                rule.mutation,
                rule.default_severity.value,
                notes
            )
        
        console.print(table)
        console.print()


if __name__ == "__main__":
    app() 