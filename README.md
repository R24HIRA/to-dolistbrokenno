# DataMut

**Production-grade tool for scanning Python code for data mutation operations**

DataMut is a static analysis tool that scans Python code (and inline SQL strings) for potential data-mutation operations, assigns severity levels, and generates interactive HTML reports. It's designed for data engineers, analysts, and auditors who need to understand how their code modifies data.

## 🚀 Features

- **Static Analysis**: Pure static analysis with no external AI or network calls
- **Multiple Libraries**: Built-in support for pandas, numpy, and SQL operations
- **Configurable Rules**: YAML-based rule bundles that auditors can edit without code changes
- **Multiple Output Formats**: HTML (interactive), JSON, and SARIF for CI/CD integration
- **Rich CLI**: Beautiful command-line interface with progress indicators and colored output
- **Severity Escalation**: Smart severity escalation based on function arguments (e.g., `inplace=True`)

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install datamut
```

### From Source (Development)

```bash
# Clone the repository
git clone https://github.com/your-org/datamut.git
cd datamut

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Requirements

- Python 3.8+
- libcst >= 1.0.0
- pydantic >= 2.0.0
- typer >= 0.9.0
- rich >= 13.0.0
- pyyaml >= 6.0.0

## 🔧 Quick Start

### Basic Usage

```bash
# Analyze a single file
datamut audit my_script.py

# Analyze a directory
datamut audit src/

# Analyze with verbose output
datamut audit src/ --verbose

# Generate JSON report
datamut audit src/ --format json --output report.json

# Set minimum severity for exit code
datamut audit src/ --min-severity HIGH

# List all available rules
datamut list-rules

# Show version information
datamut version
```

### Example Analysis

Let's analyze a simple Python file:

```python
# example.py
import pandas as pd
import numpy as np

# Create test data
df = pd.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
arr = np.array([1, 2, 3, 4, 5])

# These operations will be detected as mutations
df.drop('A', axis=1, inplace=True)  # CRITICAL - inplace drop
arr = np.delete(arr, 0)             # HIGH - numpy delete

# SQL operations are also detected
import sqlite3
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
cursor.execute("DELETE FROM users WHERE active = 0")  # CRITICAL - SQL delete
```

Running DataMut on this file:

```bash
$ datamut audit example.py
DataMut - Data Mutation Analysis Tool
Analyzing 1 input path(s)...

Analysis Complete!
            Summary            
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric              ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total Findings      │ 3     │
│ Files Analyzed      │ 1     │
│ Files with Findings │ 1     │
│ CRITICAL Severity   │ 2     │
│ HIGH Severity       │ 1     │
└─────────────────────┴───────┘

Report saved to: datamut-report.html
```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=datamut

# Run specific test files
pytest tests/test_pandas_detection.py
pytest tests/test_sql_detection.py

# Run with verbose output
pytest -v

# Run a specific test
pytest tests/test_pandas_detection.py::test_pandas_drop_detection -v
```

### Test Structure

```
tests/
├── __init__.py
├── test_pandas_detection.py    # Tests for pandas mutation detection
├── test_sql_detection.py       # Tests for SQL mutation detection
└── fixtures/                   # Test data files
    ├── sample_code.py
    └── complex_analysis.py
```

### Writing Tests

Example test for a new detection rule:

```python
def test_new_mutation_detection():
    """Test detection of new mutation operation."""
    code = '''
    import pandas as pd
    df = pd.DataFrame({'A': [1, 2, 3]})
    df.new_operation()  # Should be detected
    '''
    
    # Parse and analyze
    tree = cst.parse_module(code)
    visitor = MutationVisitor(Path("test.py"), rule_loader, context)
    wrapper = cst.metadata.MetadataWrapper(tree)
    wrapper.visit(visitor)
    
    # Verify detection
    assert len(visitor.findings) == 1
    assert visitor.findings[0].function_name == 'new_operation'
```

## 🛠️ Development

### Development Setup

```bash
# Clone and setup
git clone https://github.com/your-org/datamut.git
cd datamut

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

### Development Dependencies

The `[dev]` extra includes:

- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `black` - Code formatting
- `ruff` - Linting
- `isort` - Import sorting
- `mypy` - Type checking
- `pre-commit` - Git hooks

### Code Quality

```bash
# Format code
black datamut/ tests/

# Sort imports
isort datamut/ tests/

# Lint code
ruff check datamut/ tests/

# Type checking
mypy datamut/

# Run all quality checks
make lint  # If Makefile is available
```

### Project Structure

```
datamut/
├── __init__.py
├── cli.py                 # Command-line interface
├── core/
│   ├── __init__.py
│   ├── context.py         # Analysis context and alias resolution
│   ├── emitter.py         # Report generation
│   ├── finding.py         # Finding data structures
│   ├── loader.py          # Rule loading
│   └── visitor.py         # LibCST visitors for detection
├── rules/
│   ├── pandas.yml         # Pandas detection rules
│   ├── numpy.yml          # NumPy detection rules
│   └── sql.yml            # SQL detection rules
└── render/
    └── report.html        # HTML report template
```

### Adding New Detection Rules

1. **Define rules in YAML**:

```yaml
# datamut/rules/my_library.yml
meta:
  library: my_library
  alias_regex: "^(mylib|my_library)$"

rules:
  - func: dangerous_operation
    mutation: "data destruction"
    default_severity: CRITICAL
    notes: "This operation permanently destroys data"
    extra_checks:
      arg_present:
        name: force
        value: true
        set_severity: CRITICAL
```

2. **Test the new rules**:

```python
def test_my_library_detection():
    code = '''
    import my_library as mylib
    mylib.dangerous_operation(force=True)
    '''
    # ... test implementation
```

3. **Update documentation** in README and rule files.

### Adding New Libraries

To add support for a new library:

1. Create a new rule file in `datamut/rules/`
2. Add detection patterns for the library's mutation operations
3. Update the alias resolution in `RuleLoader`
4. Add comprehensive tests
5. Update documentation

### Debugging

Enable verbose logging for debugging:

```bash
# Enable verbose output
datamut audit src/ --verbose

# Debug specific issues
python -c "
import datamut
from pathlib import Path
# Your debugging code here
"
```

## 📊 Interactive HTML Report

The HTML report includes:

- **Summary Dashboard**: Overview statistics with severity breakdown
- **Interactive Filtering**: Search, filter by severity, library, or mutation type
- **Code Snippets**: Syntax-highlighted code with mutation context
- **Detailed Notes**: Hover tooltips with explanations and recommendations
- **Responsive Design**: Works on desktop and mobile devices

## 🎯 Supported Operations

### Pandas
- `drop()`, `drop_duplicates()`, `dropna()` - Data removal operations
- `merge()`, `join()`, `concat()` - Data combination operations  
- `fillna()`, `replace()` - Data modification operations
- `pivot()`, `melt()`, `transpose()` - Data reshaping operations
- And many more...

### NumPy
- `delete()`, `insert()`, `append()` - Array modification
- `reshape()`, `resize()`, `transpose()` - Shape manipulation
- `concatenate()`, `split()`, `stack()` - Array combination/splitting
- `sort()`, `unique()`, `compress()` - Data reordering/filtering
- And many more...

### SQL
- `INSERT`, `UPDATE`, `DELETE` - Data modification
- `DROP`, `TRUNCATE`, `ALTER` - Schema/data destruction
- `MERGE`, `UPSERT`, `REPLACE` - Complex operations
- Detected in string literals and variables within Python code

## ⚙️ Configuration

### Rule Bundles

Rules are defined in YAML files that can be customized:

```yaml
# rules/pandas.yml
meta:
  library: pandas
  alias_regex: "^(pd|pandas)$"

rules:
  - func: drop
    mutation: "row/col drop"
    default_severity: HIGH
    notes: |
      Permanently removes data from DataFrame. Use with caution in production.
    extra_checks:
      arg_present:
        name: inplace
        value: true
        set_severity: CRITICAL
```

### Custom Rules

Add your own rule bundles:

```bash
datamut audit src/ --rules-dir ./custom-rules/
```

### Severity Levels

- **LOW**: Minor operations that change data organization
- **MEDIUM**: Operations that may affect data interpretation  
- **HIGH**: Operations that remove or significantly modify data
- **CRITICAL**: Destructive operations or those with `inplace=True`

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: DataMut Analysis
on: [push, pull_request]

jobs:
  datamut:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install DataMut
      run: pip install datamut
    
    - name: Run DataMut Analysis
      run: |
        datamut audit src/ --format sarif --output datamut.sarif
        datamut audit src/ --format json --output datamut.json
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: datamut.sarif
    
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: datamut-results
        path: |
          datamut.sarif
          datamut.json
          datamut-report.html
```

### Exit Codes

DataMut returns different exit codes based on findings and configuration:

- **Exit Code 0**: No issues found OR `--no-fail-on-findings` is used
- **Exit Code 1**: Issues found with severity >= `--min-severity` (default: MEDIUM)  
- **Exit Code 2+**: Tool errors or failures

Use `--no-fail-on-findings` to always exit with code 0 when analysis completes successfully, regardless of findings. This is useful for reporting-only scenarios where you don't want to fail CI/CD pipelines.

## 📚 CLI Reference

### Commands

- `datamut audit` - Analyze Python files for mutations
- `datamut list-rules` - Show available detection rules  
- `datamut version` - Show version information

### Options

```bash
datamut audit [OPTIONS] INPUTS...

Options:
  -o, --output PATH        Output file path
  -f, --format [html|json|sarif]  Output format (default: html)
  --min-severity [LOW|MEDIUM|HIGH|CRITICAL]  Minimum severity for exit code
  --rules-dir PATH         Additional custom rules directory
  -v, --verbose           Enable verbose output
  --no-fail-on-findings   Don't exit with code 1 when findings are found (always exit 0 on success)
  --help                  Show help message
```

### Examples

```bash
# Basic analysis
datamut audit src/

# Analyze specific files
datamut audit file1.py file2.py

# Generate JSON report
datamut audit src/ --format json --output mutations.json

# Only fail on HIGH or CRITICAL findings
datamut audit src/ --min-severity HIGH

# Never fail on findings (for reporting only)
datamut audit src/ --no-fail-on-findings

# Use custom rules
datamut audit src/ --rules-dir ./my-rules/

# Verbose output for debugging
datamut audit src/ --verbose

# List all available rules
datamut list-rules

# Filter rules by library
datamut list-rules --library pandas
```

## 🐛 Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'libcst'`
```bash
# Solution: Install libcst
pip install libcst>=1.0.0
```

**Issue**: No findings detected in obvious mutation code
```bash
# Solution: Check if library aliases are recognized
datamut list-rules
# Ensure your import style matches the alias patterns
```

**Issue**: `PositionProvider` metadata errors
```bash
# Solution: This is usually due to malformed Python code
# Check that your Python files are syntactically valid
python -m py_compile your_file.py
```

### Debug Mode

Enable debug logging:

```bash
# Set environment variable for detailed logging
export DATAMUT_DEBUG=1
datamut audit src/ --verbose
```

### Performance Issues

For large codebases:

```bash
# Analyze specific directories
datamut audit src/critical_modules/

# Use parallel processing (if available)
datamut audit src/ --parallel

# Exclude large files or directories
datamut audit src/ --exclude "*/tests/*" --exclude "*/migrations/*"
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Ensure all tests pass (`pytest`)
5. Run code quality checks (`black`, `ruff`, `isort`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Submit a pull request

### Contribution Guidelines

- **Tests**: All new features must include tests
- **Documentation**: Update README and docstrings
- **Code Style**: Follow Black formatting and Ruff linting
- **Type Hints**: Use type hints for all new code
- **Commit Messages**: Use conventional commit format

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/datamut/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/datamut/discussions)
- **Security**: Report security issues to security@your-org.com

## 🏆 Acknowledgments

- Built with [libcst](https://github.com/Instagram/LibCST) for Python AST analysis
- UI powered by [Bootstrap 5](https://getbootstrap.com/) and modern web standards
- CLI built with [Typer](https://typer.tiangolo.com/) and [Rich](https://github.com/Textualize/rich)
- Inspired by static analysis tools like [bandit](https://github.com/PyCQA/bandit) and [semgrep](https://github.com/returntocorp/semgrep)