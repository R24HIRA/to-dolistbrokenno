# Excel Rules Guide for DataMut

DataMut supports loading custom rules from Excel files (`.xlsx` and `.xls`) in addition to YAML files. This makes it easier for non-technical users to create and modify detection rules.

## 📋 Requirements

To use Excel rules, you need pandas installed:
```bash
pip install pandas
```

## 📊 Excel File Formats

DataMut supports two Excel file formats:

### Option 1: Single Sheet Format (Recommended)

Create a single Excel sheet with the following columns:

| Column | Required | Description | Example |
|--------|----------|-------------|---------|
| `func` | ✅ | Function name to detect | `drop` |
| `mutation` | ✅ | Type of mutation | `row/col drop` |
| `default_severity` | ✅ | Severity level | `HIGH` |
| `notes` | ❌ | Description/notes | `Permanently removes data` |
| `inplace_critical` | ❌ | Make inplace=True critical | `TRUE` |
| `library` | ❌ | Library name (inferred from filename if missing) | `pandas` |
| `alias_regex` | ❌ | Regex for aliases (auto-generated if missing) | `^(pd\|pandas)$` |

**Example Excel content:**

| func | mutation | default_severity | notes | inplace_critical | library | alias_regex |
|------|----------|------------------|-------|------------------|---------|-------------|
| drop | row/col drop | HIGH | Permanently removes data | TRUE | pandas | ^(pd\|pandas)$ |
| fillna | null imputation | MEDIUM | Fills missing values | TRUE | pandas | ^(pd\|pandas)$ |
| hardcoded_number | data validation | HIGH | Custom hardcoded number checks | FALSE | custom | ^(custom|cust)$ |
| delete | element removal | HIGH | Removes array elements | FALSE | numpy | ^(np\|numpy)$ |
| DELETE | data deletion | CRITICAL | sql | ^(sql\|SQL)$ |

### Option 2: Multi-Sheet Format

Create an Excel file with two sheets:

#### Sheet 1: "meta"
| Key | Value |
|-----|-------|
| library | pandas |
| alias_regex | ^(pd\|pandas)$ |

#### Sheet 2: "rules"
| func | mutation | default_severity | notes | inplace_critical |
|------|----------|------------------|-------|------------------|
| drop | row/col drop | HIGH | Permanently removes data | TRUE |
| fillna | null imputation | MEDIUM | Fills missing values | TRUE |

## 🎯 Column Details

### Required Columns

- **`func`**: The exact function name to detect (e.g., `drop`, `fillna`, `DELETE`)
- **`mutation`**: Description of what the function does (e.g., `row/col drop`, `data deletion`)
- **`default_severity`**: One of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`

### Optional Columns

- **`notes`**: Detailed explanation of why this is flagged and recommendations
- **`inplace_critical`**: Set to `TRUE`/`YES`/`1` to make `inplace=True` calls CRITICAL severity
- **`library`**: Library name (defaults to filename without extension)
- **`alias_regex`**: Regex pattern for common aliases (auto-generated if missing)

## 🚀 Usage Examples

### Creating Custom Rules

1. **Create Excel file**: `my_custom_rules.xlsx`
2. **Add your rules**:

| func | mutation | default_severity | notes |
|------|----------|------------------|-------|
| risky_function | data manipulation | HIGH | Custom function that modifies data |
| delete_records | record deletion | CRITICAL | Permanently deletes database records |

3. **Use with DataMut**:
```bash
# Place in rules directory
datamut audit src/ --rules-dir ./custom-rules/

# Or put alongside built-in rules
cp my_custom_rules.xlsx datamut/rules/
datamut audit src/
```

### Financial Institution Example

```excel
func | mutation | default_severity | notes | inplace_critical
process_transactions | transaction processing | HIGH | Modifies financial transactions | TRUE
calculate_interest | interest calculation | MEDIUM | Calculates and applies interest | FALSE
update_balance | balance update | CRITICAL | Updates account balances | TRUE
audit_trail | audit logging | LOW | Creates audit records | FALSE
```

### Database Operations Example

```excel
func | mutation | default_severity | notes | library | alias_regex
execute_stored_proc | stored procedure | HIGH | Executes database stored procedures | database | ^(db|database)$
bulk_insert | bulk data insertion | MEDIUM | Inserts large amounts of data | database | ^(db|database)$
truncate_table | table truncation | CRITICAL | Removes all table data | database | ^(db|database)$
```

## ⚠️ Common Pitfalls

1. **Empty Rows**: Leave no empty rows between rules
2. **Case Sensitivity**: Severity levels must be uppercase (`HIGH` not `high`)
3. **Required Columns**: `func`, `mutation`, and `default_severity` are mandatory
4. **Boolean Values**: Use `TRUE`/`FALSE`, `YES`/`NO`, or `1`/`0` for `inplace_critical`

## 🔧 Advanced Features

### Multiple Libraries in One File

You can include rules for multiple libraries by using the `library` column:

| func | mutation | default_severity | library | alias_regex |
|------|----------|------------------|---------|-------------|
| drop | row/col drop | HIGH | pandas | ^(pd\|pandas)$ |
| delete | element removal | HIGH | numpy | ^(np\|numpy)$ |
| DELETE | data deletion | CRITICAL | sql | ^(sql\|SQL)$ |

### Custom Severity Escalation

Use `inplace_critical` to automatically escalate severity when `inplace=True`:

| func | mutation | default_severity | inplace_critical | notes |
|------|----------|------------------|------------------|-------|
| fillna | null imputation | MEDIUM | TRUE | Becomes CRITICAL when inplace=True |

## 🎯 File Naming Conventions

- **Library-specific**: `pandas_custom.xlsx`, `numpy_rules.xlsx`
- **Organization-specific**: `company_rules.xlsx`, `financial_rules.xlsx`
- **Feature-specific**: `data_validation.xlsx`, `security_rules.xlsx`

## 🔍 Validation

DataMut will validate your Excel rules and show helpful error messages:

```bash
$ datamut audit src/ --rules-dir ./rules/
[red]Error: Excel file missing required columns: ['func', 'mutation'][/red]
[yellow]Warning: Invalid severity 'medium' in row 3, should be uppercase[/yellow]
```

## 🚀 Getting Started

1. **Download Template**: Use `examples/custom_rules_template.xlsx` as a starting point
2. **Create Rules**: Add your organization's specific mutation patterns
3. **Test**: Run DataMut to validate your rules work correctly
4. **Share**: Excel files are easy to share with auditors and compliance teams

Excel rules make DataMut accessible to business users while maintaining the same powerful detection capabilities! 