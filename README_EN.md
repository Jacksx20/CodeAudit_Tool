# CodeAudit_Tool

## Code Security Audit Tool

**English | [简体中文](README.md)**

A powerful automated code security audit tool that supports multiple web frameworks and vulnerability types. It can automatically identify Source points, detect Sink points, build call chains, generate PoC verification code, and output multi-format security reports.

---

## Core Features

### 1. Source Point Identification

Automatically identify HTTP entry points, supporting the following frameworks:

- **Python**: Flask, Django, FastAPI
- **JavaScript/Node.js**: Express, Koa
- **Java**: Spring, Struts
- **Go**: Gin, Echo
- **PHP**: Laravel, Symfony

### 2. Sink Point Detection

Built-in dangerous function rule library, detecting the following vulnerability types:

- SQL Injection
- Command Injection
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Cross-Site Scripting (XSS)
- Deserialization
- Code Injection
- XML External Entity (XXE)
- LDAP Injection
- Open Redirect

### 3. Bidirectional Audit Mode

- **Forward Audit**: Trace data flow from Source to discover Sink points
- **Reverse Audit**: Trace data sources from Sink to find Source points
- **Bidirectional Audit**: Execute both forward and reverse audits to ensure comprehensive coverage

### 4. Call Chain Analysis

- Build complete Source→Sink call chains
- Analyze taint propagation paths
- Support cross-file and cross-function call chain tracking

### 5. Automatic PoC Generation

- Automatically generate verification code based on vulnerability type
- Support multiple languages: Python, JavaScript, Java, Go, PHP
- Include common attack payloads
- Directly executable for vulnerability verification

### 6. Attack Chain Analysis

- Analyze multi-vulnerability exploitation scenarios
- Identifies chainable vulnerabilities
- Generate combined attack PoCs

### 7. Multi-format Reports

- JSON format: For programmatic processing
- HTML format: Visual reports with interactive features
- Markdown format: Easy to read and share

---

## Project Structure

```
code_audit_tool/
├── cli.py                          # Main CLI entry point
├── setup.py                        # Python package installation configuration
├── pyproject.toml                  # Modern Python project configuration
├── requirements.txt                # Project dependencies
│
├── core/                           # Core modules
│   ├── __init__.py
│   ├── config.py                   # Configuration management, data structures, rule loading
│   └── audit_engine.py             # Audit engine, bidirectional audit, attack chain analysis
│
├── analyzers/                      # Analyzer modules
│   ├── __init__.py
│   ├── source_analyzer.py          # Source point analyzer (HTTP entry point identification)
│   │   └── Supported frameworks: Flask, Django, FastAPI, Express, Spring, Gin
│   ├── sink_analyzer.py            # Sink point analyzer (dangerous function detection)
│   │   └── Supported vulnerability types: SQL injection, XSS, command injection, etc. (10 types)
│   └── call_chain_analyzer.py      # Call chain analyzer (taint propagation tracking)
│       └── Functions: Build call graph, path finding, chain analysis
│
├── generators/                     # Generator modules
│   ├── __init__.py
│   └── poc_generator.py            # PoC generator (vulnerability verification code)
│       └── Supported languages: Python, JavaScript, Java, Go, PHP
│
├── reports/                        # Report modules
│   ├── __init__.py
│   └── report_generator.py         # Report generator (multi-format output)
│       └── Supported formats: JSON, HTML, Markdown
│
├── rules/                          # Rule library
│   ├── sinks/                      # Sink rules (dangerous functions)
│   │   ├── __init__.py
│   │   └── sink_rules.py           # Dangerous function rule definitions
│   │       └── Contains dangerous function patterns for 10 vulnerability types
│   ├── sources/                    # Source rules (HTTP entry points)
│   │   ├── __init__.py
│   │   └── source_patterns.py      # Framework routing pattern definitions
│   │       └── Contains routing patterns for 6 frameworks
│   └── vulnerabilities/            # Detailed vulnerability rules
│       ├── __init__.py
│       ├── README.md               # Vulnerability rules documentation
│       ├── sql_injection.json      # SQL injection rules
│       ├── xss.json                # XSS rules
│       ├── command_injection.json  # Command injection rules
│       ├── ssrf.json               # SSRF rules
│       ├── path_traversal.json     # Path traversal rules
│       ├── deserialization.json    # Deserialization rules
│       ├── code_injection.json     # Code injection rules
│       ├── xxe.json                # XXE rules
│       ├── ldap_injection.json     # LDAP injection rules
│       └── open_redirect.json      # Open redirect rules
│
├── templates/                      # Report templates
│   ├── html/
│   │   └── report_template.html    # HTML report template (visual)
│   ├── markdown/
│   │   └── report_template.md      # Markdown report template (documentation)
│   └── json/
│       └── report_template.json    # JSON report template (structured)
│
├── test/                           # Test files
│   ├── test_vulnerable_app.py      # Vulnerability test sample
│   └── test_audit.py               # Automated test script
│
├── README.md                       # Chinese documentation
└── README_EN.md                    # English documentation (this file)
```

### Architecture Overview

#### 1. Core Layer
Responsible for overall coordination and configuration management:
- **config.py**: Defines all data structures (SourcePoint, SinkPoint, CallChain, Vulnerability, PoC, AuditResult), loads and manages rule libraries
- **audit_engine.py**: Main audit engine, coordinates analyzers, executes forward/reverse audits, analyzes attack chains

#### 2. Analyzer Layer
Responsible for static code analysis and vulnerability detection:
- **source_analyzer.py**: Uses AST parsing and regex matching to identify HTTP entry points (routes, controllers)
- **sink_analyzer.py**: Identifies dangerous function calls, marks potential Sink points
- **call_chain_analyzer.py**: Builds call graphs, analyzes taint propagation paths, constructs Source→Sink call chains

#### 3. Generator Layer
Responsible for generating vulnerability verification code:
- **poc_generator.py**: Automatically generates executable PoC verification code based on vulnerability type and call chain

#### 4. Report Layer
Responsible for generating multi-format security reports:
- **report_generator.py**: Supports JSON/HTML/Markdown formats, includes statistics, details, recommendations, compliance, etc.

#### 5. Rule Library
Stores all detection rules:
- **sinks/**: Dangerous function rules (Sink points)
- **sources/**: HTTP entry point rules (Source points)
- **vulnerabilities/**: Detailed vulnerability rules (descriptions, CWE, remediation, etc.)

#### 6. Template Layer
Provides report templates:
- **html/**: Visual HTML templates
- **markdown/**: Documented Markdown templates
- **json/**: Structured JSON templates

### Data Flow

```
User Input (code path)
    ↓
CLI Entry (cli.py)
    ↓
Audit Engine (audit_engine.py)
    ├─→ Source Analyzer (source_analyzer.py)
    │   └─→ Identify HTTP entry points
    ├─→ Sink Analyzer (sink_analyzer.py)
    │   └─→ Identify dangerous functions
    ├─→ Call Chain Analyzer (call_chain_analyzer.py)
    │   └─→ Build call chains
    └─→ Attack Chain Analysis
        └─→ Identify vulnerability combinations
    ↓
PoC Generator (poc_generator.py)
    └─→ Generate verification code
    ↓
Report Generator (report_generator.py)
    ├─→ JSON report
    ├─→ HTML report
    └─→ Markdown report
    ↓
Output report files
```

---

## Installation & Usage

### Environment Requirements

#### Supported Python Versions

| Python Version | Support Status | Description |
| -------------- | -------------- | ----------- |
| Python 3.7    | ✅ Supported   | Minimum version, requires `from __future__ import annotations` for some type annotations |
| Python 3.8    | ✅ Supported   | Recommended version, full support for all features |
| Python 3.9    | ✅ Supported   | Full support, performance optimizations |
| Python 3.10   | ✅ Supported   | Full support, supports new syntax features |
| Python 3.11   | ✅ Supported   | Full support, significant performance improvements |
| Python 3.12+  | ✅ Supported   | Full support for latest versions |
| Python 2.x    | ❌ Not Supported | Does not support Python 2.x |

#### Version Selection Recommendations

- **Production Environment**: Recommended **Python 3.10+** for best performance
- **Development Environment**: Recommended **Python 3.9+** for good compatibility
- **Minimum Requirement**: **Python 3.7**, may need to handle some compatibility issues

#### Dependency Description

Core functionality uses Python standard library, no additional dependencies required:

```python
# Core dependencies (Python standard library)
- os, sys, re, ast      # File and code analysis
- json                   # Configuration and report generation
- datetime               # Time handling
- typing                 # Type annotations
- dataclasses            # Data class definitions (Python 3.7+)
- enum                   # Enum types
- collections            # Collection utilities
- pathlib                # Path handling
```

### Installation

#### Method 1: Clone Repository

```bash
git clone https://github.com/yourusername/code_audit_tool.git
cd code_audit_tool
```

#### Method 2: Install via pip (Recommended)

```bash
pip install code-audit-tool
```

#### Method 3: Development Installation

```bash
# Clone repository
git clone https://github.com/yourusername/code_audit_tool.git
cd code_audit_tool

# Install in development mode
pip install -e .
```

### Basic Usage

#### Quick Start

```bash
# Basic audit
python cli.py /path/to/code

# Specify output directory
python cli.py /path/to/code -o ./reports

# Specify report format
python cli.py /path/to/code -f json html markdown

# Only detect specific vulnerability types
python cli.py /path/to/code --vuln-types sql_injection command_injection

# Use specific audit mode
python cli.py /path/to/code --mode forward  # Forward audit
python cli.py /path/to/code --mode backward # Reverse audit
python cli.py /path/to/code --mode both     # Bidirectional audit (default)

# Disable PoC generation
python cli.py /path/to/code --no-poc

# Set maximum call chain depth
python cli.py /path/to/code --max-depth 30
```

### Command Line Arguments

| Parameter | Description | Default Value |
| ---------- | ----------- | ------------- |
| `target` | Target code path | Required |
| `-o, --output` | Output directory | `./audit_reports` |
| `-f, --formats` | Report formats | `json html markdown` |
| `--mode` | Audit mode | `both` |
| `--vuln-types` | Vulnerability types | All |
| `--frameworks` | Target frameworks | Auto-detect |
| `--max-depth` | Maximum call chain depth | `20` |
| `--no-poc` | Disable PoC generation | `False` |
| `--no-attack-chain` | Disable attack chain analysis | `False` |
| `-v, --verbose` | Verbose output | `False` |

---

## Usage Examples

### Example 1: Audit Flask Project

```bash
python cli.py ./my_flask_app -o ./reports
```

### Example 2: Only Detect SQL Injection and Command Injection

```bash
python cli.py ./my_project --vuln-types sql_injection command_injection
```

### Example 3: Generate HTML Report

```bash
python cli.py ./my_project -f html
```

### Example 4: Quick Scan (Sink Points Only)

```bash
python cli.py ./my_project --quick
```

### Example 5: Generate All Format Reports

```bash
python cli.py ./my_project --all-formats -o ./reports
```

### Example 6: Generate PoC with Custom Base URL

```bash
python cli.py ./my_project --poc --base-url http://localhost:5000
```

---

## Output Description

### Report Files

- `audit_report_YYYYMMDD_HHMMSS.json` - JSON format report
- `audit_report_YYYYMMDD_HHMMSS.html` - HTML format report
- `audit_report_YYYYMMDD_HHMMSS.md` - Markdown format report

### PoC Files

- `pocs/poc_VULN-ID_vuln_type.py` - Vulnerability verification code

### Report Contents

1. **Overview**: Audit target, time, statistics
2. **Source Points**: All identified HTTP entry points
3. **Sink Points**: All detected dangerous function calls
4. **Vulnerability Details**:
   - Vulnerability ID and type
   - Severity level
   - Source entry point information
   - Sink dangerous point information
   - Complete call chain
   - Taint propagation path
   - PoC verification code
   - Remediation recommendations
5. **Attack Chains**: Multi-vulnerability exploitation analysis

---

## Vulnerability Types

| Vulnerability Type | Description | Severity | CWE |
| ------------------ | ----------- | -------- | --- |
| sql_injection | SQL Injection | Critical | CWE-89 |
| command_injection | Command Injection | Critical | CWE-78 |
| code_injection | Code Injection | Critical | CWE-94 |
| deserialization | Deserialization | Critical | CWE-502 |
| path_traversal | Path Traversal | High | CWE-22 |
| ssrf | Server-Side Request Forgery | High | CWE-918 |
| xss | Cross-Site Scripting | High | CWE-79 |
| xxe | XML External Entity | High | CWE-611 |
| ldap_injection | LDAP Injection | High | CWE-90 |
| open_redirect | Open Redirect | Medium | CWE-601 |

---

## Advanced Features

### Custom Rules

You can add custom vulnerability detection rules:

```python
# Add custom Sink rules
SinkRule(
    vuln_type=VulnType.YOUR_VULN_TYPE,
    language=Language.PYTHON,
    function_patterns=[
        r'dangerous_function\s*\(',
    ],
    description="Vulnerability description",
    severity="high",
    cwe_id="CWE-XXX",
    remediation="Remediation recommendation",
    taint_parameters=[0]
)
```

### Add New Framework Support

Add new patterns in `analyzers/source_analyzer.py`:

```python
SourcePattern(
    framework=Framework.YOUR_FRAMEWORK,
    pattern=r'route_pattern',
    http_method='GET',
    route_group=1,
    function_group=2
)
```

---

## Notes

1. **False Positives**: The tool may produce false positives, manual review is recommended
2. **False Negatives**: Cannot detect all vulnerabilities, recommend combining with other tools
3. **Security**: PoC code is for authorized testing only, prohibited from illegal use
4. **Performance**: Large projects may require longer analysis time

---

## Changelog

### v1.1.2 (2026-03-20)

#### New Features
- ✨ Completed vulnerability rule library, added 4 new vulnerability type rule files (code_injection, xxe, ldap_injection, open_redirect)
- ✨ Added comprehensive vulnerability rule library documentation (`rules/vulnerabilities/README.md`)
- ✨ Added English README documentation (`README_EN.md`), providing complete English documentation support
- ✨ Added language switching links in both Chinese and English READMEs for easy language switching

#### Optimizations
- 🔧 Enhanced Sink analyzer, fully supporting all 10 vulnerability type detections
  - Added code injection detection (eval, exec, compile, __import__)
  - Added XXE/XML injection detection (xml.etree.ElementTree, xml.dom.minidom, etc.)
  - Added LDAP injection detection (search, search_s, search_st, bind, simple_bind)
  - Added open redirect detection (redirect, HttpResponseRedirect, redirect_to, header)
- 🔧 Improved PoC file naming format to match README specification (`poc_VULN-ID_vuln_type.py`)
- 🔧 Optimized rule file organization structure, unified rule file location to `rules/vulnerabilities/` directory

#### Fixes
- 🐛 Fixed Sink analyzer missing support for some vulnerability types
- 🐛 Fixed PoC file naming format inconsistency with README
- 🐛 Fixed scattered rule file storage causing management difficulties

#### Technical Improvements
- ⚡ Optimized Sink analyzer `_build_dangerous_functions_map` method
- ⚡ Added dangerous function mappings for 4 new vulnerability types
- ⚡ Completed severity mapping, ensuring all vulnerability types have correct severity levels
- ⚡ Improved rule file loading mechanism, automatically scans `rules/vulnerabilities/` directory

#### Documentation Updates
- 📝 Added comprehensive vulnerability rule library documentation
- 📝 Added English README with complete feature descriptions and usage guide
- 📝 Added language switching links in both README files
- 📝 Updated project structure description to reflect latest file organization
- 📝 Enhanced vulnerability type description table

#### Testing & Validation
- ✅ Verified all 10 vulnerability types have corresponding rule files
- ✅ Verified Sink analyzer fully supports all vulnerability type detections
- ✅ Verified PoC file naming format is correct
- ✅ Verified Chinese and English README links work properly
- ✅ Verified rule file loading mechanism works normally

#### Rule Library Completeness
- ✅ sql_injection - SQL Injection (5 database types supported)
- ✅ command_injection - Command Injection (3 operating systems supported)
- ✅ code_injection - Code Injection (3 programming languages supported)
- ✅ deserialization - Deserialization (6 formats supported)
- ✅ path_traversal - Path Traversal (3 systems + bypass supported)
- ✅ ssrf - Server-Side Request Forgery (4 scenarios supported)
- ✅ xss - Cross-Site Scripting (4 types + bypass supported)
- ✅ xxe - XML External Entity Injection (4 attack methods)
- ✅ ldap_injection - LDAP Injection (3 exploitation methods)
- ✅ open_redirect - Open Redirect (4 bypass techniques)

---

### v1.1.1 (2026-03-19)

#### New Features
- ✨ Added rule module `__init__.py` files, improved project structure
- ✨ Support for loading Python rule files (`sink_rules.py` and `source_patterns.py`) with priority
- ✨ Backup support for JSON rule file loading, improved compatibility

#### Optimizations
- 🔧 Optimized core module error handling mechanisms
  - Added target path validation to prevent crashes from invalid paths
  - Added independent exception handling for each audit step
  - Added detailed error logging and stack traces
- 🔧 Enhanced analyzer module robustness
  - Added file size checking (max 10MB) to avoid memory issues
  - Distinguished `PermissionError` from other exception types
  - Added detailed error logging output
- 🔧 Improved rule loading logic
  - Priority: Python rules > JSON rules
  - Fixed rule directory path reference errors
  - Support for dynamic rule module loading

#### Fixes
- 🐛 Fixed missing `__init__.py` files in rule directories
- 🐛 Fixed rule loading path reference errors (`sources` → `vulnerabilities`)
- 🐛 Fixed potential memory overflow from large file processing
- 🐛 Fixed analysis failures from permission errors

#### Technical Improvements
- ⚡ Optimized `config.py` rule loading logic, supports multiple rule formats
- ⚡ Optimized `audit_engine.py` error handling, improved stability
- ⚡ Optimized `source_analyzer.py` and `sink_analyzer.py` file processing
- ⚡ Added file size limit protection mechanism
- ⚡ Improved exception handling and logging output

#### Code Quality Improvements
- 📝 Unified error handling patterns
- 📝 Improved log output format and detail level
- 📝 Enhanced code readability and maintainability
- 📝 Strengthened code robustness and fault tolerance

#### Testing & Validation
- ✅ All optimizations passed complete testing
- ✅ Verified all functionality works normally (Source/Sink/Vulnerability/Attack Chain/Report)
- ✅ Confirmed performance and stability improvements

---

### v1.0.1 (2026-03-18)

#### New Features
- ✨ Added JSON report template file (`templates/json/report_template.json`)
- ✨ Enhanced JSON report generation, added:
  - Detailed statistics (scan duration, file analysis, vulnerability metrics, Source-Sink analysis, match rate)
  - Priority-sorted remediation recommendations
  - OWASP Top 10 compliance check results
  - CWE coverage statistics
- ✨ Added `setup.py` and `pyproject.toml` files, supports pip installation

#### Optimizations
- 🔧 Completed `requirements.txt` file, added detailed dependency categorization and comments
- 🔧 Added complete Python version support information to README
- 🔧 Fixed vulnerability severity count statistics issue in report templates
  - HTML template added low vulnerability statistics cards
  - Markdown template fixed variable replacement logic
  - Ensured all report formats correctly display Critical/High/Medium/Low vulnerability counts

#### Fixes
- 🐛 Fixed `import re` location error in `poc_generator.py`
- 🐛 Fixed missing exception handling in config loading
- 🐛 Fixed single file analysis support, now can analyze single files
- 🐛 Fixed decorator parsing issue, correctly extracts Flask route decorator parameters
- 🐛 Fixed call chain analysis logic, added direct matching functionality
- 🐛 Fixed duplicate vulnerability reporting, added deduplication logic
- 🐛 Fixed missing `summary` variable error in `_render_markdown_template` method

#### Technical Improvements
- ⚡ Optimized Source point analyzer, supports more precise decorator parsing
- ⚡ Optimized Sink point analyzer, supports single file analysis
- ⚡ Optimized call chain analyzer, added direct matching and deduplication
- ⚡ Optimized audit engine, added vulnerability deduplication logic
- ⚡ Optimized report generator, enhanced JSON report content

#### Documentation Updates
- 📝 Completed README documentation, added Python version support table
- 📝 Added detailed dependency description table
- 📝 Added version selection recommendations
- 📝 Updated project structure description

#### Testing & Validation
- ✅ Added test case file `test_vulnerable_app.py`
- ✅ Added automated test script `test_audit.py`
- ✅ Verified all report formats generate correctly
- ✅ Verified vulnerability detection functionality works normally

---

### v1.0.0 (2026-03-18)

#### Initial Release

**Core Features**
- ✅ Supports multi-framework Source point identification (Flask, Django, FastAPI, Express, Spring, Gin)
- ✅ Built-in complete dangerous function rule library
- ✅ Supports 10 common vulnerability type detections
- ✅ Implements bidirectional audit mode (forward + reverse)
- ✅ Supports call chain analysis
- ✅ Automatic PoC generation with executable verification code
- ✅ Supports multi-format report output (JSON, HTML, Markdown)
- ✅ Attack chain analysis functionality

**Supported Vulnerability Types**
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Server-Side Request Forgery (CWE-918)
- Cross-Site Scripting (CWE-79)
- Deserialization (CWE-502)
- Code Injection (CWE-94)
- LDAP Injection (CWE-90)
- XML Injection/XXE (CWE-611)
- Open Redirect (CWE-601)

**Usage**
```bash
# Basic audit
python cli.py /path/to/code

# Specify output format
python cli.py /path/to/code -f html -o report.html

# Quick scan
python cli.py /path/to/code --quick

# Generate all format reports
python cli.py /path/to/code --all-formats -o ./reports

# Generate PoC
python cli.py /path/to/code --poc --base-url http://localhost:5000
```

---

## License

MIT License

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## Contact

For questions and suggestions, please open an issue on GitHub.

---

**Version**: 1.0.2
**Last Updated**: 2026-03-19
**Status**: Stable ✅
