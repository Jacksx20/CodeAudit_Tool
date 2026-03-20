# Vulnerability Rules Library

**English | [简体中文](README.md)**

This directory contains all vulnerability detection rules supported by the code security audit tool.

## Rules Library Integrity Verification

| Vulnerability Type | Description | Severity | CWE | Rule File | Status |
|-------------------|-------------|----------|-----|-----------|--------|
| sql_injection | SQL Injection | Critical | CWE-89 | ✅ sql_injection.json | [OK] |
| command_injection | Command Injection | Critical | CWE-78 | ✅ command_injection.json | [OK] |
| code_injection | Code Injection | Critical | CWE-94 | ✅ code_injection.json | [OK] |
| deserialization | Deserialization | Critical | CWE-502 | ✅ deserialization.json | [OK] |
| path_traversal | Path Traversal | High | CWE-22 | ✅ path_traversal.json | [OK] |
| ssrf | Server-Side Request Forgery | High | CWE-918 | ✅ ssrf.json | [OK] |
| xss | Cross-Site Scripting | High | CWE-79 | ✅ xss.json | [OK] |
| xxe | XML External Entity Injection | High | CWE-611 | ✅ xxe.json | [OK] |
| ldap_injection | LDAP Injection | High | CWE-90 | ✅ ldap_injection.json | [OK] |
| open_redirect | Open Redirect | Medium | CWE-601 | ✅ open_redirect.json | [OK] |

## Rule File Content Description

Each rule file contains the following complete content:

### 1. Basic Information
- **Vulnerability Name**: Both Chinese and English
- **CWE ID**: Official MITRE CWE number
- **CVSS Base Score**: Common Vulnerability Scoring System base score
- **Detailed Description**: Technical description of the vulnerability
- **Impact**: Potential damage caused by the vulnerability

### 2. Payload Library
Each vulnerability type includes multiple payloads covering various databases, operating systems, programming languages, and scenarios:

- **sql_injection**: mysql, postgresql, sqlite, mssql, oracle (5 databases)
- **command_injection**: linux, windows, generic (3 operating systems)
- **code_injection**: python, php, javascript (3 programming languages)
- **deserialization**: python_pickle, python_pickle_base64, java, php, yaml, json (6 formats)
- **path_traversal**: linux, windows, bypass (3 systems + bypass)
- **ssrf**: internal, cloud_metadata, file, bypass (4 scenarios)
- **xss**: reflected, stored, dom, bypass (4 types + bypass)
- **xxe**: file_read, ssrf, dos, blind_xxe (4 attack methods)
- **ldap_injection**: authentication_bypass, information_disclosure, blind_ldap (3 exploitation methods)
- **open_redirect**: basic_redirects, javascript_redirects, data_redirects, url_encoding (4 bypass techniques)

### 3. Detection Patterns
- **Dangerous Function Detection Patterns**: Used to identify potentially dangerous function calls
- **Secure Coding Patterns**: Used to identify secure coding practices

### 4. Remediation Suggestions
Each vulnerability type includes 6-7 detailed remediation suggestions covering:
- Input validation and filtering
- Using secure APIs and methods
- Implementing the principle of least privilege
- Using security frameworks and libraries
- Configuring security measures

### 5. References
- OWASP official documentation
- MITRE CWE database
- PortSwigger security guides

## Rule File Structure

```json
{
    "vulnerability_type": {
        "name": "Vulnerability Name",
        "cwe_id": "CWE-XXX",
        "cvss_base_score": 0.0,
        "description": "Detailed vulnerability description",
        "impact": "Impact scope",
        "payloads": {
            "payload_type": [
                "payload1",
                "payload2",
                "..."
            ]
        },
        "detection_patterns": [
            "pattern1",
            "pattern2",
            "..."
        ],
        "safe_patterns": [
            "safe_pattern1",
            "safe_pattern2",
            "..."
        ],
        "remediation": [
            "Remediation suggestion 1",
            "Remediation suggestion 2",
            "..."
        ],
        "references": [
            "https://...",
            "https://...",
            "..."
        ]
    }
}
```

## Rule File Location

```
CodeAudit_Tool/rules/vulnerabilities/
├── __init__.py
├── README.md
├── README_EN.md
├── sql_injection.json
├── command_injection.json
├── code_injection.json
├── deserialization.json
├── path_traversal.json
├── ssrf.json
├── xss.json
├── xxe.json
├── ldap_injection.json
└── open_redirect.json
```

## Usage Instructions

### Adding New Vulnerability Types

1. Create a new JSON file in this directory with the vulnerability type name (e.g., `new_vulnerability.json`)
2. Write the rule content following the above structure
3. Run the test script to verify the rule format:
   ```bash
   python test_rules.py
   ```
4. Update this README file to add the new vulnerability type description

### Modifying Existing Rules

1. Find the corresponding rule file
2. Modify the required fields (payloads, detection_patterns, etc.)
3. Run the test script to verify the changes:
   ```bash
   python test_rules.py
   ```

### Rule Loading Mechanism

The tool automatically loads all JSON rule files from the `rules/vulnerabilities/` directory:
- Python rule files are loaded first (if available)
- JSON rule files are loaded as fallback
- Supports dynamic loading and hot reloading

## Detailed Vulnerability Type Descriptions

### Critical Level Vulnerabilities (4)

1. **SQL Injection (CWE-89)**
   - Allows attackers to manipulate database queries
   - Can lead to data leakage, tampering, and privilege escalation
   - Supports payloads for multiple databases

2. **Command Injection (CWE-78)**
   - Allows attackers to execute system commands
   - Can lead to complete server compromise
   - Supports Linux, Windows, and other systems

3. **Code Injection (CWE-94)**
   - Allows attackers to execute arbitrary code
   - Can lead to remote code execution
   - Supports Python, PHP, JavaScript, and other languages

4. **Deserialization (CWE-502)**
   - Allows attackers to execute malicious code through deserialization
   - Can lead to remote code execution
   - Supports multiple serialization formats

### High Level Vulnerabilities (5)

5. **Path Traversal (CWE-22)**
   - Allows attackers to access arbitrary files on the server
   - Can lead to sensitive file disclosure
   - Supports path formats for multiple operating systems

6. **Server-Side Request Forgery (CWE-918)**
   - Allows attackers to initiate requests as the server
   - Can lead to internal network penetration and cloud metadata access
   - Supports multiple SSRF scenarios

7. **Cross-Site Scripting (CWE-79)**
   - Allows attackers to execute malicious scripts in victim browsers
   - Can lead to cookie theft and session hijacking
   - Supports reflected, stored, and DOM-based XSS

8. **XML External Entity Injection (CWE-611)**
   - Allows attackers to access sensitive information through XML external entities
   - Can lead to file reading, SSRF, and DoS
   - Supports multiple XXE attack methods

9. **LDAP Injection (CWE-90)**
   - Allows attackers to manipulate LDAP queries
   - Can lead to authentication bypass and information disclosure
   - Supports multiple LDAP injection scenarios

### Medium Level Vulnerabilities (1)

10. **Open Redirect (CWE-601)**
    - Allows attackers to redirect users to malicious websites
    - Can be used for phishing and credential theft
    - Supports multiple redirect bypass techniques

## Maintenance and Updates

- **Regular Payload Updates**: Keep the payload library up-to-date
- **Add New Detection Patterns**: Update detection rules based on new attack techniques
- **Improve Remediation Suggestions**: Provide more detailed and practical remediation solutions
- **Refer to Latest Security Standards**: Follow the latest security guidelines from OWASP, MITRE, etc.

## Contribution Guidelines

Contributions to add new vulnerability type rules or improve existing rules are welcome:

1. Fork the project repository
2. Create new rule files or modify existing files
3. Ensure rule format is correct and content is complete
4. Run the test script for verification
5. Submit a Pull Request

## License

This rules library follows the project's main license (MIT License).

## Contact

If you have any questions or suggestions, please contact us through the project Issues.

---

**Last Updated**: 2026-03-19
**Version**: 1.1.1
**Status**: Complete ✅
