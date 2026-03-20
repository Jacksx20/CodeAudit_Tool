# 漏洞规则库说明

**[English](README_EN.md) | 简体中文**

本目录包含代码安全审计工具支持的所有漏洞类型检测规则。

## 规则库完整性验证

| 漏洞类型 | 说明 | 严重程度 | CWE | 规则文件 | 状态 |
|---------|------|---------|-----|---------|------|
| sql_injection | SQL注入 | Critical | CWE-89 | ✅ sql_injection.json | [OK] |
| command_injection | 命令注入 | Critical | CWE-78 | ✅ command_injection.json | [OK] |
| code_injection | 代码注入 | Critical | CWE-94 | ✅ code_injection.json | [OK] |
| deserialization | 反序列化 | Critical | CWE-502 | ✅ deserialization.json | [OK] |
| path_traversal | 路径遍历 | High | CWE-22 | ✅ path_traversal.json | [OK] |
| ssrf | 服务端请求伪造 | High | CWE-918 | ✅ ssrf.json | [OK] |
| xss | 跨站脚本 | High | CWE-79 | ✅ xss.json | [OK] |
| xxe | XML外部实体注入 | High | CWE-611 | ✅ xxe.json | [OK] |
| ldap_injection | LDAP注入 | High | CWE-90 | ✅ ldap_injection.json | [OK] |
| open_redirect | 开放重定向 | Medium | CWE-601 | ✅ open_redirect.json | [OK] |

## 规则文件内容说明

每个规则文件都包含以下完整内容：

### 1. 基本信息
- **漏洞名称**：中英文对照
- **CWE编号**：MITRE官方CWE编号
- **CVSS基础评分**：通用漏洞评分系统基础分
- **详细描述**：漏洞的详细技术说明
- **影响范围**：漏洞可能造成的危害

### 2. Payload库
每个漏洞类型都包含多种Payload，覆盖不同的数据库、操作系统、编程语言等场景：

- **sql_injection**: mysql, postgresql, sqlite, mssql, oracle (5种数据库)
- **command_injection**: linux, windows, generic (3种操作系统)
- **code_injection**: python, php, javascript (3种编程语言)
- **deserialization**: python_pickle, python_pickle_base64, java, php, yaml, json (6种格式)
- **path_traversal**: linux, windows, bypass (3种系统+绕过)
- **ssrf**: internal, cloud_metadata, file, bypass (4种场景)
- **xss**: reflected, stored, dom, bypass (4种类型+绕过)
- **xxe**: file_read, ssrf, dos, blind_xxe (4种攻击方式)
- **ldap_injection**: authentication_bypass, information_disclosure, blind_ldap (3种利用方式)
- **open_redirect**: basic_redirects, javascript_redirects, data_redirects, url_encoding (4种绕过)

### 3. 检测模式
- **危险函数检测模式**：用于识别潜在的危险函数调用
- **安全编码模式**：用于识别安全的编码实践

### 4. 修复建议
每个漏洞类型都包含 6-7 条详细的修复建议，涵盖：
- 输入验证和过滤
- 使用安全的API和方法
- 实施最小权限原则
- 使用安全框架和库
- 配置安全措施

### 5. 参考链接
- OWASP官方文档
- MITRE CWE数据库
- PortSwigger安全指南

## 规则文件结构

```json
{
    "vulnerability_type": {
        "name": "漏洞名称",
        "cwe_id": "CWE-XXX",
        "cvss_base_score": 0.0,
        "description": "漏洞详细描述",
        "impact": "影响范围",
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
            "修复建议1",
            "修复建议2",
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

## 规则文件位置

```
CodeAudit_Tool/rules/vulnerabilities/
├── __init__.py
├── README.md
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


## 使用说明

### 添加新的漏洞类型

1. 在本目录创建新的JSON文件，文件名为漏洞类型（如 `new_vulnerability.json`）
2. 按照上述结构编写规则内容
3. 运行测试脚本验证规则格式：
   ```bash
   python test_rules.py
   ```
4. 更新本README文件，添加新漏洞类型的说明

### 修改现有规则

1. 找到对应的规则文件
2. 修改需要的字段（payloads、detection_patterns等）
3. 运行测试脚本验证修改：
   ```bash
   python test_rules.py
   ```

### 规则加载机制

工具会自动加载 `rules/vulnerabilities/` 目录下的所有JSON规则文件：
- 优先加载Python规则文件（如果存在）
- 备用加载JSON规则文件
- 支持动态加载和热更新

## 漏洞类型详细说明

### Critical级别漏洞（4个）

1. **SQL注入 (CWE-89)**
   - 允许攻击者操纵数据库查询
   - 可导致数据泄露、篡改、权限提升
   - 支持多种数据库的Payload

2. **命令注入 (CWE-78)**
   - 允许攻击者执行系统命令
   - 可导致服务器完全控制
   - 支持Linux、Windows等系统

3. **代码注入 (CWE-94)**
   - 允许攻击者执行任意代码
   - 可导致远程代码执行
   - 支持Python、PHP、JavaScript等语言

4. **反序列化 (CWE-502)**
   - 允许攻击者通过反序列化执行恶意代码
   - 可导致远程代码执行
   - 支持多种序列化格式

### High级别漏洞（5个）

5. **路径遍历 (CWE-22)**
   - 允许攻击者访问服务器上的任意文件
   - 可导致敏感文件泄露
   - 支持多种操作系统的路径格式

6. **服务端请求伪造 (CWE-918)**
   - 允许攻击者以服务器身份发起请求
   - 可导致内网渗透、云元数据访问
   - 支持多种SSRF场景

7. **跨站脚本 (CWE-79)**
   - 允许攻击者在受害者浏览器中执行恶意脚本
   - 可导致Cookie窃取、会话劫持
   - 支持反射型、存储型、DOM型XSS

8. **XML外部实体注入 (CWE-611)**
   - 允许攻击者通过XML外部实体访问敏感信息
   - 可导致文件读取、SSRF、DoS
   - 支持多种XXE攻击方式

9. **LDAP注入 (CWE-90)**
   - 允许攻击者操纵LDAP查询
   - 可导致认证绕过、信息泄露
   - 支持多种LDAP注入场景

### Medium级别漏洞（1个）

10. **开放重定向 (CWE-601)**
    - 允许攻击者将用户重定向到恶意网站
    - 可用于网络钓鱼、凭证窃取
    - 支持多种重定向绕过技术

## 维护和更新

- **定期更新Payload**：保持Payload库的时效性
- **新增检测模式**：根据新的攻击手法更新检测规则
- **完善修复建议**：提供更详细和实用的修复方案
- **参考最新安全标准**：遵循OWASP、MITRE等最新安全指南

## 贡献指南

欢迎贡献新的漏洞类型规则或改进现有规则：

1. Fork项目仓库
2. 创建新的规则文件或修改现有文件
3. 确保规则格式正确且内容完整
4. 运行测试脚本验证
5. 提交Pull Request

## 许可证

本规则库遵循项目的主许可证（MIT License）。

## 联系方式

如有问题或建议，请通过项目Issues联系我们。

---

**最后更新**: 2026-03-19
**版本**: 1.1.1
**状态**: 完整 ✅
