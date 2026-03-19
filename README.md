# CodeAudit_Tool

## 代码安全审计工具Code Security Audit Tool

一个功能强大的自动化代码安全审计工具，支持多种Web框架和漏洞类型，能够自动识别Source点、检测Sink点、构建调用链、生成PoC验证代码，并输出多格式安全报告。

---

## 核心功能

### 1. Source点识别

自动识别HTTP入口点，支持以下框架：

- **Python**: Flask, Django, FastAPI
- **JavaScript/Node.js**: Express, Koa
- **Java**: Spring, Struts
- **Go**: Gin, Echo
- **PHP**: Laravel, Symfony

### 2. Sink点检测

内置危险函数规则库，检测以下漏洞类型：

- SQL注入 (SQL Injection)
- 命令注入 (Command Injection)
- 路径遍历 (Path Traversal)
- 服务端请求伪造 (SSRF)
- 跨站脚本 (XSS)
- 反序列化漏洞 (Deserialization)
- 代码注入 (Code Injection)
- XML外部实体注入 (XXE)
- LDAP注入 (LDAP Injection)
- 开放重定向 (Open Redirect)

### 3. 双向审计模式

- **正向审计**: 从Source出发，追踪数据流，发现Sink点
- **反向审计**: 从Sink出发，追溯数据来源，找到Source点
- **双向审计**: 同时执行正向和反向审计，确保全面覆盖

### 4. 调用链分析

- 构建完整的Source→Sink调用链
- 分析污点传播路径
- 支持跨文件、跨函数的调用链追踪

### 5. PoC自动生成

- 根据漏洞类型自动生成验证代码
- 支持Python、JavaScript、Java、Go、PHP等多种语言
- 包含常见攻击Payload
- 可直接执行验证漏洞

### 6. 攻击链分析

- 分析多漏洞组合利用场景
- 识别可串联的漏洞链
- 生成组合攻击PoC

### 7. 多格式报告

- JSON格式：便于程序处理
- HTML格式：可视化报告，支持交互
- Markdown格式：便于阅读和分享

---

## 项目结构

```
CodeAudit_Tool/
├── cli.py                          # 命令行主入口文件
├── setup.py                        # Python 包安装配置
├── pyproject.toml                  # 现代 Python 项目配置
├── requirements.txt                # 项目依赖清单
│
├── core/                           # 核心模块
│   ├── __init__.py
│   ├── config.py                   # 配置管理、数据结构定义、规则加载
│   └── audit_engine.py             # 审计引擎、双向审计、攻击链分析
│
├── analyzers/                      # 分析器模块
│   ├── __init__.py
│   ├── source_analyzer.py          # Source点分析器（HTTP入口点识别）
│   │   └── 支持框架: Flask, Django, FastAPI, Express, Spring, Gin
│   ├── sink_analyzer.py            # Sink点分析器（危险函数检测）
│   │   └── 支持漏洞类型: SQL注入, XSS, 命令注入等10种
│   └── call_chain_analyzer.py      # 调用链分析器（污点传播追踪）
│       └── 功能: 构建调用图、路径查找、链路分析
│
├── generators/                     # 生成器模块
│   ├── __init__.py
│   └── poc_generator.py            # PoC生成器（漏洞验证代码）
│       └── 支持语言: Python, JavaScript, Java, Go, PHP
│
├── reports/                        # 报告模块
│   ├── __init__.py
│   └── report_generator.py         # 报告生成器（多格式输出）
│       └── 支持格式: JSON, HTML, Markdown
│
├── rules/                          # 规则库
│   ├── sinks/                      # Sink规则（危险函数）
│   │   ├── __init__.py
│   │   └── sink_rules.py           # 危险函数规则定义
│   │       └── 包含10种漏洞类型的危险函数模式
│   ├── sources/                    # Source规则（HTTP入口点）
│   │   ├── __init__.py
│   │   └── source_patterns.py      # 框架路由模式定义
│   │       └── 包含6种框架的路由模式
│   └── vulnerabilities/            # 漏洞详细规则
│       ├── __init__.py
│       ├── sql_injection.json      # SQL注入规则
│       ├── xss.json                # XSS规则
│       ├── command_injection.json  # 命令注入规则
│       ├── ssrf.json               # SSRF规则
│       ├── path_traversal.json     # 路径遍历规则
│       └── deserialization.json    # 反序列化规则
│
├── templates/                      # 报告模板
│   ├── html/
│   │   └── report_template.html    # HTML报告模板（可视化）
│   ├── markdown/
│   │   └── report_template.md      # Markdown报告模板（文档）
│   └── json/
│       └── report_template.json    # JSON报告模板（结构化）
│
├── test/                           # 测试文件
│   ├── test_vulnerable_app.py      # 漏洞测试样本
│   └── test_audit.py               # 自动化测试脚本
│
└── README.md                       # 项目文档
```

---

### 架构说明

#### 1. 核心层 (Core Layer)

**负责整体协调和配置管理：**

* **config.py**: 定义所有数据结构（SourcePoint, SinkPoint, CallChain, Vulnerability, PoC, AuditResult），加载和管理规则库
* **audit\_engine.py**: 主审计引擎，协调各分析器，执行正向/反向审计，分析攻击链

#### 2. 分析层 (Analyzer Layer)

**负责代码静态分析和漏洞检测：**

* **source\_analyzer.py**: 使用AST解析和正则匹配，识别HTTP入口点（路由、控制器）
* **sink\_analyzer.py**: 识别危险函数调用，标记潜在的Sink点
* **call\_chain\_analyzer.py**: 构建调用图，分析污点传播路径，构建Source→Sink调用链

#### 3. 生成层 (Generator Layer)

**负责生成漏洞验证代码：**

* **poc\_generator.py**: 根据漏洞类型和调用链，自动生成可执行的PoC验证代码

#### 4. 报告层 (Report Layer)

**负责生成多格式安全报告：**

* **report\_generator.py**: 支持JSON/HTML/Markdown三种格式，包含统计、详情、建议、合规性等

#### 5. 规则库 (Rules)

**存储所有检测规则：**

* **sinks/**: 危险函数规则（Sink点）
* **sources/**: HTTP入口点规则（Source点）
* **vulnerabilities/**: 漏洞详细规则（描述、CWE、修复建议等）

#### 6. 模板层 (Templates)

**提供报告模板：**

* **html/**: 可视化HTML模板
* **markdown/**: 文档化Markdown模板
* **json/**: 结构化JSON模板

### 数据流

```
用户输入 (代码路径)
    ↓
CLI入口 (cli.py)
    ↓
审计引擎 (audit_engine.py)
    ├─→ Source分析器 (source_analyzer.py)
    │   └─→ 识别HTTP入口点
    ├─→ Sink分析器 (sink_analyzer.py)
    │   └─→ 识别危险函数
    ├─→ 调用链分析器 (call_chain_analyzer.py)
    │   └─→ 构建调用链
    └─→ 攻击链分析
        └─→ 识别漏洞组合
    ↓
PoC生成器 (poc_generator.py)
    └─→ 生成验证代码
    ↓
报告生成器 (report_generator.py)
    ├─→ JSON报告
    ├─→ HTML报告
    └─→ Markdown报告
    ↓
输出报告文件
```

---

## 安装使用

### 环境要求

#### 支持的Python版本


| Python版本   | 支持状态  | 说明                                                               |
| ------------ | --------- | ------------------------------------------------------------------ |
| Python 3.7   | ✅ 支持   | 最低支持版本，部分类型注解需要`from __future__ import annotations` |
| Python 3.8   | ✅ 支持   | 推荐版本，完整支持所有功能                                         |
| Python 3.9   | ✅ 支持   | 完整支持，性能优化                                                 |
| Python 3.10  | ✅ 支持   | 完整支持，支持新的语法特性                                         |
| Python 3.11  | ✅ 支持   | 完整支持，性能显著提升                                             |
| Python 3.12+ | ✅ 支持   | 完整支持最新版本                                                   |
| Python 2.x   | ❌ 不支持 | 不支持Python 2.x版本                                               |

#### 版本选择建议

- **生产环境**: 推荐使用 **Python 3.10+**，性能最佳
- **开发环境**: 推荐使用 **Python 3.9+**，兼容性好
- **最低要求**: **Python 3.7**，需要处理部分兼容性问题

#### 依赖说明

核心功能使用Python标准库，无需额外安装依赖：

```python
# 核心依赖（Python标准库）
- os, sys, re, ast      # 文件和代码分析
- json                   # 配置和报告生成
- datetime               # 时间处理
- typing                 # 类型注解
- dataclasses            # 数据类定义（Python 3.7+）
- enum                   # 枚举类型
- collections            # 集合工具
- pathlib                # 路径处理
```

可选依赖用于增强功能：

```bash
# 安装可选依赖
pip install -r requirements.txt
```


| 依赖包   | 版本要求 | 用途            | 必需 |
| -------- | -------- | --------------- | ---- |
| requests | >=2.25.0 | PoC验证HTTP请求 | 可选 |
| pyyaml   | >=5.4.0  | YAML配置解析    | 可选 |
| pytest   | >=6.0.0  | 单元测试        | 开发 |
| black    | >=21.0   | 代码格式化      | 开发 |
| flake8   | >=3.9.0  | 代码检查        | 开发 |

### 基本用法

```bash
# 审计指定目录
python cli.py /path/to/project

# 指定输出目录
python cli.py /path/to/project -o ./reports

# 指定报告格式
python cli.py /path/to/project -f json html markdown

# 只检测特定漏洞类型
python cli.py /path/to/project --vuln-types sql_injection command_injection

# 使用特定审计模式
python cli.py /path/to/project --mode forward  # 正向审计
python cli.py /path/to/project --mode backward # 反向审计
python cli.py /path/to/project --mode both     # 双向审计（默认）

# 禁用PoC生成
python cli.py /path/to/project --no-poc

# 设置最大调用链深度
python cli.py /path/to/project --max-depth 30
```

### 命令行参数


| 参数                | 说明           | 默认值               |
| ------------------- | -------------- | -------------------- |
| `target`            | 目标代码路径   | 必填                 |
| `-o, --output`      | 输出目录       | `./audit_reports`    |
| `-f, --formats`     | 报告格式       | `json html markdown` |
| `--mode`            | 审计模式       | `both`               |
| `--vuln-types`      | 漏洞类型       | 全部                 |
| `--frameworks`      | 目标框架       | 自动检测             |
| `--max-depth`       | 最大调用链深度 | `20`                 |
| `--no-poc`          | 禁用PoC生成    | `False`              |
| `--no-attack-chain` | 禁用攻击链分析 | `False`              |
| `-v, --verbose`     | 详细输出       | `False`              |

---

## 使用示例

### 示例1: 审计Flask项目

```bash
python cli.py ./my_flask_app -o ./reports
```

### 示例2: 只检测SQL注入和命令注入

```bash
python cli.py ./my_project --vuln-types sql_injection command_injection
```

### 示例3: 生成HTML报告

```bash
python cli.py ./my_project -f html
```

---

## 输出说明

### 报告文件

- `audit_report_YYYYMMDD_HHMMSS.json` - JSON格式报告
- `audit_report_YYYYMMDD_HHMMSS.html` - HTML格式报告
- `audit_report_YYYYMMDD_HHMMSS.md` - Markdown格式报告

### PoC文件

- `pocs/poc_VULN-ID_vuln_type.py` - 漏洞验证代码

### 报告内容

1. **概述**: 审计目标、时间、统计信息
2. **Source点**: 所有识别的HTTP入口点
3. **Sink点**: 所有检测到的危险函数调用
4. **漏洞详情**:
   - 漏洞ID和类型
   - 严重程度
   - Source入口点信息
   - Sink危险点信息
   - 完整调用链
   - 污点传播路径
   - PoC验证代码
   - 修复建议
5. **攻击链**: 多漏洞组合利用分析

---

## 漏洞类型说明


| 漏洞类型          | 说明            | 严重程度 | CWE     |
| ----------------- | --------------- | -------- | ------- |
| sql_injection     | SQL注入         | Critical | CWE-89  |
| command_injection | 命令注入        | Critical | CWE-78  |
| code_injection    | 代码注入        | Critical | CWE-94  |
| deserialization   | 反序列化        | Critical | CWE-502 |
| path_traversal    | 路径遍历        | High     | CWE-22  |
| ssrf              | 服务端请求伪造  | High     | CWE-918 |
| xss               | 跨站脚本        | High     | CWE-79  |
| xxe               | XML外部实体注入 | High     | CWE-611 |
| ldap_injection    | LDAP注入        | High     | CWE-90  |
| open_redirect     | 开放重定向      | Medium   | CWE-601 |

---

## 技术架构

### 审计流程

```
┌─────────────────────────────────────────────────────────────┐
│                     代码安全审计流程                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Source点识别                                            │
│     ├── 扫描源代码文件                                       │
│     ├── 识别HTTP路由装饰器/注解                              │
│     └── 提取入口函数和参数                                   │
│                                                             │
│  2. Sink点检测                                              │
│     ├── 加载危险函数规则库                                   │
│     ├── 匹配危险函数调用                                     │
│     └── 过滤安全模式                                         │
│                                                             │
│  3. 调用图构建                                              │
│     ├── 解析函数定义                                         │
│     ├── 提取函数调用关系                                     │
│     └── 构建调用图                                           │
│                                                             │
│  4. 漏洞分析                                                │
│     ├── 正向审计: Source → Sink                             │
│     ├── 反向审计: Sink → Source                             │
│     └── 构建调用链                                           │
│                                                             │
│  5. PoC生成                                                 │
│     ├── 选择Payload模板                                     │
│     ├── 生成验证代码                                         │
│     └── 生成HTTP请求                                         │
│                                                             │
│  6. 报告生成                                                │
│     ├── JSON格式                                            │
│     ├── HTML格式                                            │
│     └── Markdown格式                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 核心数据结构

```python
# Source点 - HTTP入口
SourcePoint:
  - file_path: 文件路径
  - line_number: 行号
  - function_name: 函数名
  - framework: 框架类型
  - http_method: HTTP方法
  - route: URL路由
  - parameters: 参数列表

# Sink点 - 危险函数
SinkPoint:
  - file_path: 文件路径
  - line_number: 行号
  - function_name: 函数名
  - vuln_type: 漏洞类型
  - dangerous_function: 危险函数
  - arguments: 参数列表

# 调用链
CallChain:
  - source: Source点
  - sink: Sink点
  - nodes: 调用链节点列表
  - is_complete: 是否完整
  - taint_flow: 污点传播路径

# 漏洞
Vulnerability:
  - vuln_id: 漏洞ID
  - vuln_type: 漏洞类型
  - severity: 严重程度
  - source: Source点
  - sink: Sink点
  - call_chain: 调用链
  - poc_code: PoC代码
  - remediation: 修复建议
```

---

## 扩展开发

### 添加新的漏洞规则

在 `rules/sinks/sink_rules.py` 中添加新规则：

```python
SinkRule(
    vuln_type=VulnType.YOUR_VULN_TYPE,
    language=Language.PYTHON,
    function_patterns=[
        r'dangerous_function\s*\(',
    ],
    description="漏洞描述",
    severity="high",
    cwe_id="CWE-XXX",
    remediation="修复建议",
    taint_parameters=[0]
)
```

### 添加新的框架支持

在 `analyzers/source_analyzer.py` 中添加新模式：

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

## 注意事项

1. **误报处理**: 工具可能产生误报，建议人工复核
2. **漏报风险**: 无法检测所有漏洞，建议结合其他工具
3. **安全使用**: PoC代码仅用于授权测试，禁止非法使用
4. **性能考虑**: 大型项目可能需要较长时间分析

---

## 许可证

MIT License

---

## 更新日志

### v1.1.1 (2026-03-19)

#### 新增功能
- ✨ 新增规则模块 `__init__.py` 文件，完善项目结构
- ✨ 支持优先加载 Python 规则文件（`sink_rules.py` 和 `source_patterns.py`）
- ✨ 备用支持 JSON 规则文件加载，提高兼容性

#### 优化改进
- 🔧 优化了核心模块的错误处理机制
  - 添加目标路径验证，防止无效路径导致崩溃
  - 为每个审计步骤添加独立的异常处理
  - 添加详细的错误日志和堆栈跟踪
- 🔧 增强了分析器模块的鲁棒性
  - 添加文件大小检查（最大 10MB），避免内存问题
  - 区分 `PermissionError` 和其他异常类型
  - 添加详细的错误日志输出
- 🔧 改进了规则加载逻辑
  - 优先级：Python 规则 > JSON 规则
  - 修复规则目录路径引用错误
  - 支持动态加载规则模块

#### 修复内容
- 🐛 修复规则目录缺少 `__init__.py` 文件的问题
- 🐛 修复规则加载时路径引用错误（`sources` → `vulnerabilities`）
- 🐛 修复大文件处理可能导致内存溢出的问题
- 🐛 修复权限错误导致分析失败的问题
- 🐛 报告格式问题

#### 技术改进
- ⚡ 优化了 `config.py` 的规则加载逻辑，支持多种规则格式
- ⚡ 优化了 `audit_engine.py` 的错误处理，提升稳定性
- ⚡ 优化了 `source_analyzer.py` 和 `sink_analyzer.py` 的文件处理
- ⚡ 添加了文件大小限制保护机制
- ⚡ 改进了异常处理和日志输出

#### 代码质量提升
- 📝 统一了错误处理模式
- 📝 改进了日志输出格式和详细程度
- 📝 提升了代码可读性和维护性
- 📝 增强了代码鲁棒性和容错能力

---

### v1.0.1 (2026-03-19)

#### 新增功能
- ✨ 新增 JSON 报告模板文件 (`templates/json/report_template.json`)
- ✨ 增强了 JSON 报告生成功能，添加以下内容：
  - 详细的统计信息（扫描时长、文件分析、漏洞指标、Source-Sink分析、匹配率）
  - 优先级排序的修复建议列表
  - OWASP Top 10 合规性检查结果
  - CWE 覆盖情况统计
- ✨ 添加了 `setup.py` 和 `pyproject.toml` 文件，支持 pip 安装

#### 优化改进
- 🔧 完善了 `requirements.txt` 文件，添加详细的依赖分类和注释
- 🔧 在 README 中添加了完整的 Python 版本支持说明
- 🔧 修复了报告模板中漏洞严重程度统计异常的问题
  - HTML 模板添加了低危漏洞统计卡片
  - Markdown 模板修复了变量替换逻辑
  - 确保所有报告格式正确显示 Critical/High/Medium/Low 漏洞数量

#### 修复内容
- 🐛 修复 `poc_generator.py` 中 `import re` 位置错误问题
- 🐛 修复配置加载缺少异常处理的问题
- 🐛 修复单文件分析支持，现在可以分析单个文件
- 🐛 修复装饰器解析问题，正确提取 Flask 路由装饰器参数
- 🐛 修复调用链分析逻辑，添加直接匹配功能
- 🐛 修复漏洞重复报告问题，添加去重逻辑
- 🐛 修复 `_render_markdown_template` 方法缺少 `summary` 变量的错误

#### 技术改进
- ⚡ 优化了 Source 点分析器，支持更精确的装饰器解析
- ⚡ 优化了 Sink 点分析器，支持单文件分析
- ⚡ 优化了调用链分析器，添加直接匹配和去重功能
- ⚡ 优化了审计引擎，添加漏洞去重逻辑
- ⚡ 优化了报告生成器，增强 JSON 报告内容

#### 文档更新
- 📝 完善了 README 文档，添加 Python 版本支持表格
- 📝 添加了详细的依赖说明表格
- 📝 添加了版本选择建议
- 📝 更新了项目结构说明

---

### v1.0.0 (2026-03-18)

#### 初始版本发布

**核心功能**

- ✅ 支持多框架 Source 点识别（Flask、Django、FastAPI、Express、Spring、Gin）
- ✅ 内置完整危险函数规则库
- ✅ 支持 10 种常见漏洞类型检测
- ✅ 实现双向审计模式（正向 + 反向）
- ✅ 支持调用链分析
- ✅ 自动生成 PoC 验证代码
- ✅ 支持多格式报告输出（JSON、HTML、Markdown）
- ✅ 攻击链分析功能

**漏洞类型支持**

- SQL 注入 (CWE-89)
- 命令注入 (CWE-78)
- 路径遍历 (CWE-22)
- 服务端请求伪造 (CWE-918)
- 跨站脚本 (CWE-79)
- 反序列化 (CWE-502)
- 代码注入 (CWE-94)
- LDAP 注入 (CWE-90)
- XML 注入/XXE (CWE-611)
- 开放重定向 (CWE-601)
