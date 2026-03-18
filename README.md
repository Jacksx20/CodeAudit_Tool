# Code Security Audit Tool

## 代码安全审计工具

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
├── cli.py                    # 主入口文件
├── core/                     # 核心模块
│   ├── __init__.py
│   ├── config.py            # 配置和数据结构定义
│   └── audit_engine.py      # 审计引擎
├── analyzers/               # 分析器模块
│   ├── source_analyzer.py   # Source点分析器
│   ├── sink_analyzer.py     # Sink点分析器
│   └── call_chain_analyzer.py # 调用链分析器
├── generators/              # 生成器模块
│   └── poc_generator.py     # PoC生成器
├── reports/                 # 报告模块
│   └── report_generator.py  # 报告生成器
├── rules/                   # 规则库
│   ├── SS/                  # Sink和source规则
│   │   ├── sink_rules.json    # 危险函数规则库
│   │   └── source_rules.json
│   └── sources/             # Source规则
│   	├── sql_injection.json
│   	├── xss.json
│   	├── command_injection.json
│   	├── ssrf.json
│   	├── path_traversal.json
│   	└── deserialization.json
│
└── templates/                 # 报告模板
│     ├── html/
│     │     └── report_template.html
│     └── markdown/
│           └── report_template.md
└── README.md               # 项目说明文档
```

---

## 安装使用

### 环境要求

#### 支持的Python版本

| Python版本 | 支持状态 | 说明 |
|-----------|---------|------|
| Python 3.7 | ✅ 支持 | 最低支持版本，部分类型注解需要 `from __future__ import annotations` |
| Python 3.8 | ✅ 支持 | 推荐版本，完整支持所有功能 |
| Python 3.9 | ✅ 支持 | 完整支持，性能优化 |
| Python 3.10 | ✅ 支持 | 完整支持，支持新的语法特性 |
| Python 3.11 | ✅ 支持 | 完整支持，性能显著提升 |
| Python 3.12+ | ✅ 支持 | 完整支持最新版本 |
| Python 2.x | ❌ 不支持 | 不支持Python 2.x版本 |

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

| 依赖包 | 版本要求 | 用途 | 必需 |
|-------|---------|------|------|
| requests | >=2.25.0 | PoC验证HTTP请求 | 可选 |
| pyyaml | >=5.4.0 | YAML配置解析 | 可选 |
| pytest | >=6.0.0 | 单元测试 | 开发 |
| black | >=21.0 | 代码格式化 | 开发 |
| flake8 | >=3.9.0 | 代码检查 | 开发 |

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

### v1.0.0 (2026-03)

- 初始版本发布
- 支持多框架Source点识别
- 内置完整危险函数规则库
- 实现双向审计模式
- 支持调用链分析
- 自动生成PoC验证代码
- 支持多格式报告输出
