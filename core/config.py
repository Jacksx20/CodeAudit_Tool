# -*- coding: utf-8 -*-
"""
配置和数据结构定义
"""
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    CODE_INJECTION = "code_injection"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    OPEN_REDIRECT = "open_redirect"


class Severity(Enum):
    """漏洞严重程度"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Framework(Enum):
    """支持的框架类型"""
    FLASK = "flask"
    DJANGO = "django"
    FASTAPI = "fastapi"
    EXPRESS = "express"
    SPRING = "spring"
    GIN = "gin"
    LARAVEL = "laravel"
    SYMFONY = "symfony"
    ASPNET = "aspnet"
    GENERIC = "generic"


@dataclass
class SourcePoint:
    """Source点 - HTTP入口点"""
    file_path: str                          # 文件路径
    line_number: int                        # 行号
    function_name: str                      # 函数名
    framework: Framework                    # 框架类型
    route: str                              # 路由路径
    http_method: str                        # HTTP方法 (GET, POST, etc.)
    parameters: List[str] = field(default_factory=list)  # 参数列表
    code_snippet: str = ""                  # 代码片段
    decorators: List[str] = field(default_factory=list)  # 装饰器列表
    class_name: Optional[str] = None        # 类名(如果有)
    
    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'line_number': self.line_number,
            'function_name': self.function_name,
            'framework': self.framework.value,
            'route': self.route,
            'http_method': self.http_method,
            'parameters': self.parameters,
            'code_snippet': self.code_snippet,
            'decorators': self.decorators,
            'class_name': self.class_name
        }


@dataclass
class SinkPoint:
    """Sink点 - 危险函数调用"""
    file_path: str                          # 文件路径
    line_number: int                        # 行号
    function_name: str                      # 危险函数名
    vulnerability_type: VulnerabilityType   # 漏洞类型
    severity: Severity                      # 严重程度
    code_snippet: str = ""                  # 代码片段
    arguments: List[str] = field(default_factory=list)  # 参数列表
    description: str = ""                   # 描述
    remediation: str = ""                   # 修复建议
    class_name: Optional[str] = None        # 类名(如果有)
    
    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'line_number': self.line_number,
            'function_name': self.function_name,
            'vulnerability_type': self.vulnerability_type.value,
            'severity': self.severity.value,
            'code_snippet': self.code_snippet,
            'arguments': self.arguments,
            'description': self.description,
            'remediation': self.remediation,
            'class_name': self.class_name
        }


@dataclass
class CallChainNode:
    """调用链节点"""
    file_path: str
    line_number: int
    function_name: str
    code_snippet: str = ""
    class_name: Optional[str] = None
    call_type: str = "direct"  # direct, conditional, callback
    
    def to_dict(self) -> Dict:
        return {
            'file_path': self.file_path,
            'line_number': self.line_number,
            'function_name': self.function_name,
            'code_snippet': self.code_snippet,
            'class_name': self.class_name,
            'call_type': self.call_type
        }


@dataclass
class CallChain:
    """调用链 - 从source到sink的完整路径"""
    source: SourcePoint                     # 起点
    sink: SinkPoint                         # 终点
    nodes: List[CallChainNode] = field(default_factory=list)  # 中间节点
    is_complete: bool = False               # 是否完整可达
    data_flow: List[str] = field(default_factory=list)  # 数据流描述
    
    def to_dict(self) -> Dict:
        return {
            'source': self.source.to_dict(),
            'sink': self.sink.to_dict(),
            'nodes': [node.to_dict() for node in self.nodes],
            'is_complete': self.is_complete,
            'data_flow': self.data_flow
        }


@dataclass
class PoC:
    """漏洞验证PoC"""
    vulnerability_type: VulnerabilityType
    http_method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    payload: str = ""                       # 恶意payload
    expected_result: str = ""               # 预期结果
    curl_command: str = ""                  # curl命令
    python_code: str = ""                   # Python验证代码
    
    def to_dict(self) -> Dict:
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'http_method': self.http_method,
            'url': self.url,
            'headers': self.headers,
            'params': self.params,
            'data': self.data,
            'payload': self.payload,
            'expected_result': self.expected_result,
            'curl_command': self.curl_command,
            'python_code': self.python_code
        }


@dataclass
class Vulnerability:
    """漏洞信息"""
    id: str                                 # 漏洞唯一ID
    name: str                               # 漏洞名称
    vulnerability_type: VulnerabilityType   # 漏洞类型
    severity: Severity                      # 严重程度
    source: SourcePoint                     # Source点
    sink: SinkPoint                         # Sink点
    call_chain: CallChain                   # 调用链
    poc: Optional[PoC] = None               # PoC
    description: str = ""                   # 描述
    remediation: str = ""                   # 修复建议
    references: List[str] = field(default_factory=list)  # 参考链接
    cwe_id: str = ""                        # CWE编号
    cvss_score: float = 0.0                 # CVSS评分
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'vulnerability_type': self.vulnerability_type.value,
            'severity': self.severity.value,
            'source': self.source.to_dict(),
            'sink': self.sink.to_dict(),
            'call_chain': self.call_chain.to_dict(),
            'poc': self.poc.to_dict() if self.poc else None,
            'description': self.description,
            'remediation': self.remediation,
            'references': self.references,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score
        }


@dataclass
class AttackChain:
    """攻击链 - 多个漏洞的组合利用"""
    vulnerabilities: List[Vulnerability]     # 相关漏洞列表
    description: str                        # 攻击链描述
    impact: str                             # 影响
    steps: List[str] = field(default_factory=list)  # 攻击步骤
    
    def to_dict(self) -> Dict:
        return {
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'description': self.description,
            'impact': self.impact,
            'steps': self.steps
        }


@dataclass
class AuditResult:
    """审计结果"""
    target_path: str                        # 审计目标路径
    total_files: int = 0                    # 总文件数
    scanned_files: int = 0                  # 已扫描文件数
    sources_found: int = 0                  # 发现的source点数
    sinks_found: int = 0                    # 发现的sink点数
    vulnerabilities: List[Vulnerability] = field(default_factory=list)  # 漏洞列表
    attack_chains: List[AttackChain] = field(default_factory=list)  # 攻击链列表
    scan_time: float = 0.0                  # 扫描耗时
    framework: Framework = Framework.GENERIC  # 检测到的框架
    
    def to_dict(self) -> Dict:
        return {
            'target_path': self.target_path,
            'total_files': self.total_files,
            'scanned_files': self.scanned_files,
            'sources_found': self.sources_found,
            'sinks_found': self.sinks_found,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'attack_chains': [ac.to_dict() for ac in self.attack_chains],
            'scan_time': self.scan_time,
            'framework': self.framework.value
        }
    
    def get_summary(self) -> Dict:
        """获取漏洞统计摘要"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'by_type': {}
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value
            summary[severity] = summary.get(severity, 0) + 1
            
            vuln_type = vuln.vulnerability_type.value
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
        
        return summary


class Config:
    """配置类"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.rules_dir = os.path.join(os.path.dirname(__file__), '..', 'rules')
        self.templates_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
        
        # 默认配置
        self.max_call_depth = 20              # 最大调用深度
        self.max_file_size = 10 * 1024 * 1024 # 最大文件大小 (10MB)
        self.supported_extensions = [
            '.py', '.js', '.ts', '.java', '.go', '.php', '.rb', '.jsp', '.asp', '.aspx', '.cs', '.cshtml'
        ]
        self.exclude_dirs = [
            'node_modules', 'venv', '.git', '__pycache__', 'vendor', 'dist', 'build'
        ]
        
        # 加载自定义配置
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
        
        # 加载规则
        self.sink_rules = self._load_sink_rules()
        self.source_rules = self._load_source_rules()
    
    def _load_config(self, config_path: str):
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
        except Exception as e:
            print(f"加载配置文件失败: {e}")
    
    def _load_sink_rules(self) -> Dict:
        """加载Sink规则"""
        rules = {}
        
        # 优先加载Python规则文件
        sink_rules_path = os.path.join(self.rules_dir, 'sinks', 'sink_rules.py')
        if os.path.exists(sink_rules_path):
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("sink_rules", sink_rules_path)
                if spec and spec.loader:
                    sink_rules_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(sink_rules_module)
                    if hasattr(sink_rules_module, 'SINK_RULES'):
                        rules.update(sink_rules_module.SINK_RULES)
            except Exception as e:
                print(f"加载Python sink规则失败: {e}")
        
        # 备用：加载JSON规则文件
        sink_rules_json_path = os.path.join(self.rules_dir, 'SS', 'sink_rules.json')
        if os.path.exists(sink_rules_json_path) and not rules:
            try:
                with open(sink_rules_json_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            except Exception as e:
                print(f"加载JSON sink规则失败: {e}")
        
        # 加载各漏洞类型的详细规则
        vulnerabilities_dir = os.path.join(self.rules_dir, 'vulnerabilities')
        if os.path.exists(vulnerabilities_dir):
            for filename in os.listdir(vulnerabilities_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(vulnerabilities_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            vuln_rules = json.load(f)
                            rules.update(vuln_rules)
                    except Exception as e:
                        print(f"加载规则文件 {filename} 失败: {e}")
        
        return rules
    
    def _load_source_rules(self) -> Dict:
        """加载Source规则"""
        rules = {}
        
        # 优先加载Python规则文件
        source_rules_path = os.path.join(self.rules_dir, 'sources', 'source_patterns.py')
        if os.path.exists(source_rules_path):
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("source_rules", source_rules_path)
                if spec and spec.loader:
                    source_rules_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(source_rules_module)
                    if hasattr(source_rules_module, 'SOURCE_PATTERNS'):
                        rules.update(source_rules_module.SOURCE_PATTERNS)
            except Exception as e:
                print(f"加载Python source规则失败: {e}")
        
        # 备用：加载JSON规则文件
        source_rules_json_path = os.path.join(self.rules_dir, 'SS', 'source_rules.json')
        if os.path.exists(source_rules_json_path) and not rules:
            try:
                with open(source_rules_json_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            except Exception as e:
                print(f"加载JSON source规则失败: {e}")
        
        return rules
    
    def get_sink_functions(self, vuln_type: Optional[str] = None) -> List[Dict]:
        """获取危险函数列表"""
        if vuln_type:
            return self.sink_rules.get(vuln_type, {}).get('sinks', [])
        
        all_sinks = []
        for vuln_data in self.sink_rules.values():
            if isinstance(vuln_data, dict) and 'sinks' in vuln_data:
                all_sinks.extend(vuln_data['sinks'])
        return all_sinks
    
    def get_source_patterns(self, framework: Optional[str] = None) -> List[Dict]:
        """获取Source模式列表"""
        if framework:
            return self.source_rules.get(framework, [])
        
        all_patterns = []
        for patterns in self.source_rules.values():
            all_patterns.extend(patterns)
        return all_patterns
