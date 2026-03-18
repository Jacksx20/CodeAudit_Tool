# -*- coding: utf-8 -*-
"""
Sink点分析器 - 检测危险函数调用
支持SQL注入、命令注入、路径遍历、SSRF、XSS、反序列化等漏洞
"""
import os
import re
import ast
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import SinkPoint, VulnerabilityType, Severity, Config


class SinkAnalyzer:
    """Sink点分析器"""
    
    def __init__(self, config: Config):
        self.config = config
        self.sinks: List[SinkPoint] = []
        
        # 危险函数映射
        self.dangerous_functions = self._build_dangerous_functions_map()
        
        # 漏洞类型到严重程度的映射
        self.severity_map = {
            VulnerabilityType.SQL_INJECTION: Severity.CRITICAL,
            VulnerabilityType.COMMAND_INJECTION: Severity.CRITICAL,
            VulnerabilityType.DESERIALIZATION: Severity.CRITICAL,
            VulnerabilityType.CODE_INJECTION: Severity.CRITICAL,
            VulnerabilityType.PATH_TRAVERSAL: Severity.HIGH,
            VulnerabilityType.SSRF: Severity.HIGH,
            VulnerabilityType.XSS: Severity.HIGH,
            VulnerabilityType.LDAP_INJECTION: Severity.HIGH,
            VulnerabilityType.XML_INJECTION: Severity.HIGH,
            VulnerabilityType.OPEN_REDIRECT: Severity.MEDIUM,
        }
    
    def _build_dangerous_functions_map(self) -> Dict[str, List[Dict]]:
        """构建危险函数映射表"""
        functions_map = {}
        
        # SQL注入危险函数
        functions_map['sql_injection'] = [
            {'name': 'execute', 'modules': ['sqlite3', 'pymysql', 'psycopg2', 'mysql.connector'], 
             'pattern': r'execute\s*\([^)]*\+[^)]*\)'},
            {'name': 'executemany', 'modules': ['sqlite3', 'pymysql', 'psycopg2']},
            {'name': 'raw', 'modules': ['django.db.models']},
            {'name': 'extra', 'modules': ['django.db.models']},
            {'name': 'text', 'modules': ['sqlalchemy']},
        ]
        
        # 命令注入危险函数
        functions_map['command_injection'] = [
            {'name': 'system', 'modules': ['os']},
            {'name': 'popen', 'modules': ['os']},
            {'name': 'call', 'modules': ['subprocess'], 'check_shell': True},
            {'name': 'run', 'modules': ['subprocess'], 'check_shell': True},
            {'name': 'Popen', 'modules': ['subprocess'], 'check_shell': True},
            {'name': 'check_output', 'modules': ['subprocess'], 'check_shell': True},
            {'name': 'exec', 'modules': ['builtins']},
            {'name': 'eval', 'modules': ['builtins']},
        ]
        
        # 路径遍历危险函数
        functions_map['path_traversal'] = [
            {'name': 'open', 'modules': ['builtins']},
            {'name': 'read', 'modules': ['builtins']},
            {'name': 'write', 'modules': ['builtins']},
            {'name': 'send_file', 'modules': ['flask']},
            {'name': 'FileResponse', 'modules': ['django.http']},
        ]
        
        # SSRF危险函数
        functions_map['ssrf'] = [
            {'name': 'urlopen', 'modules': ['urllib.request', 'urllib']},
            {'name': 'urlretrieve', 'modules': ['urllib.request', 'urllib']},
            {'name': 'get', 'modules': ['requests']},
            {'name': 'post', 'modules': ['requests']},
            {'name': 'put', 'modules': ['requests']},
            {'name': 'delete', 'modules': ['requests']},
            {'name': 'request', 'modules': ['requests']},
        ]
        
        # XSS危险函数
        functions_map['xss'] = [
            {'name': 'render_template_string', 'modules': ['flask']},
            {'name': 'Markup', 'modules': ['markupsafe']},
            {'name': 'mark_safe', 'modules': ['django.utils.safestring']},
            {'name': 'HttpResponse', 'modules': ['django.http']},
        ]
        
        # 反序列化危险函数
        functions_map['deserialization'] = [
            {'name': 'loads', 'modules': ['pickle']},
            {'name': 'load', 'modules': ['pickle']},
            {'name': 'load', 'modules': ['yaml'], 'check_loader': True},
            {'name': 'unsafe_load', 'modules': ['yaml']},
            {'name': 'loads', 'modules': ['marshal']},
        ]
        
        return functions_map
    
    def analyze(self, target_path: str) -> List[SinkPoint]:
        """分析目标路径，识别所有Sink点"""
        self.sinks = []
        
        # 遍历所有文件
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                if ext in self.config.supported_extensions:
                    self._analyze_file(file_path)
        
        return self.sinks
    
    def _analyze_file(self, file_path: str):
        """分析单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return
        
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext == '.py':
            self._analyze_python_file(file_path, content, lines)
        elif ext in ['.js', '.ts']:
            self._analyze_javascript_file(file_path, content, lines)
        elif ext == '.java':
            self._analyze_java_file(file_path, content, lines)
        elif ext == '.go':
            self._analyze_go_file(file_path, content, lines)
        elif ext == '.php':
            self._analyze_php_file(file_path, content, lines)
    
    def _analyze_python_file(self, file_path: str, content: str, lines: List[str]):
        """分析Python文件"""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            self._analyze_python_with_regex(file_path, content, lines)
            return
        
        # 遍历AST查找危险函数调用
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_python_call(node, file_path, lines)
    
    def _check_python_call(self, node: ast.Call, file_path: str, lines: List[str]):
        """检查Python函数调用是否危险"""
        # 获取函数名
        func_name = self._get_call_name(node)
        if not func_name:
            return
        
        # 检查是否是危险函数
        for vuln_type, functions in self.dangerous_functions.items():
            for func_info in functions:
                if func_info['name'] == func_name or func_info['name'] in func_name:
                    # 检查是否真的危险(例如检查shell=True)
                    if self._is_dangerous_call(node, func_info, lines):
                        sink = self._create_sink_point(
                            node, file_path, lines, func_name, 
                            vuln_type, func_info
                        )
                        if sink:
                            self.sinks.append(sink)
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """获取函数调用的名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # 处理 module.function 形式
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return None
    
    def _is_dangerous_call(self, node: ast.Call, func_info: Dict, lines: List[str]) -> bool:
        """检查函数调用是否真的危险"""
        # 检查shell参数
        if func_info.get('check_shell'):
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value:
                        return True
                    elif isinstance(keyword.value, ast.NameConstant) and keyword.value.value:
                        return True
            return False
        
        # 检查yaml loader
        if func_info.get('check_loader'):
            for keyword in node.keywords:
                if keyword.arg == 'Loader':
                    # 检查是否是安全的Loader
                    loader_name = self._get_loader_name(keyword.value)
                    if loader_name in ['Loader', 'FullLoader', 'UnsafeLoader']:
                        return True
            return False
        
        # 检查参数是否包含用户输入或字符串拼接
        return self._has_user_input_or_concat(node)
    
    def _get_loader_name(self, node) -> Optional[str]:
        """获取YAML Loader名称"""
        if isinstance(node, ast.Attribute):
            return node.attr
        elif isinstance(node, ast.Name):
            return node.id
        return None
    
    def _has_user_input_or_concat(self, node: ast.Call) -> bool:
        """检查函数调用参数是否包含用户输入或字符串拼接"""
        # 检查位置参数
        for arg in node.args:
            if self._is_user_input(arg) or self._is_string_concat(arg):
                return True
        
        # 检查关键字参数
        for keyword in node.keywords:
            if keyword.arg in ['query', 'sql', 'command', 'cmd', 'url', 'path', 'filename', 'data']:
                if self._is_user_input(keyword.value) or self._is_string_concat(keyword.value):
                    return True
        
        return False
    
    def _is_user_input(self, node) -> bool:
        """检查节点是否是用户输入"""
        user_input_patterns = [
            'request.args', 'request.form', 'request.json', 'request.data',
            'request.GET', 'request.POST', 'request.body',
            'req.query', 'req.body', 'req.params',
            '$_GET', '$_POST', '$_REQUEST',
        ]
        
        node_str = self._node_to_string(node)
        for pattern in user_input_patterns:
            if pattern in node_str:
                return True
        
        return False
    
    def _is_string_concat(self, node) -> bool:
        """检查节点是否是字符串拼接"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        if isinstance(node, ast.JoinedStr):  # f-string
            return True
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name in ['format', 'join']:
                return True
        return False
    
    def _node_to_string(self, node) -> str:
        """将AST节点转换为字符串"""
        try:
            return ast.unparse(node)
        except:
            return ""
    
    def _create_sink_point(self, node: ast.Call, file_path: str, lines: List[str],
                          func_name: str, vuln_type: str, func_info: Dict) -> Optional[SinkPoint]:
        """创建Sink点"""
        try:
            vuln_enum = VulnerabilityType(vuln_type)
        except ValueError:
            return None
        
        line_num = node.lineno
        start_line = max(0, line_num - 1)
        end_line = min(len(lines), line_num + 5)
        code_snippet = '\n'.join(lines[start_line:end_line])
        
        # 获取参数
        arguments = []
        for arg in node.args:
            arg_str = self._node_to_string(arg)
            if arg_str:
                arguments.append(arg_str)
        
        # 获取修复建议
        remediation = self._get_remediation(vuln_enum)
        
        return SinkPoint(
            file_path=file_path,
            line_number=line_num,
            function_name=func_name,
            vulnerability_type=vuln_enum,
            severity=self.severity_map.get(vuln_enum, Severity.MEDIUM),
            code_snippet=code_snippet,
            arguments=arguments,
            description=f"检测到危险函数调用: {func_name}",
            remediation=remediation
        )
    
    def _get_remediation(self, vuln_type: VulnerabilityType) -> str:
        """获取修复建议"""
        remediations = {
            VulnerabilityType.SQL_INJECTION: "使用参数化查询，避免字符串拼接SQL语句",
            VulnerabilityType.COMMAND_INJECTION: "避免使用shell=True，使用列表形式传递命令参数",
            VulnerabilityType.PATH_TRAVERSAL: "验证并规范化文件路径，使用白名单限制可访问文件",
            VulnerabilityType.SSRF: "验证URL，使用白名单限制允许访问的域名",
            VulnerabilityType.XSS: "对用户输入进行HTML转义，使用模板引擎的自动转义功能",
            VulnerabilityType.DESERIALIZATION: "避免反序列化不可信数据，使用JSON等安全格式",
            VulnerabilityType.CODE_INJECTION: "避免动态执行用户代码",
        }
        return remediations.get(vuln_type, "验证并过滤用户输入")
    
    def _analyze_python_with_regex(self, file_path: str, content: str, lines: List[str]):
        """使用正则表达式分析Python文件"""
        # SQL注入模式
        sql_patterns = [
            r'execute\s*\([^)]*\+[^)]*\)',
            r'execute\s*\([^)]*%[^)]*%[^)]*\)',
            r'cursor\.execute\s*\([^)]*\+[^)]*\)',
            r'\.raw\s*\([^)]*\+[^)]*\)',
        ]
        
        for pattern in sql_patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, 'sql_injection', 'execute')
        
        # 命令注入模式
        cmd_patterns = [
            r'os\.system\s*\([^)]*\+[^)]*\)',
            r'os\.popen\s*\([^)]*\+[^)]*\)',
            r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True[^)]*\)',
            r'eval\s*\([^)]*\)',
            r'exec\s*\([^)]*\)',
        ]
        
        for pattern in cmd_patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, 'command_injection', 'system')
        
        # 路径遍历模式
        path_patterns = [
            r'open\s*\([^)]*\+[^)]*\)',
            r'send_file\s*\([^)]*\+[^)]*\)',
        ]
        
        for pattern in path_patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, 'path_traversal', 'open')
        
        # SSRF模式
        ssrf_patterns = [
            r'urllib\.request\.urlopen\s*\([^)]*\+[^)]*\)',
            r'requests\.\w+\s*\([^)]*\+[^)]*\)',
        ]
        
        for pattern in ssrf_patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, 'ssrf', 'urlopen')
        
        # 反序列化模式
        deserial_patterns = [
            r'pickle\.loads\s*\([^)]*\)',
            r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader[^)]*\)',
            r'yaml\.unsafe_load\s*\([^)]*\)',
        ]
        
        for pattern in deserial_patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, 'deserialization', 'loads')
    
    def _add_sink_from_match(self, match, file_path: str, lines: List[str], 
                            vuln_type: str, func_name: str):
        """从正则匹配创建Sink点"""
        try:
            vuln_enum = VulnerabilityType(vuln_type)
        except ValueError:
            return
        
        line_num = match.string[:match.start()].count('\n') + 1
        start_line = max(0, line_num - 1)
        end_line = min(len(lines), line_num + 3)
        code_snippet = '\n'.join(lines[start_line:end_line])
        
        sink = SinkPoint(
            file_path=file_path,
            line_number=line_num,
            function_name=func_name,
            vulnerability_type=vuln_enum,
            severity=self.severity_map.get(vuln_enum, Severity.MEDIUM),
            code_snippet=code_snippet,
            description=f"检测到危险函数调用: {func_name}",
            remediation=self._get_remediation(vuln_enum)
        )
        
        self.sinks.append(sink)
    
    def _analyze_javascript_file(self, file_path: str, content: str, lines: List[str]):
        """分析JavaScript文件"""
        # 命令注入
        patterns = [
            (r'exec\s*\([^)]*\+[^)]*\)', 'command_injection', 'exec'),
            (r'eval\s*\([^)]*\)', 'command_injection', 'eval'),
            (r'child_process\.exec\s*\([^)]*\+[^)]*\)', 'command_injection', 'exec'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # 路径遍历
        patterns = [
            (r'fs\.readFile\s*\([^)]*\+[^)]*\)', 'path_traversal', 'readFile'),
            (r'fs\.writeFile\s*\([^)]*\+[^)]*\)', 'path_traversal', 'writeFile'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # SSRF
        patterns = [
            (r'fetch\s*\([^)]*\+[^)]*\)', 'ssrf', 'fetch'),
            (r'axios\.\w+\s*\([^)]*\+[^)]*\)', 'ssrf', 'axios'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
    
    def _analyze_java_file(self, file_path: str, content: str, lines: List[str]):
        """分析Java文件"""
        # SQL注入
        patterns = [
            (r'executeQuery\s*\([^)]*\+[^)]*\)', 'sql_injection', 'executeQuery'),
            (r'executeUpdate\s*\([^)]*\+[^)]*\)', 'sql_injection', 'executeUpdate'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # 命令注入
        patterns = [
            (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+[^)]*\)', 'command_injection', 'exec'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # 反序列化
        patterns = [
            (r'ObjectInputStream.*readObject\s*\(\)', 'deserialization', 'readObject'),
            (r'XMLDecoder.*readObject\s*\(\)', 'deserialization', 'readObject'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
    
    def _analyze_go_file(self, file_path: str, content: str, lines: List[str]):
        """分析Go文件"""
        # 命令注入
        patterns = [
            (r'exec\.Command\s*\([^)]*\+[^)]*\)', 'command_injection', 'Command'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # SQL注入
        patterns = [
            (r'\.Query\s*\([^)]*\+[^)]*\)', 'sql_injection', 'Query'),
            (r'\.Exec\s*\([^)]*\+[^)]*\)', 'sql_injection', 'Exec'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
    
    def _analyze_php_file(self, file_path: str, content: str, lines: List[str]):
        """分析PHP文件"""
        # 命令注入
        patterns = [
            (r'exec\s*\([^)]*\.\s*\$_', 'command_injection', 'exec'),
            (r'system\s*\([^)]*\.\s*\$_', 'command_injection', 'system'),
            (r'passthru\s*\([^)]*\.\s*\$_', 'command_injection', 'passthru'),
            (r'shell_exec\s*\([^)]*\.\s*\$_', 'command_injection', 'shell_exec'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # SQL注入
        patterns = [
            (r'mysql_query\s*\([^)]*\.\s*\$_', 'sql_injection', 'mysql_query'),
            (r'mysqli_query\s*\([^)]*\.\s*\$_', 'sql_injection', 'mysqli_query'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
        
        # 反序列化
        patterns = [
            (r'unserialize\s*\([^)]*\$_', 'deserialization', 'unserialize'),
        ]
        
        for pattern, vuln_type, func_name in patterns:
            for match in re.finditer(pattern, content):
                self._add_sink_from_match(match, file_path, lines, vuln_type, func_name)
    
    def get_sinks_by_type(self, vuln_type: VulnerabilityType) -> List[SinkPoint]:
        """按漏洞类型获取Sink点"""
        return [s for s in self.sinks if s.vulnerability_type == vuln_type]
    
    def get_sinks_by_file(self, file_path: str) -> List[SinkPoint]:
        """按文件获取Sink点"""
        return [s for s in self.sinks if s.file_path == file_path]
