# -*- coding: utf-8 -*-
"""
调用链分析器 - 构建完整的source→sink调用链
支持正向审计和反向审计
增强功能：变量追踪、数据流分析、污点传播
"""
import os
import re
import ast
from typing import List, Dict, Optional, Set, Tuple, Any
from collections import defaultdict
from pathlib import Path
from dataclasses import dataclass, field

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import (
    SourcePoint, SinkPoint, CallChain, CallChainNode, 
    Vulnerability, VulnerabilityType, Severity, Config
)


@dataclass
class VariableInfo:
    """变量信息"""
    name: str                           # 变量名
    source: str                         # 来源：'user_input', 'literal', 'param', 'unknown'
    taint_sources: List[str] = field(default_factory=list)  # 污点来源
    is_tainted: bool = False            # 是否被污染
    line_number: int = 0                # 定义行号
    value_type: str = 'unknown'         # 值类型


@dataclass
class DataFlowNode:
    """数据流节点"""
    var_name: str                       # 变量名
    operation: str                      # 操作类型：'assign', 'call', 'return', 'param'
    source_line: int                    # 源行号
    source_var: Optional[str] = None    # 源变量
    target_var: Optional[str] = None    # 目标变量
    is_tainted: bool = False            # 是否污染
    taint_propagated: bool = False      # 污点是否已传播


class CallChainAnalyzer:
    """调用链分析器 - 增强版"""
    
    def __init__(self, config: Config):
        self.config = config
        self.call_graph: Dict[str, List[str]] = defaultdict(list)  # 函数调用图
        self.function_definitions: Dict[str, Tuple[str, int, List[str]]] = {}  # 函数定义信息
        self.reverse_call_graph: Dict[str, List[str]] = defaultdict(list)  # 反向调用图
        
        # 新增：变量追踪相关
        self.variable_states: Dict[str, Dict[str, VariableInfo]] = {}  # 文件 -> {变量名 -> 变量信息}
        self.data_flows: Dict[str, List[DataFlowNode]] = {}  # 函数键 -> 数据流节点列表
        self.tainted_variables: Dict[str, Set[str]] = defaultdict(set)  # 函数键 -> 污染变量集合
        
        # 用户输入模式
        self.user_input_patterns = [
            'request.args', 'request.form', 'request.json', 'request.data',
            'request.GET', 'request.POST', 'request.body', 'request.values',
            'req.query', 'req.body', 'req.params',
            '$_GET', '$_POST', '$_REQUEST', '$_FILES',
            'c.Query', 'c.PostForm', 'c.Param',
            'input()', 'sys.argv', 'os.environ',
        ]
        
        # 净化函数模式
        self.sanitization_functions = {
            'escape', 'htmlspecialchars', 'htmlentities', 'strip_tags',
            'mysqli_real_escape_string', 'mysql_real_escape_string',
            'pg_escape_string', 'sqlite_escape_string',
            'filter_input', 'filter_var', 'sanitize', 'clean',
            'escape_string', 'quote', 'prepare',
            'mark_safe', 'safe', 'escape_js', 'escape_html',
            'urllib.parse.quote', 'urllib.quote', 'url_encode',
            're.escape', 'shlex.quote', 'pipes.quote',
        }
        
    def analyze(self, target_path: str, sources: List[SourcePoint], 
                sinks: List[SinkPoint]) -> List[Vulnerability]:
        """
        分析调用链，找出source到sink的完整路径
        
        Args:
            target_path: 目标路径
            sources: Source点列表
            sinks: Sink点列表
            
        Returns:
            漏洞列表
        """
        # 构建调用图
        self._build_call_graph(target_path)
        
        # 构建反向调用图
        self._build_reverse_call_graph()
        
        vulnerabilities = []
        vuln_id = 1
        
        # 对每个sink点，尝试找到可达的source
        for sink in sinks:
            # 反向审计：从sink往回找source
            call_chains = self._find_paths_to_source(sink, sources)
            
            for chain in call_chains:
                if chain.is_complete:
                    vuln = Vulnerability(
                        id=f"VULN-{vuln_id:04d}",
                        name=f"{sink.vulnerability_type.value} in {chain.source.function_name}",
                        vulnerability_type=sink.vulnerability_type,
                        severity=sink.severity,
                        source=chain.source,
                        sink=sink,
                        call_chain=chain,
                        description=self._generate_description(chain, sink),
                        remediation=sink.remediation,
                        cwe_id=self._get_cwe_id(sink.vulnerability_type)
                    )
                    vulnerabilities.append(vuln)
                    vuln_id += 1
        
        # 如果没有找到完整调用链，尝试直接匹配source和sink
        if not vulnerabilities:
            for sink in sinks:
                # 找到sink所在的函数
                sink_func = self._find_containing_function(sink.file_path, sink.line_number)
                
                # 查找匹配的source
                for source in sources:
                    source_func_key = f"{source.file_path}:{source.function_name}"
                    
                    # 检查sink是否在source函数内
                    if sink_func and sink_func == source_func_key:
                        # 创建直接调用链
                        chain = self._create_direct_chain(source, sink)
                        
                        vuln = Vulnerability(
                            id=f"VULN-{vuln_id:04d}",
                            name=f"{sink.vulnerability_type.value} in {source.function_name}",
                            vulnerability_type=sink.vulnerability_type,
                            severity=sink.severity,
                            source=source,
                            sink=sink,
                            call_chain=chain,
                            description=f"在函数 {source.function_name} 中检测到 {sink.vulnerability_type.value}",
                            remediation=sink.remediation,
                            cwe_id=self._get_cwe_id(sink.vulnerability_type)
                        )
                        vulnerabilities.append(vuln)
                        vuln_id += 1
                        break
        
        return vulnerabilities
    
    def _create_direct_chain(self, source: SourcePoint, sink: SinkPoint) -> CallChain:
        """创建直接调用链"""
        node = CallChainNode(
            file_path=source.file_path,
            line_number=source.line_number,
            function_name=source.function_name,
            code_snippet=source.code_snippet,
            call_type="direct"
        )
        
        return CallChain(
            source=source,
            sink=sink,
            nodes=[node],
            is_complete=True,
            data_flow=[f"{source.function_name}() -> {sink.function_name}()"]
        )
    
    def _build_call_graph(self, target_path: str):
        """构建函数调用图"""
        self.call_graph.clear()
        self.function_definitions.clear()
        
        # 检查是文件还是目录
        if os.path.isfile(target_path):
            ext = os.path.splitext(target_path)[1].lower()
            if ext == '.py':
                self._build_python_call_graph(target_path)
            elif ext in ['.js', '.ts']:
                self._build_js_call_graph(target_path)
            elif ext == '.java':
                self._build_java_call_graph(target_path)
            elif ext == '.go':
                self._build_go_call_graph(target_path)
            elif ext == '.php':
                self._build_php_call_graph(target_path)
            elif ext == '.cs':
                self._build_cs_call_graph(target_path)
        else:
            # 遍历所有文件
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()
                    
                    if ext == '.py':
                        self._build_python_call_graph(file_path)
                    elif ext in ['.js', '.ts']:
                        self._build_js_call_graph(file_path)
                    elif ext == '.java':
                        self._build_java_call_graph(file_path)
                    elif ext == '.go':
                        self._build_go_call_graph(file_path)
                    elif ext == '.php':
                        self._build_php_call_graph(file_path)
                    elif ext == '.cs':
                        self._build_cs_call_graph(file_path)
    
    def _build_python_call_graph(self, file_path: str):
        """构建Python文件的调用图 - 增强版，包含变量追踪"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return
        
        # 初始化文件的变量状态
        if file_path not in self.variable_states:
            self.variable_states[file_path] = {}
        
        # 收集函数定义
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                func_key = f"{file_path}:{node.name}"
                
                # 获取函数参数
                params = [arg.arg for arg in node.args.args]
                
                self.function_definitions[func_key] = (file_path, node.lineno, params)
                
                # 收集函数内的调用
                calls = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        call_name = self._get_call_name(child)
                        if call_name:
                            calls.append(call_name)
                
                self.call_graph[func_key] = calls
                
                # 新增：分析函数内的变量追踪和数据流
                self._analyze_function_variables(node, func_key, file_path, lines)
        
        # 构建跨文件的调用关系
        self._resolve_cross_file_calls(file_path, content)
    
    def _analyze_function_variables(self, func_node, func_key: str, file_path: str, lines: List[str]):
        """分析函数内的变量追踪和数据流"""
        data_flow_nodes = []
        local_vars = {}
        
        # 处理函数参数 - 参数可能是污染源
        for arg in func_node.args.args:
            var_info = VariableInfo(
                name=arg.arg,
                source='param',
                is_tainted=True,  # 参数默认视为可能被污染
                taint_sources=[f'param:{arg.arg}'],
                line_number=func_node.lineno,
                value_type='unknown'
            )
            local_vars[arg.arg] = var_info
            self.tainted_variables[func_key].add(arg.arg)
        
        # 遍历函数体，追踪变量赋值和数据流
        for stmt in ast.walk(func_node):
            # 处理赋值语句
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        var_info = self._analyze_assignment(stmt.value, var_name, stmt.lineno, local_vars, func_key)
                        local_vars[var_name] = var_info
                        
                        # 记录数据流
                        df_node = DataFlowNode(
                            var_name=var_name,
                            operation='assign',
                            source_line=stmt.lineno,
                            is_tainted=var_info.is_tainted
                        )
                        data_flow_nodes.append(df_node)
            
            # 处理增强赋值 (+=, -= 等)
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name):
                    var_name = stmt.target.id
                    # 增强赋值保持原有污点状态
                    if var_name in local_vars and local_vars[var_name].is_tainted:
                        self.tainted_variables[func_key].add(var_name)
            
            # 处理函数调用中的变量传递
            elif isinstance(stmt, ast.Call):
                self._analyze_call_arguments(stmt, func_key, local_vars, stmt.lineno, data_flow_nodes)
        
        # 保存数据流信息
        self.data_flows[func_key] = data_flow_nodes
        
        # 更新文件的变量状态
        self.variable_states[file_path].update(local_vars)
    
    def _analyze_assignment(self, value_node, var_name: str, line_num: int, 
                           local_vars: Dict, func_key: str) -> VariableInfo:
        """分析赋值语句右侧表达式"""
        is_tainted = False
        taint_sources = []
        source = 'unknown'
        value_type = 'unknown'
        
        # 检查是否是用户输入
        if self._is_user_input_node(value_node):
            is_tainted = True
            taint_sources.append('user_input')
            source = 'user_input'
        
        # 检查是否是字面量
        elif isinstance(value_node, (ast.Constant, ast.Str, ast.Num)):
            source = 'literal'
            is_tainted = False
            value_type = type(value_node.value).__name__ if hasattr(value_node, 'value') else 'str'
        
        # 检查是否是变量引用
        elif isinstance(value_node, ast.Name):
            ref_var = value_node.id
            if ref_var in local_vars:
                is_tainted = local_vars[ref_var].is_tainted
                taint_sources = local_vars[ref_var].taint_sources.copy()
                source = local_vars[ref_var].source
            elif ref_var in self.tainted_variables[func_key]:
                is_tainted = True
                taint_sources.append(f'var:{ref_var}')
        
        # 检查是否是属性访问 (如 request.args.get())
        elif isinstance(value_node, ast.Attribute):
            attr_str = self._node_to_string(value_node)
            if self._is_user_input_pattern(attr_str):
                is_tainted = True
                taint_sources.append(f'user_input:{attr_str}')
                source = 'user_input'
        
        # 检查是否是函数调用
        elif isinstance(value_node, ast.Call):
            call_name = self._get_call_name(value_node)
            if call_name:
                # 检查是否是净化函数
                if self._is_sanitization_function(call_name):
                    is_tainted = False  # 净化后不再污染
                    source = 'sanitized'
                else:
                    # 检查参数是否被污染
                    for arg in value_node.args:
                        if isinstance(arg, ast.Name) and arg.id in local_vars:
                            if local_vars[arg.id].is_tainted:
                                is_tainted = True
                                taint_sources.extend(local_vars[arg.id].taint_sources)
                                break
        
        # 检查是否是二元操作 (字符串拼接等)
        elif isinstance(value_node, ast.BinOp):
            # 检查操作数是否被污染
            for operand in [value_node.left, value_node.right]:
                if isinstance(operand, ast.Name) and operand.id in local_vars:
                    if local_vars[operand.id].is_tainted:
                        is_tainted = True
                        taint_sources.extend(local_vars[operand.id].taint_sources)
                elif isinstance(operand, ast.Attribute):
                    attr_str = self._node_to_string(operand)
                    if self._is_user_input_pattern(attr_str):
                        is_tainted = True
                        taint_sources.append(f'user_input:{attr_str}')
        
        # 检查是否是f-string
        elif isinstance(value_node, ast.JoinedStr):
            for value in value_node.values:
                if isinstance(value, ast.FormattedValue):
                    if isinstance(value.value, ast.Name) and value.value.id in local_vars:
                        if local_vars[value.value.id].is_tainted:
                            is_tainted = True
                            taint_sources.extend(local_vars[value.value.id].taint_sources)
        
        # 如果被污染，添加到污染变量集合
        if is_tainted:
            self.tainted_variables[func_key].add(var_name)
        
        return VariableInfo(
            name=var_name,
            source=source,
            taint_sources=taint_sources,
            is_tainted=is_tainted,
            line_number=line_num,
            value_type=value_type
        )
    
    def _analyze_call_arguments(self, call_node: ast.Call, func_key: str, 
                               local_vars: Dict, line_num: int, data_flow_nodes: List):
        """分析函数调用中的参数传递"""
        call_name = self._get_call_name(call_node)
        if not call_name:
            return
        
        # 检查每个参数
        for i, arg in enumerate(call_node.args):
            if isinstance(arg, ast.Name):
                var_name = arg.id
                if var_name in local_vars and local_vars[var_name].is_tainted:
                    # 记录污染数据流
                    df_node = DataFlowNode(
                        var_name=var_name,
                        operation='call_arg',
                        source_line=line_num,
                        target_var=f'{call_name}:arg{i}',
                        is_tainted=True
                    )
                    data_flow_nodes.append(df_node)
    
    def _is_user_input_node(self, node) -> bool:
        """检查节点是否是用户输入"""
        node_str = self._node_to_string(node)
        return self._is_user_input_pattern(node_str)
    
    def _is_user_input_pattern(self, text: str) -> bool:
        """检查文本是否匹配用户输入模式"""
        for pattern in self.user_input_patterns:
            if pattern in text:
                return True
        return False
    
    def _is_sanitization_function(self, func_name: str) -> bool:
        """检查是否是净化函数"""
        # 检查函数名
        if func_name in self.sanitization_functions:
            return True
        # 检查函数名是否包含净化相关关键词
        sanitize_keywords = ['escape', 'sanitize', 'clean', 'filter', 'quote', 'safe']
        for keyword in sanitize_keywords:
            if keyword in func_name.lower():
                return True
        return False
    
    def _node_to_string(self, node) -> str:
        """将AST节点转换为字符串"""
        try:
            # Python 3.9+ 支持 ast.unparse
            if hasattr(ast, 'unparse'):
                return ast.unparse(node)
            # 对于旧版本，使用手动转换
            if isinstance(node, ast.Name):
                return node.id
            elif isinstance(node, ast.Attribute):
                value_str = self._node_to_string(node.value)
                return f"{value_str}.{node.attr}" if value_str else node.attr
            elif isinstance(node, ast.Constant):
                return repr(node.value) if hasattr(node, 'value') else ''
            elif isinstance(node, ast.Str):
                return repr(node.s)
            elif isinstance(node, ast.Num):
                return str(node.n)
            return ""
        except Exception:
            return ""
    
    def get_tainted_variables(self, func_key: str) -> Set[str]:
        """获取函数中的所有污染变量"""
        return self.tainted_variables.get(func_key, set())
    
    def get_variable_info(self, file_path: str, var_name: str) -> Optional[VariableInfo]:
        """获取变量信息"""
        return self.variable_states.get(file_path, {}).get(var_name)
    
    def is_variable_tainted(self, func_key: str, var_name: str) -> bool:
        """检查变量是否被污染"""
        return var_name in self.tainted_variables.get(func_key, set())
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """获取函数调用名称"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _resolve_cross_file_calls(self, file_path: str, content: str):
        """解析跨文件的函数调用"""
        # 查找import语句
        import_pattern = r'^(?:from|import)\s+(\w+)'
        imports = []
        
        for match in re.finditer(import_pattern, content, re.MULTILINE):
            imports.append(match.group(1))
        
        # 更新调用图，添加模块前缀
        for func_key, calls in list(self.call_graph.items()):
            if func_key.startswith(file_path):
                resolved_calls = []
                for call in calls:
                    # 尝试解析调用
                    resolved_calls.append(call)
                self.call_graph[func_key] = resolved_calls
    
    def _build_js_call_graph(self, file_path: str):
        """构建JavaScript文件的调用图"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return
        
        # 查找函数定义
        func_pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\()'
        
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1) or match.group(2)
            if func_name:
                line_num = content[:match.start()].count('\n') + 1
                func_key = f"{file_path}:{func_name}"
                self.function_definitions[func_key] = (file_path, line_num, [])
        
        # 查找函数调用
        call_pattern = r'(\w+)\s*\('
        
        for func_key in self.function_definitions:
            if func_key.startswith(file_path):
                calls = []
                for match in re.finditer(call_pattern, content):
                    call_name = match.group(1)
                    if call_name not in ['if', 'for', 'while', 'switch', 'catch', 'function']:
                        calls.append(call_name)
                self.call_graph[func_key] = calls
    
    def _build_java_call_graph(self, file_path: str):
        """构建Java文件的调用图"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return
        
        # 查找方法定义
        method_pattern = r'(?:public|private|protected)\s+\w+\s+(\w+)\s*\('
        
        for match in re.finditer(method_pattern, content):
            method_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            func_key = f"{file_path}:{method_name}"
            self.function_definitions[func_key] = (file_path, line_num, [])
        
        # 查找方法调用
        call_pattern = r'\.(\w+)\s*\('
        
        for func_key in self.function_definitions:
            if func_key.startswith(file_path):
                calls = []
                for match in re.finditer(call_pattern, content):
                    calls.append(match.group(1))
                self.call_graph[func_key] = calls
    
    def _build_go_call_graph(self, file_path: str):
        """构建Go文件的调用图"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return
        
        # 查找函数定义
        func_pattern = r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\('
        
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            func_key = f"{file_path}:{func_name}"
            self.function_definitions[func_key] = (file_path, line_num, [])
        
        # 查找函数调用
        call_pattern = r'(\w+)\s*\('
        
        for func_key in self.function_definitions:
            if func_key.startswith(file_path):
                calls = []
                for match in re.finditer(call_pattern, content):
                    call_name = match.group(1)
                    if call_name not in ['if', 'for', 'switch', 'func', 'go', 'defer']:
                        calls.append(call_name)
                self.call_graph[func_key] = calls
    
    def _build_php_call_graph(self, file_path: str):
        """构建PHP文件的调用图"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return
        
        # 查找函数定义
        func_patterns = [
            r'function\s+(\w+)\s*\(',  # 普通函数
            r'public\s+function\s+(\w+)\s*\(',  # 公共方法
            r'private\s+function\s+(\w+)\s*\(',  # 私有方法
            r'protected\s+function\s+(\w+)\s*\(',  # 保护方法
        ]
        
        for pattern in func_patterns:
            for match in re.finditer(pattern, content):
                func_name = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                func_key = f"{file_path}:{func_name}"
                self.function_definitions[func_key] = (file_path, line_num, [])
        
        # 查找函数调用
        call_patterns = [
            r'(\w+)\s*\(',  # 普通函数调用
            r'->(\w+)\s*\(',  # 方法调用
            r'::(\w+)\s*\(',  # 静态方法调用
        ]
        
        for func_key in self.function_definitions:
            if func_key.startswith(file_path):
                calls = []
                for pattern in call_patterns:
                    for match in re.finditer(pattern, content):
                        call_name = match.group(1)
                        if call_name not in ['if', 'for', 'while', 'switch', 'foreach', 'function', 'class', 'public', 'private', 'protected']:
                            calls.append(call_name)
                self.call_graph[func_key] = list(set(calls))  # 去重
    
    def _build_cs_call_graph(self, file_path: str):
        """构建C#文件的调用图"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return
        
        # 查找方法定义
        method_pattern = r'(?:public|private|protected|internal|static)\s+(?:async\s+)?(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\('
        
        for match in re.finditer(method_pattern, content):
            method_name = match.group(1)
            line_num = content[:match.start()].count('\n') + 1
            func_key = f"{file_path}:{method_name}"
            self.function_definitions[func_key] = (file_path, line_num, [])
        
        # 查找方法调用
        call_patterns = [
            r'\.(\w+)\s*\(',  # 实例方法调用
            r'(\w+)\s*\(',  # 静态方法调用
        ]
        
        for func_key in self.function_definitions:
            if func_key.startswith(file_path):
                calls = []
                for pattern in call_patterns:
                    for match in re.finditer(pattern, content):
                        call_name = match.group(1)
                        if call_name not in ['if', 'for', 'while', 'switch', 'foreach', 'using', 'try', 'catch', 'finally', 'lock']:
                            calls.append(call_name)
                self.call_graph[func_key] = list(set(calls))  # 去重
    
    def _build_reverse_call_graph(self):
        """构建反向调用图"""
        self.reverse_call_graph.clear()
        
        for caller, callees in self.call_graph.items():
            for callee in callees:
                self.reverse_call_graph[callee].append(caller)
    
    def _find_paths_to_source(self, sink: SinkPoint, sources: List[SourcePoint]) -> List[CallChain]:
        """
        从sink点反向查找可达的source点
        
        Args:
            sink: Sink点
            sources: Source点列表
            
        Returns:
            调用链列表
        """
        chains = []
        
        # 获取sink点所在的函数
        sink_func = self._find_containing_function(sink.file_path, sink.line_number)
        if not sink_func:
            return chains
        
        # 对每个source点，检查是否存在从source到sink_func的路径
        for source in sources:
            source_func = f"{source.file_path}:{source.function_name}"
            
            # 检查是否直接调用
            if source_func == sink_func or sink_func in self.call_graph.get(source_func, []):
                chain = self._build_call_chain(source, sink, [source_func, sink_func])
                chains.append(chain)
                continue
            
            # 使用BFS查找路径
            path = self._find_path_bfs(source_func, sink_func)
            if path:
                chain = self._build_call_chain(source, sink, path)
                chains.append(chain)
        
        return chains
    
    def _find_containing_function(self, file_path: str, line_number: int) -> Optional[str]:
        """找到包含指定行号的函数"""
        candidates = []
        
        for func_key, (fp, line, params) in self.function_definitions.items():
            if fp == file_path:
                # 简单判断：函数定义行号小于目标行号
                if line <= line_number:
                    candidates.append((func_key, line))
        
        if candidates:
            # 返回最近的函数
            candidates.sort(key=lambda x: x[1], reverse=True)
            return candidates[0][0]
        
        return None
    
    def _find_path_bfs(self, start: str, end: str) -> Optional[List[str]]:
        """
        使用BFS查找从start到end的路径
        
        Args:
            start: 起始函数
            end: 目标函数
            
        Returns:
            路径列表，如果不存在则返回None
        """
        if start == end:
            return [start]
        
        visited = set()
        queue = [(start, [start])]
        
        while queue:
            current, path = queue.pop(0)
            
            if current in visited:
                continue
            visited.add(current)
            
            # 获取当前函数调用的所有函数
            callees = self.call_graph.get(current, [])
            
            for callee in callees:
                # 检查是否匹配目标函数
                if self._function_matches(callee, end):
                    return path + [end]
                
                # 检查是否已经访问过
                if callee not in visited:
                    # 查找callee对应的完整函数键
                    callee_keys = [k for k in self.function_definitions if k.endswith(f":{callee}")]
                    for callee_key in callee_keys:
                        if len(path) < self.config.max_call_depth:
                            queue.append((callee_key, path + [callee_key]))
        
        return None
    
    def _function_matches(self, func1: str, func2: str) -> bool:
        """检查两个函数是否匹配"""
        # 提取函数名部分
        name1 = func1.split(':')[-1] if ':' in func1 else func1
        name2 = func2.split(':')[-1] if ':' in func2 else func2
        
        return name1 == name2 or func1 == func2
    
    def _build_call_chain(self, source: SourcePoint, sink: SinkPoint, 
                         path: List[str]) -> CallChain:
        """
        构建调用链
        
        Args:
            source: Source点
            sink: Sink点
            path: 函数路径
            
        Returns:
            CallChain对象
        """
        nodes = []
        data_flow = []
        
        for i, func_key in enumerate(path):
            if func_key in self.function_definitions:
                file_path, line_num, params = self.function_definitions[func_key]
                func_name = func_key.split(':')[-1]
                
                # 获取代码片段
                code_snippet = self._get_code_snippet(file_path, line_num)
                
                node = CallChainNode(
                    file_path=file_path,
                    line_number=line_num,
                    function_name=func_name,
                    code_snippet=code_snippet,
                    call_type="direct" if i == 0 else "conditional"
                )
                nodes.append(node)
                
                # 构建数据流描述
                if i < len(path) - 1:
                    next_func = path[i + 1].split(':')[-1]
                    data_flow.append(f"{func_name}() -> {next_func}()")
        
        return CallChain(
            source=source,
            sink=sink,
            nodes=nodes,
            is_complete=len(nodes) > 0,
            data_flow=data_flow
        )
    
    def _get_code_snippet(self, file_path: str, line_number: int, 
                         context_lines: int = 5) -> str:
        """获取代码片段"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line_number - 1)
            end = min(len(lines), line_number + context_lines)
            
            return ''.join(lines[start:end]).strip()
        except Exception:
            return ""
    
    def _generate_description(self, chain: CallChain, sink: SinkPoint) -> str:
        """生成漏洞描述"""
        func_path = " -> ".join([node.function_name for node in chain.nodes])
        
        description = f"""
检测到{sink.vulnerability_type.value}漏洞:

调用链: {func_path}

Source点: {chain.source.function_name}() at {chain.source.file_path}:{chain.source.line_number}
  - 路由: {chain.source.route} [{chain.source.http_method}]
  - 参数: {', '.join(chain.source.parameters) if chain.source.parameters else '无'}

Sink点: {sink.function_name}() at {sink.file_path}:{sink.line_number}
  - 漏洞类型: {sink.vulnerability_type.value}
  - 严重程度: {sink.severity.value}

数据流:
{chr(10).join(chain.data_flow) if chain.data_flow else '直接调用'}
"""
        return description.strip()
    
    def _get_cwe_id(self, vuln_type: VulnerabilityType) -> str:
        """获取CWE编号"""
        cwe_map = {
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.COMMAND_INJECTION: "CWE-78",
            VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
            VulnerabilityType.SSRF: "CWE-918",
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.DESERIALIZATION: "CWE-502",
            VulnerabilityType.CODE_INJECTION: "CWE-94",
            VulnerabilityType.LDAP_INJECTION: "CWE-90",
            VulnerabilityType.XML_INJECTION: "CWE-611",
            VulnerabilityType.OPEN_REDIRECT: "CWE-601",
        }
        return cwe_map.get(vuln_type, "")
    
    def forward_audit(self, source: SourcePoint, target_path: str) -> List[CallChain]:
        """
        正向审计：从source出发，分析所有可能的调用路径
        
        Args:
            source: Source点
            target_path: 目标路径
            
        Returns:
            调用链列表
        """
        chains = []
        source_func = f"{source.file_path}:{source.function_name}"
        
        # 使用DFS遍历所有可能的调用路径
        visited = set()
        self._dfs_forward(source_func, [], visited, chains, source)
        
        return chains
    
    def _dfs_forward(self, current: str, path: List[str], visited: Set[str],
                    chains: List[CallChain], source: SourcePoint):
        """DFS正向遍历"""
        if current in visited or len(path) >= self.config.max_call_depth:
            return
        
        visited.add(current)
        path.append(current)
        
        # 获取当前函数调用的所有函数
        callees = self.call_graph.get(current, [])
        
        for callee in callees:
            # 查找callee对应的完整函数键
            callee_keys = [k for k in self.function_definitions if k.endswith(f":{callee}")]
            
            for callee_key in callee_keys:
                if callee_key not in visited:
                    self._dfs_forward(callee_key, path.copy(), visited, chains, source)
        
        visited.remove(current)
    
    def reverse_audit(self, sink: SinkPoint, sources: List[SourcePoint]) -> List[CallChain]:
        """
        反向审计：从sink出发，反向查找所有可达的source
        
        Args:
            sink: Sink点
            sources: Source点列表
            
        Returns:
            调用链列表
        """
        return self._find_paths_to_source(sink, sources)
