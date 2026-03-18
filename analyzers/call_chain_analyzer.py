# -*- coding: utf-8 -*-
"""
调用链分析器 - 构建完整的source→sink调用链
支持正向审计和反向审计
"""
import os
import re
import ast
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import (
    SourcePoint, SinkPoint, CallChain, CallChainNode, 
    Vulnerability, VulnerabilityType, Severity, Config
)


class CallChainAnalyzer:
    """调用链分析器"""
    
    def __init__(self, config: Config):
        self.config = config
        self.call_graph: Dict[str, List[str]] = defaultdict(list)  # 函数调用图
        self.function_definitions: Dict[str, Tuple[str, int, List[str]]] = {}  # 函数定义信息
        self.reverse_call_graph: Dict[str, List[str]] = defaultdict(list)  # 反向调用图
        
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
        
        return vulnerabilities
    
    def _build_call_graph(self, target_path: str):
        """构建函数调用图"""
        self.call_graph.clear()
        self.function_definitions.clear()
        
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
    
    def _build_python_call_graph(self, file_path: str):
        """构建Python文件的调用图"""
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
        
        # 构建跨文件的调用关系
        self._resolve_cross_file_calls(file_path, content)
    
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
