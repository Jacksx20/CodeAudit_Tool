# -*- coding: utf-8 -*-
"""
审计引擎 - 协调各分析器完成代码安全审计
"""
import os
import time
import json
from typing import List, Dict, Optional, Set
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import (
    Config, AuditResult, Vulnerability, AttackChain,
    SourcePoint, SinkPoint, Framework
)
from analyzers.source_analyzer import SourceAnalyzer
from analyzers.sink_analyzer import SinkAnalyzer
from analyzers.call_chain_analyzer import CallChainAnalyzer


class AuditEngine:
    """审计引擎"""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.source_analyzer = SourceAnalyzer(self.config)
        self.sink_analyzer = SinkAnalyzer(self.config)
        self.call_chain_analyzer = CallChainAnalyzer(self.config)
    
    def audit(self, target_path: str, 
              enable_forward: bool = True,
              enable_reverse: bool = True,
              enable_attack_chain: bool = True) -> AuditResult:
        """
        执行代码安全审计
        
        Args:
            target_path: 目标代码路径
            enable_forward: 是否启用正向审计
            enable_reverse: 是否启用反向审计
            enable_attack_chain: 是否启用攻击链分析
            
        Returns:
            AuditResult: 审计结果
        """
        start_time = time.time()
        
        # 初始化结果
        result = AuditResult(target_path=target_path)
        
        # 统计文件数
        result.total_files = self._count_files(target_path)
        
        print(f"[*] 开始审计目标: {target_path}")
        print(f"[*] 总文件数: {result.total_files}")
        
        # Step 1: 识别Source点
        print("\n[+] Step 1: 识别HTTP入口点(Source点)...")
        sources = self.source_analyzer.analyze(target_path)
        result.sources_found = len(sources)
        result.framework = self._get_primary_framework(self.source_analyzer.get_detected_frameworks())
        print(f"    发现 {len(sources)} 个Source点")
        
        # Step 2: 检测Sink点
        print("\n[+] Step 2: 检测危险函数调用(Sink点)...")
        sinks = self.sink_analyzer.analyze(target_path)
        result.sinks_found = len(sinks)
        print(f"    发现 {len(sinks)} 个Sink点")
        
        # Step 3: 分析调用链
        print("\n[+] Step 3: 分析调用链...")
        vulnerabilities = []
        seen_vulns = set()  # 用于去重
        
        if enable_reverse:
            print("    执行反向审计(从Sink到Source)...")
            vulns_reverse = self.call_chain_analyzer.analyze(target_path, sources, sinks)
            for vuln in vulns_reverse:
                vuln_key = (vuln.source.function_name, vuln.sink.function_name, 
                           vuln.vulnerability_type.value, vuln.sink.line_number)
                if vuln_key not in seen_vulns:
                    vulnerabilities.append(vuln)
                    seen_vulns.add(vuln_key)
            print(f"    反向审计发现 {len(vulns_reverse)} 个漏洞")
        
        if enable_forward:
            print("    执行正向审计(从Source到Sink)...")
            vulns_forward = self._forward_audit(target_path, sources, sinks)
            # 合并结果，避免重复
            for vuln in vulns_forward:
                vuln_key = (vuln.source.function_name, vuln.sink.function_name,
                           vuln.vulnerability_type.value, vuln.sink.line_number)
                if vuln_key not in seen_vulns:
                    vulnerabilities.append(vuln)
                    seen_vulns.add(vuln_key)
            print(f"    正向审计发现 {len(vulns_forward)} 个漏洞")
        
        result.vulnerabilities = vulnerabilities
        print(f"    总计发现 {len(vulnerabilities)} 个漏洞")
        
        # Step 4: 分析攻击链
        if enable_attack_chain and len(vulnerabilities) > 1:
            print("\n[+] Step 4: 分析攻击链...")
            attack_chains = self._analyze_attack_chains(vulnerabilities)
            result.attack_chains = attack_chains
            print(f"    发现 {len(attack_chains)} 条潜在攻击链")
        
        # 统计扫描文件数
        result.scanned_files = self._count_scanned_files(target_path)
        
        # 计算扫描时间
        result.scan_time = time.time() - start_time
        
        print(f"\n[*] 审计完成，耗时: {result.scan_time:.2f}秒")
        
        return result
    
    def _count_files(self, target_path: str) -> int:
        """统计目标路径下的文件数"""
        count = 0
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in self.config.supported_extensions:
                    count += 1
        return count
    
    def _count_scanned_files(self, target_path: str) -> int:
        """统计已扫描的文件数"""
        return self._count_files(target_path)
    
    def _get_primary_framework(self, frameworks: Set[Framework]) -> Framework:
        """获取主要框架"""
        if not frameworks:
            return Framework.GENERIC
        
        # 优先级排序
        priority = [
            Framework.FLASK, Framework.DJANGO, Framework.FASTAPI,
            Framework.SPRING, Framework.EXPRESS, Framework.GIN
        ]
        
        for fw in priority:
            if fw in frameworks:
                return fw
        
        return list(frameworks)[0] if frameworks else Framework.GENERIC
    
    def _forward_audit(self, target_path: str, sources: List[SourcePoint],
                      sinks: List[SinkPoint]) -> List[Vulnerability]:
        """
        正向审计：从Source出发，分析所有可能的调用路径
        
        Args:
            target_path: 目标路径
            sources: Source点列表
            sinks: Sink点列表
            
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        vuln_id = len(self.call_chain_analyzer.function_definitions) + 1
        
        # 构建调用图
        self.call_chain_analyzer._build_call_graph(target_path)
        
        for source in sources:
            # 从source出发，找到所有可达的函数
            reachable_funcs = self._find_reachable_functions(source)
            
            # 检查是否有sink点在可达函数中
            for sink in sinks:
                sink_func = self.call_chain_analyzer._find_containing_function(
                    sink.file_path, sink.line_number
                )
                
                if sink_func and self._is_reachable(sink_func, reachable_funcs):
                    # 构建调用链
                    path = self.call_chain_analyzer._find_path_bfs(
                        f"{source.file_path}:{source.function_name}",
                        sink_func
                    )
                    
                    if path:
                        chain = self.call_chain_analyzer._build_call_chain(source, sink, path)
                        
                        vuln = Vulnerability(
                            id=f"VULN-{vuln_id:04d}",
                            name=f"{sink.vulnerability_type.value} in {source.function_name}",
                            vulnerability_type=sink.vulnerability_type,
                            severity=sink.severity,
                            source=source,
                            sink=sink,
                            call_chain=chain,
                            description=self.call_chain_analyzer._generate_description(chain, sink),
                            remediation=sink.remediation,
                            cwe_id=self.call_chain_analyzer._get_cwe_id(sink.vulnerability_type)
                        )
                        vulnerabilities.append(vuln)
                        vuln_id += 1
        
        return vulnerabilities
    
    def _find_reachable_functions(self, source: SourcePoint) -> Set[str]:
        """从source出发，找到所有可达的函数"""
        reachable = set()
        source_func = f"{source.file_path}:{source.function_name}"
        
        # BFS遍历
        queue = [source_func]
        visited = set()
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            reachable.add(current)
            
            # 获取调用的函数
            callees = self.call_chain_analyzer.call_graph.get(current, [])
            for callee in callees:
                # 查找完整的函数键
                callee_keys = [k for k in self.call_chain_analyzer.function_definitions 
                              if k.endswith(f":{callee}")]
                for callee_key in callee_keys:
                    if callee_key not in visited:
                        queue.append(callee_key)
        
        return reachable
    
    def _is_reachable(self, target: str, reachable: Set[str]) -> bool:
        """检查目标函数是否可达"""
        if target in reachable:
            return True
        
        # 检查函数名是否匹配
        target_name = target.split(':')[-1] if ':' in target else target
        for func in reachable:
            func_name = func.split(':')[-1] if ':' in func else func
            if func_name == target_name:
                return True
        
        return False
    
    def _analyze_attack_chains(self, vulnerabilities: List[Vulnerability]) -> List[AttackChain]:
        """
        分析攻击链：多个漏洞的组合利用
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            攻击链列表
        """
        attack_chains = []
        
        # 按漏洞类型分组
        vulns_by_type: Dict[str, List[Vulnerability]] = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.vulnerability_type.value
            if vuln_type not in vulns_by_type:
                vulns_by_type[vuln_type] = []
            vulns_by_type[vuln_type].append(vuln)
        
        # 检测常见的攻击链组合
        attack_chain_patterns = [
            # SQL注入 + 路径遍历 = 数据库文件读取
            {
                'types': ['sql_injection', 'path_traversal'],
                'description': 'SQL注入结合路径遍历，可能读取数据库文件或配置文件',
                'impact': '敏感数据泄露、数据库文件读取',
                'steps': [
                    '1. 利用SQL注入获取数据库结构信息',
                    '2. 利用路径遍历读取数据库配置文件',
                    '3. 结合两者信息获取完整数据库访问权限'
                ]
            },
            # 命令注入 + SSRF = 内网渗透
            {
                'types': ['command_injection', 'ssrf'],
                'description': '命令注入结合SSRF，可进行内网渗透',
                'impact': '内网服务访问、远程代码执行',
                'steps': [
                    '1. 利用SSRF探测内网服务',
                    '2. 利用命令注入执行系统命令',
                    '3. 结合两者实现内网横向移动'
                ]
            },
            # XSS + 反序列化 = 会话劫持 + RCE
            {
                'types': ['xss', 'deserialization'],
                'description': 'XSS结合反序列化，可实现会话劫持和远程代码执行',
                'impact': '用户会话劫持、远程代码执行',
                'steps': [
                    '1. 利用XSS窃取用户会话Cookie',
                    '2. 构造恶意序列化数据',
                    '3. 利用反序列化漏洞执行任意代码'
                ]
            },
            # 路径遍历 + 反序列化 = 任意文件写入 + RCE
            {
                'types': ['path_traversal', 'deserialization'],
                'description': '路径遍历结合反序列化，可写入恶意序列化文件',
                'impact': '远程代码执行',
                'steps': [
                    '1. 构造恶意序列化数据',
                    '2. 利用路径遍历写入到应用加载路径',
                    '3. 触发反序列化执行恶意代码'
                ]
            },
            # SSRF + 路径遍历 = 云元数据访问 + 敏感文件读取
            {
                'types': ['ssrf', 'path_traversal'],
                'description': 'SSRF结合路径遍历，可访问云元数据和读取敏感文件',
                'impact': '云凭证泄露、敏感文件读取',
                'steps': [
                    '1. 利用SSRF访问云元数据服务',
                    '2. 获取云访问凭证',
                    '3. 利用路径遍历读取应用配置文件'
                ]
            }
        ]
        
        # 检查每个攻击链模式
        for pattern in attack_chain_patterns:
            required_types = pattern['types']
            matching_vulns = []
            
            for vuln_type in required_types:
                if vuln_type in vulns_by_type:
                    matching_vulns.append(vulns_by_type[vuln_type][0])
            
            if len(matching_vulns) == len(required_types):
                attack_chain = AttackChain(
                    vulnerabilities=matching_vulns,
                    description=pattern['description'],
                    impact=pattern['impact'],
                    steps=pattern['steps']
                )
                attack_chains.append(attack_chain)
        
        return attack_chains
    
    def quick_scan(self, target_path: str) -> AuditResult:
        """
        快速扫描：仅检测Sink点，不进行调用链分析
        
        Args:
            target_path: 目标代码路径
            
        Returns:
            AuditResult: 审计结果
        """
        start_time = time.time()
        
        result = AuditResult(target_path=target_path)
        result.total_files = self._count_files(target_path)
        
        print(f"[*] 快速扫描目标: {target_path}")
        
        # 仅检测Sink点
        sinks = self.sink_analyzer.analyze(target_path)
        result.sinks_found = len(sinks)
        
        # 创建简化的漏洞报告
        for i, sink in enumerate(sinks):
            # 创建一个虚拟的source点
            dummy_source = SourcePoint(
                file_path=sink.file_path,
                line_number=sink.line_number,
                function_name="unknown",
                framework=Framework.GENERIC,
                route="/unknown",
                http_method="GET"
            )
            
            vuln = Vulnerability(
                id=f"VULN-{i+1:04d}",
                name=f"{sink.vulnerability_type.value} detected",
                vulnerability_type=sink.vulnerability_type,
                severity=sink.severity,
                source=dummy_source,
                sink=sink,
                call_chain=None,
                description=sink.description,
                remediation=sink.remediation,
                cwe_id=self.call_chain_analyzer._get_cwe_id(sink.vulnerability_type)
            )
            result.vulnerabilities.append(vuln)
        
        result.scan_time = time.time() - start_time
        print(f"[*] 快速扫描完成，发现 {len(sinks)} 个潜在漏洞，耗时: {result.scan_time:.2f}秒")
        
        return result
    
    def get_statistics(self, result: AuditResult) -> Dict:
        """获取审计统计信息"""
        stats = {
            'total_files': result.total_files,
            'scanned_files': result.scanned_files,
            'sources_found': result.sources_found,
            'sinks_found': result.sinks_found,
            'vulnerabilities': len(result.vulnerabilities),
            'attack_chains': len(result.attack_chains),
            'scan_time': result.scan_time,
            'framework': result.framework.value,
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'vulnerability_types': {}
        }
        
        for vuln in result.vulnerabilities:
            severity = vuln.severity.value
            stats['severity_distribution'][severity] = \
                stats['severity_distribution'].get(severity, 0) + 1
            
            vuln_type = vuln.vulnerability_type.value
            stats['vulnerability_types'][vuln_type] = \
                stats['vulnerability_types'].get(vuln_type, 0) + 1
        
        return stats
