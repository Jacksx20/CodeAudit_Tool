#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码安全审计工具 - CLI主入口
"""
import os
import sys
import argparse
import json
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config, AuditResult
from core.audit_engine import AuditEngine
from generators.poc_generator import PoCGenerator
from reports.report_generator import ReportGenerator


def print_banner():
    """打印工具横幅"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           Code Security Audit Tool v1.0.0                 ║
    ║           代码安全审计工具                                 ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_summary(result: AuditResult):
    """打印审计摘要"""
    summary = result.get_summary()
    
    print("\n" + "="*60)
    print("审计摘要")
    print("="*60)
    print(f"目标路径: {result.target_path}")
    print(f"检测框架: {result.framework.value}")
    print(f"扫描文件: {result.scanned_files}/{result.total_files}")
    print(f"扫描耗时: {result.scan_time:.2f}秒")
    print(f"Source点: {result.sources_found}")
    print(f"Sink点: {result.sinks_found}")
    print(f"发现漏洞: {len(result.vulnerabilities)}")
    print("-"*60)
    print("漏洞严重程度分布:")
    print(f"  Critical: {summary['critical']}")
    print(f"  High:     {summary['high']}")
    print(f"  Medium:   {summary['medium']}")
    print(f"  Low:      {summary['low']}")
    print("-"*60)
    print("漏洞类型分布:")
    for vuln_type, count in summary['by_type'].items():
        print(f"  {vuln_type}: {count}")
    print("="*60)


def print_vulnerability(vuln, index: int, total: int):
    """打印单个漏洞信息"""
    print(f"\n[{index+1}/{total}] {vuln.id}: {vuln.name}")
    print("-"*60)
    print(f"类型: {vuln.vulnerability_type.value}")
    print(f"严重程度: {vuln.severity.value.upper()}")
    print(f"CWE: {vuln.cwe_id}")
    print(f"\nSource点:")
    print(f"  函数: {vuln.source.function_name}()")
    print(f"  位置: {vuln.source.file_path}:{vuln.source.line_number}")
    print(f"  路由: {vuln.source.route} [{vuln.source.http_method}]")
    print(f"\nSink点:")
    print(f"  函数: {vuln.sink.function_name}()")
    print(f"  位置: {vuln.sink.file_path}:{vuln.sink.line_number}")
    
    if vuln.call_chain and vuln.call_chain.nodes:
        print(f"\n调用链:")
        chain_str = " -> ".join([node.function_name for node in vuln.call_chain.nodes])
        print(f"  {chain_str}")
    
    print(f"\n修复建议:")
    print(f"  {vuln.remediation}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='代码安全审计工具 - 自动化代码安全漏洞检测',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  # 基本审计
  python cli.py /path/to/code
  
  # 指定输出格式和路径
  python cli.py /path/to/code -f html -o report.html
  
  # 快速扫描(仅检测Sink点)
  python cli.py /path/to/code --quick
  
  # 生成所有格式的报告
  python cli.py /path/to/code --all-formats -o ./reports
  
  # 生成PoC
  python cli.py /path/to/code --poc --base-url http://localhost:5000
        '''
    )
    
    parser.add_argument('target', help='目标代码路径')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'markdown', 'md'],
                       default='json', help='报告格式 (默认: json)')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--quick', action='store_true', 
                       help='快速扫描模式(仅检测Sink点)')
    parser.add_argument('--all-formats', action='store_true',
                       help='生成所有格式的报告')
    parser.add_argument('--poc', action='store_true',
                       help='生成漏洞PoC')
    parser.add_argument('--base-url', default='http://localhost:5000',
                       help='目标应用基础URL (用于PoC生成)')
    parser.add_argument('--no-forward', action='store_true',
                       help='禁用正向审计')
    parser.add_argument('--no-reverse', action='store_true',
                       help='禁用反向审计')
    parser.add_argument('--no-attack-chain', action='store_true',
                       help='禁用攻击链分析')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='详细输出模式')
    parser.add_argument('--config', help='配置文件路径')
    
    args = parser.parse_args()
    
    # 打印横幅
    print_banner()
    
    # 验证目标路径
    if not os.path.exists(args.target):
        print(f"[!] 错误: 目标路径不存在: {args.target}")
        sys.exit(1)
    
    # 初始化配置
    config = Config(args.config)
    
    # 初始化审计引擎
    engine = AuditEngine(config)
    
    # 执行审计
    print(f"[*] 开始审计: {args.target}")
    
    if args.quick:
        result = engine.quick_scan(args.target)
    else:
        result = engine.audit(
            args.target,
            enable_forward=not args.no_forward,
            enable_reverse=not args.no_reverse,
            enable_attack_chain=not args.no_attack_chain
        )
    
    # 打印摘要
    print_summary(result)
    
    # 详细模式下打印漏洞详情
    if args.verbose and result.vulnerabilities:
        print("\n" + "="*60)
        print("漏洞详情")
        print("="*60)
        for i, vuln in enumerate(result.vulnerabilities):
            print_vulnerability(vuln, i, len(result.vulnerabilities))
    
    # 生成PoC
    if args.poc and result.vulnerabilities:
        print("\n[+] 生成PoC...")
        poc_generator = PoCGenerator(config, args.base_url)
        
        poc_dir = args.output if args.output else './pocs'
        os.makedirs(poc_dir, exist_ok=True)
        
        for vuln in result.vulnerabilities:
            poc = poc_generator.generate_poc(vuln)
            if poc:
                poc_file = os.path.join(poc_dir, f"{vuln.id}_poc.py")
                poc_generator.save_poc_to_file(poc, poc_file)
                print(f"    生成PoC: {poc_file}")
    
    # 生成报告
    print("\n[+] 生成报告...")
    report_generator = ReportGenerator(config)
    
    if args.all_formats:
        output_dir = args.output if args.output else './reports'
        reports = report_generator.generate_all_formats(result, output_dir)
        for fmt, path in reports.items():
            print(f"    {fmt.upper()}报告: {path}")
    else:
        output_path = args.output or f"audit_report.{args.format}"
        report_path = report_generator.generate(result, output_path, args.format)
        print(f"    报告已生成: {report_path}")
    
    # 打印攻击链信息
    if result.attack_chains:
        print("\n[!] 发现潜在攻击链:")
        for i, chain in enumerate(result.attack_chains):
            print(f"\n  攻击链 #{i+1}:")
            print(f"    描述: {chain.description}")
            print(f"    影响: {chain.impact}")
            print(f"    涉及漏洞: {', '.join([v.id for v in chain.vulnerabilities])}")
    
    # 返回退出码
    if result.vulnerabilities:
        # 根据漏洞严重程度返回不同的退出码
        summary = result.get_summary()
        if summary['critical'] > 0:
            sys.exit(2)  # 发现严重漏洞
        elif summary['high'] > 0:
            sys.exit(1)  # 发现高危漏洞
        else:
            sys.exit(0)  # 仅发现中低危漏洞
    else:
        sys.exit(0)  # 未发现漏洞


if __name__ == '__main__':
    main()
