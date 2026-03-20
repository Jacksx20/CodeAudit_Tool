#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试脚本 - 验证代码审计工具是否正常工作
"""
import os
import sys
from pathlib import Path

# 添加项目路径
root = Path(__file__).resolve()
while not (root / "core").exists():
    root = root.parent
sys.path.insert(0, str(root))

from core.config import Config

from core.config import Config
from core.audit_engine import AuditEngine
from reports.report_generator import ReportGenerator


def test_audit_tool():
    """测试审计工具"""
    print("="*60)
    print("代码安全审计工具测试")
    print("="*60)
    
    # 获取测试文件路径
    test_file = os.path.join(os.path.dirname(__file__), 'test_vulnerable_app.py')
    
    if not os.path.exists(test_file):
        print(f"[!] 测试文件不存在: {test_file}")
        return False
    
    print(f"\n[*] 测试文件: {test_file}")
    
    # 初始化配置
    config = Config()
    print("[+] 配置加载成功")
    
    # 初始化审计引擎
    engine = AuditEngine(config)
    print("[+] 审计引擎初始化成功")
    
    # 执行审计
    print("\n[*] 开始执行审计...")
    result = engine.audit(test_file)
    
    # 打印结果
    print("\n" + "="*60)
    print("审计结果")
    print("="*60)
    print(f"目标路径: {result.target_path}")
    print(f"检测框架: {result.framework.value}")
    print(f"扫描文件: {result.scanned_files}")
    print(f"Source点: {result.sources_found}")
    print(f"Sink点: {result.sinks_found}")
    print(f"发现漏洞: {len(result.vulnerabilities)}")
    print(f"扫描耗时: {result.scan_time:.2f}秒")
    
    if result.vulnerabilities:
        print("\n" + "-"*60)
        print("漏洞列表:")
        print("-"*60)
        for vuln in result.vulnerabilities:
            print(f"\n[{vuln.id}] {vuln.name}")
            print(f"  类型: {vuln.vulnerability_type.value}")
            print(f"  严重程度: {vuln.severity.value.upper()}")
            print(f"  位置: {vuln.sink.file_path}:{vuln.sink.line_number}")
    
    # 生成测试报告
    print("\n[*] 生成测试报告...")
    report_gen = ReportGenerator(config)
    output_dir = os.path.join(os.path.dirname(__file__), 'test_reports')
    os.makedirs(output_dir, exist_ok=True)
    
    reports = report_gen.generate_all_formats(result, output_dir)
    for fmt, path in reports.items():
        print(f"  {fmt.upper()}: {path}")
    
    print("\n" + "="*60)
    print("测试完成!")
    print("="*60)
    
    return True


if __name__ == '__main__':
    try:
        success = test_audit_tool()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[!] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
