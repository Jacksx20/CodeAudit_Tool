#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Sink点检测功能
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
from analyzers.sink_analyzer import SinkAnalyzer

def test_sink_detection():
    """测试Sink点检测"""
    print("="*60)
    print("Sink点检测测试")
    print("="*60)

    config = Config()
    sink_analyzer = SinkAnalyzer(config)

    # 检查支持的危险函数
    print("\n[+] 支持的漏洞类型和危险函数:")
    for vuln_type, functions in sink_analyzer.dangerous_functions.items():
        print(f"\n{vuln_type}:")
        for func in functions:
            module = func.get('modules', ['unknown'])
            print(f"  - {func['name']} (模块: {', '.join(module)})")

    # 测试文件
    test_file = os.path.join(os.path.dirname(__file__), "test_all_vulnerabilities.py")
    if os.path.exists(test_file):
        print(f"\n[+] 测试文件: {test_file}")
        sinks = sink_analyzer.analyze(test_file)
        print(f"[+] 发现 {len(sinks)} 个Sink点")

        print("\n[+] Sink点详情:")
        for i, sink in enumerate(sinks, 1):
            print(f"\n{i}. {sink.function_name}")
            print(f"   类型: {sink.vulnerability_type.value}")
            print(f"   严重程度: {sink.severity.value}")
            print(f"   位置: {sink.file_path}:{sink.line_number}")
    else:
        print(f"[!] 测试文件不存在: {test_file}")

if __name__ == "__main__":
    test_sink_detection()
