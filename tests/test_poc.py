#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC生成功能测试脚本
"""
import os
import sys

# 添加项目根目录到路径
from pathlib import Path

# 添加项目路径
root = Path(__file__).resolve()
while not (root / "core").exists():
    root = root.parent
sys.path.insert(0, str(root))
from core.config import Config, Vulnerability, VulnerabilityType, Severity, SourcePoint, SinkPoint, CallChain, Framework
from generators.poc_generator import PoCGenerator


def test_poc_generation():
    """测试PoC生成功能"""
    print("="*60)
    print("PoC生成功能测试")
    print("="*60)

    # 初始化配置
    print("\n[+] 初始化配置...")
    config = Config()
    print("    配置加载成功")

    # 初始化PoC生成器
    print("\n[+] 初始化PoC生成器...")
    poc_generator = PoCGenerator(config, base_url="http://localhost:5000")
    print("    PoC生成器初始化成功")

    # 创建测试漏洞
    print("\n[+] 创建测试漏洞...")

    # 测试1: SQL注入漏洞
    source1 = SourcePoint(
        file_path="/test/app.py",
        line_number=10,
        function_name="login",
        framework=Framework.FLASK,
        route="/login",
        http_method="POST",
        parameters=["username", "password"]
    )

    sink1 = SinkPoint(
        file_path="/test/app.py",
        line_number=15,
        function_name="execute",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        description="SQL注入漏洞",
        remediation="使用参数化查询"
    )

    call_chain1 = CallChain(source=source1, sink=sink1)

    vuln1 = Vulnerability(
        id="VULN-0001",
        name="SQL Injection in login",
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        source=source1,
        sink=sink1,
        call_chain=call_chain1,
        description="登录接口存在SQL注入漏洞",
        remediation="使用参数化查询或ORM",
        cwe_id="CWE-89"
    )

    # 测试2: 命令注入漏洞
    source2 = SourcePoint(
        file_path="/test/app.py",
        line_number=20,
        function_name="ping",
        framework=Framework.FLASK,
        route="/ping",
        http_method="GET",
        parameters=["ip"]
    )

    sink2 = SinkPoint(
        file_path="/test/app.py",
        line_number=25,
        function_name="subprocess.run",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        description="命令注入漏洞",
        remediation="避免使用shell=True"
    )

    call_chain2 = CallChain(source=source2, sink=sink2)

    vuln2 = Vulnerability(
        id="VULN-0002",
        name="Command Injection in ping",
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        source=source2,
        sink=sink2,
        call_chain=call_chain2,
        description="Ping接口存在命令注入漏洞",
        remediation="使用列表形式传递参数",
        cwe_id="CWE-78"
    )

    # 测试3: XSS漏洞
    source3 = SourcePoint(
        file_path="/test/app.py",
        line_number=30,
        function_name="search",
        framework=Framework.FLASK,
        route="/search",
        http_method="GET",
        parameters=["query"]
    )

    sink3 = SinkPoint(
        file_path="/test/app.py",
        line_number=35,
        function_name="render_template_string",
        vulnerability_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        description="XSS漏洞",
        remediation="对输出进行HTML转义"
    )

    call_chain3 = CallChain(source=source3, sink=sink3)

    vuln3 = Vulnerability(
        id="VULN-0003",
        name="XSS in search",
        vulnerability_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        source=source3,
        sink=sink3,
        call_chain=call_chain3,
        description="搜索接口存在XSS漏洞",
        remediation="使用安全的模板引擎或转义输出",
        cwe_id="CWE-79"
    )

    vulnerabilities = [vuln1, vuln2, vuln3]

    # 生成PoC
    print(f"\n[+] 生成 {len(vulnerabilities)} 个漏洞的PoC...")
    pocs = poc_generator.generate_batch_pocs(vulnerabilities)

    if not pocs:
        print("    [!] 未能生成任何PoC")
        return False

    print(f"    成功生成 {len(pocs)} 个PoC")

    # 显示PoC详情
    print("\n" + "="*60)
    print("PoC详情")
    print("="*60)

    for i, poc in enumerate(pocs, 1):
        print(f"\n[PoC {i}] {poc.vulnerability_type.value.upper()}")
        print("-"*60)
        print(f"URL: {poc.url}")
        print(f"方法: {poc.http_method}")
        print(f"Payload: {poc.payload}")
        print(f"预期结果: {poc.expected_result}")
        print(f"\ncURL命令:")
        print(f"  {poc.curl_command}")
        print(f"\nPython代码 (前500字符):")
        print(f"  {poc.python_code[:500]}...")

    # 保存PoC到文件
    print("\n" + "="*60)
    print("保存PoC到文件")
    print("="*60)

    poc_dir = "./test_pocs"
    os.makedirs(poc_dir, exist_ok=True)

    for i, (poc, vuln) in enumerate(zip(pocs, vulnerabilities), 1):
        # 使用 README 中指定的格式: poc_VULN-ID_vuln_type.py
        poc_file = os.path.join(poc_dir, f"poc_{vuln.id}_{vuln.vulnerability_type.value}.py")
        poc_generator.save_poc_to_file(poc, poc_file)
        print(f"[+] 保存PoC: {poc_file}")

    # 测试利用链生成
    print("\n" + "="*60)
    print("测试利用链生成")
    print("="*60)

    exploit_chain = poc_generator.generate_exploit_chain(vulnerabilities)
    exploit_file = os.path.join(poc_dir, "exploit_chain.py")

    with open(exploit_file, 'w', encoding='utf-8') as f:
        f.write(exploit_chain)

    print(f"[+] 保存利用链: {exploit_file}")
    print(f"\n利用链脚本 (前500字符):")
    print(f"  {exploit_chain[:500]}...")

    print("\n" + "="*60)
    print("测试完成!")
    print("="*60)
    print(f"\n生成的文件保存在: {poc_dir}")

    return True


if __name__ == "__main__":
    try:
        success = test_poc_generation()
        if success:
            print("\n[+] PoC生成功能测试通过!")
            sys.exit(0)
        else:
            print("\n[-] PoC生成功能测试失败!")
            sys.exit(1)
    except Exception as e:
        print(f"\n[!] 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
