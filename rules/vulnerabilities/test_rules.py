#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞规则库测试脚本
"""
import os
import sys
import json
from pathlib import Path

# 自动找到项目根目录（无限向上找，直到包含 core 文件夹）
root = Path(__file__).resolve()
while not (root / "core").exists():
    root = root.parent
sys.path.insert(0, str(root))

from core.config import Config


def test_rules_loading():
    """测试规则加载功能"""
    print("="*60)
    print("漏洞规则库测试")
    print("="*60)

    # 初始化配置
    print("\n[+] 初始化配置...")
    config = Config()
    print("    配置加载成功")

    # 检查规则目录
    vuln_dir = os.path.join(config.rules_dir, 'vulnerabilities')
    print(f"\n[+] 漏洞规则目录: {vuln_dir}")

    if not os.path.exists(vuln_dir):
        print(f"    [!] 规则目录不存在")
        return False

    # 列出所有规则文件
    rule_files = [f for f in os.listdir(vuln_dir) if f.endswith('.json')]
    print(f"\n[+] 发现 {len(rule_files)} 个规则文件")

    # 期望的漏洞类型
    expected_vulns = [
        'sql_injection',
        'command_injection',
        'code_injection',
        'deserialization',
        'path_traversal',
        'ssrf',
        'xss',
        'xxe',
        'ldap_injection',
        'open_redirect'
    ]

    # CWE 映射
    cwe_mapping = {
        'sql_injection': 'CWE-89',
        'command_injection': 'CWE-78',
        'code_injection': 'CWE-94',
        'deserialization': 'CWE-502',
        'path_traversal': 'CWE-22',
        'ssrf': 'CWE-918',
        'xss': 'CWE-79',
        'xxe': 'CWE-611',
        'ldap_injection': 'CWE-90',
        'open_redirect': 'CWE-601'
    }

    # 严重程度映射
    severity_mapping = {
        'sql_injection': 'Critical',
        'command_injection': 'Critical',
        'code_injection': 'Critical',
        'deserialization': 'Critical',
        'path_traversal': 'High',
        'ssrf': 'High',
        'xss': 'High',
        'xxe': 'High',
        'ldap_injection': 'High',
        'open_redirect': 'Medium'
    }

    print("\n" + "="*60)
    print("规则文件检查")
    print("="*60)

    missing_rules = []
    for vuln_type in expected_vulns:
        rule_file = f"{vuln_type}.json"
        rule_path = os.path.join(vuln_dir, rule_file)

        if os.path.exists(rule_path):
            print(f"\n[OK] {vuln_type:20s} - {rule_file}")

            # 读取规则文件
            try:
                with open(rule_path, 'r', encoding='utf-8') as f:
                    rule_data = json.load(f)

                # 验证规则内容
                if vuln_type in rule_data:
                    vuln_data = rule_data[vuln_type]

                    # 检查必需字段
                    required_fields = ['name', 'cwe_id', 'description', 'payloads', 'remediation']
                    missing_fields = [field for field in required_fields if field not in vuln_data]

                    if missing_fields:
                        print(f"    [!] 缺少字段: {', '.join(missing_fields)}")
                    else:
                        cwe_id = vuln_data.get('cwe_id', 'N/A')
                        expected_cwe = cwe_mapping.get(vuln_type, 'N/A')

                        if cwe_id == expected_cwe:
                            print(f"    [OK] CWE: {cwe_id}")
                        else:
                            print(f"    [!] CWE不匹配: 期望 {expected_cwe}, 实际 {cwe_id}")

                        # 检查payload
                        payloads = vuln_data.get('payloads', {})
                        if payloads:
                            print(f"    [OK] Payload类型: {', '.join(payloads.keys())}")
                        else:
                            print(f"    [!] 没有payload")

                        # 检查修复建议
                        remediation = vuln_data.get('remediation', [])
                        if remediation:
                            print(f"    [OK] 修复建议: {len(remediation)} 条")
                        else:
                            print(f"    [!] 没有修复建议")
                else:
                    print(f"    [!] 规则格式错误: 缺少 {vuln_type} 键")

            except Exception as e:
                print(f"    [!] 读取规则失败: {e}")
        else:
            print(f"\n[MISSING] {vuln_type:20s} - 缺失")
            missing_rules.append(vuln_type)

    print("\n" + "="*60)
    print("汇总")
    print("="*60)

    total_expected = len(expected_vulns)
    total_found = total_expected - len(missing_rules)

    print(f"\n期望的漏洞类型: {total_expected}")
    print(f"找到的规则文件: {total_found}")
    print(f"缺失的规则文件: {len(missing_rules)}")

    if missing_rules:
        print(f"\n缺失的漏洞类型: {', '.join(missing_rules)}")
        return False
    else:
        print("\n[OK] 所有漏洞类型规则都已创建!")
        return True


if __name__ == "__main__":
    try:
        success = test_rules_loading()
        if success:
            print("\n[+] 漏洞规则库测试通过!")
            sys.exit(0)
        else:
            print("\n[-] 漏洞规则库测试失败!")
            sys.exit(1)
    except Exception as e:
        print(f"\n[!] 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
