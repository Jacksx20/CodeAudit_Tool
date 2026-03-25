# -*- coding: utf-8 -*-
"""
大模型审计分析器 - 使用大语言模型增强代码审计能力
"""
import os
import sys
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from core.config import AuditResult, Vulnerability


class LLMAuditAnalyzer:
    """大模型审计分析器"""
    
    def __init__(self, api_key: str = None, model: str = None, base_url: str = None):
        """
        初始化大模型分析器
        
        Args:
            api_key: API密钥(可选,优先从环境变量读取)
            model: 模型名称(可选)
            base_url: API基础URL(可选)
        """
        self.api_key = api_key or os.getenv('LLM_API_KEY') or os.getenv('OPENAI_API_KEY')
        self.model = model or os.getenv('LLM_MODEL', 'gpt-4')
        self.base_url = base_url or os.getenv('LLM_BASE_URL', 'https://api.openai.com/v1')
        
        self.client = None
        self._init_client()
    
    def _init_client(self):
        """初始化大模型客户端"""
        try:
            # 尝试导入openai
            from openai import OpenAI
            
            if self.api_key:
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url
                )
                print(f"[+] 大模型客户端初始化成功: {self.model} @ {self.base_url}")
            else:
                print("[!] 警告: 未配置API密钥,大模型功能将受限")
                self.client = None
                
        except ImportError:
            print("[!] 警告: openai库未安装,请运行: pip install openai")
            self.client = None
        except Exception as e:
            print(f"[!] 大模型客户端初始化失败: {e}")
            self.client = None
    
    def _call_llm(self, prompt: str, system_prompt: str = None, temperature: float = 0.7) -> Optional[str]:
        """
        调用大模型
        
        Args:
            prompt: 用户提示
            system_prompt: 系统提示
            temperature: 温度参数
            
        Returns:
            模型响应文本
        """
        if not self.client:
            return None
        
        try:
            messages = []
            
            if system_prompt:
                messages.append({
                    "role": "system",
                    "content": system_prompt
                })
            
            messages.append({
                "role": "user",
                "content": prompt
            })
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=4000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            print(f"[!] 大模型调用失败: {e}")
            return None
    
    def analyze_audit_result(self, audit_result: AuditResult, target_path: str, 
                            options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        分析审计结果,提供大模型增强的安全分析
        
        Args:
            audit_result: 审计结果
            target_path: 目标路径
            options: 选项配置
            
        Returns:
            大模型分析结果
        """
        options = options or {}
        
        result = {
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'vulnerability_analysis': [],
            'security_summary': None,
            'recommendations': [],
            'risk_assessment': None
        }
        
        try:
            # 1. 分析每个漏洞
            if audit_result.vulnerabilities:
                print(f"[*] 分析 {len(audit_result.vulnerabilities)} 个漏洞...")
                for vuln in audit_result.vulnerabilities[:10]:  # 限制分析数量
                    analysis = self._analyze_vulnerability(vuln, target_path)
                    if analysis:
                        result['vulnerability_analysis'].append(analysis)
            
            # 2. 生成安全总结
            print("[*] 生成安全总结...")
            summary = self._generate_security_summary(audit_result)
            if summary:
                result['security_summary'] = summary
            
            # 3. 生成修复建议
            print("[*] 生成修复建议...")
            recommendations = self._generate_recommendations(audit_result)
            if recommendations:
                result['recommendations'] = recommendations
            
            # 4. 风险评估
            print("[*] 进行风险评估...")
            risk = self._assess_risk(audit_result)
            if risk:
                result['risk_assessment'] = risk
            
        except Exception as e:
            result['status'] = 'failed'
            result['error'] = str(e)
            print(f"[!] 大模型分析失败: {e}")
        
        return result
    
    def _analyze_vulnerability(self, vuln: Vulnerability, target_path: str) -> Optional[Dict[str, Any]]:
        """分析单个漏洞"""
        # 读取漏洞相关代码
        code_snippet = self._read_code_snippet(vuln.source.file_path, vuln.source.line_number, 10)
        
        prompt = f"""请分析以下安全漏洞:

漏洞类型: {vuln.vulnerability_type.value}
漏洞名称: {vuln.name}
严重程度: {vuln.severity.value}
CWE编号: {vuln.cwe_id}

Source点:
- 文件: {vuln.source.file_path}
- 行号: {vuln.source.line_number}
- 函数: {vuln.source.function_name}
- 路由: {vuln.source.route}

Sink点:
- 文件: {vuln.sink.file_path}
- 行号: {vuln.sink.line_number}
- 函数: {vuln.sink.function_name}
- 危险函数: {vuln.sink.dangerous_function}

相关代码:
```
{code_snippet}
```

请提供:
1. 漏洞成因分析
2. 攻击场景说明
3. 具体修复方案(包含代码示例)
4. 验证方法

请以JSON格式返回结果。"""

        system_prompt = """你是一个专业的代码安全审计专家,擅长分析各种安全漏洞。
请用中文回答,并提供详细的技术分析和具体的修复建议。
返回的JSON格式如下:
{
    "cause": "漏洞成因",
    "attack_scenario": "攻击场景",
    "fix_solution": "修复方案",
    "fix_code": "修复代码示例",
    "verification": "验证方法"
}"""

        response = self._call_llm(prompt, system_prompt, temperature=0.5)
        
        if response:
            try:
                # 尝试提取JSON
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    analysis = json.loads(json_match.group())
                    analysis['vuln_id'] = vuln.id
                    return analysis
            except json.JSONDecodeError:
                pass
            
            # 如果JSON解析失败,返回原始响应
            return {
                'vuln_id': vuln.id,
                'raw_analysis': response
            }
        
        return None
    
    def _generate_security_summary(self, audit_result: AuditResult) -> Optional[str]:
        """生成安全总结"""
        summary = audit_result.get_summary()
        
        prompt = f"""请根据以下审计结果生成安全总结报告:

审计统计:
- 总文件数: {audit_result.total_files}
- 扫描文件数: {audit_result.scanned_files}
- 扫描耗时: {audit_result.scan_time:.2f}秒
- Source点数量: {audit_result.sources_found}
- Sink点数量: {audit_result.sinks_found}
- 漏洞总数: {len(audit_result.vulnerabilities)}

漏洞严重程度分布:
- Critical: {summary['critical']}
- High: {summary['high']}
- Medium: {summary['medium']}
- Low: {summary['low']}

漏洞类型分布:
{json.dumps(summary['by_type'], ensure_ascii=False, indent=2)}

请生成一份简洁的安全总结报告,包括:
1. 整体安全状况评估
2. 主要风险点
3. 优先修复建议"""

        system_prompt = "你是一个专业的安全审计专家,请用中文生成简洁专业的安全总结报告。"
        
        return self._call_llm(prompt, system_prompt, temperature=0.6)
    
    def _generate_recommendations(self, audit_result: AuditResult) -> Optional[List[str]]:
        """生成修复建议"""
        if not audit_result.vulnerabilities:
            return None
        
        vuln_types = {}
        for vuln in audit_result.vulnerabilities:
            vtype = vuln.vulnerability_type.value
            if vtype not in vuln_types:
                vuln_types[vtype] = 0
            vuln_types[vtype] += 1
        
        prompt = f"""根据以下漏洞类型分布,生成优先级排序的修复建议:

漏洞类型分布:
{json.dumps(vuln_types, ensure_ascii=False, indent=2)}

请生成5-10条具体的修复建议,按优先级排序。
每条建议应该包含:
1. 建议内容
2. 优先级(高/中/低)
3. 预计工作量

请以JSON数组格式返回。"""

        system_prompt = """你是一个专业的安全顾问,请用中文提供具体的修复建议。
返回格式:
[
    {
        "content": "建议内容",
        "priority": "高/中/低",
        "effort": "工作量估计"
    }
]"""

        response = self._call_llm(prompt, system_prompt, temperature=0.6)
        
        if response:
            try:
                json_match = re.search(r'\[[\s\S]*\]', response)
                if json_match:
                    return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _assess_risk(self, audit_result: AuditResult) -> Optional[Dict[str, Any]]:
        """风险评估"""
        summary = audit_result.get_summary()
        
        prompt = f"""请对以下审计结果进行风险评估:

漏洞统计:
- Critical: {summary['critical']}
- High: {summary['high']}
- Medium: {summary['medium']}
- Low: {summary['low']}
- 总计: {len(audit_result.vulnerabilities)}

攻击链数量: {len(audit_result.attack_chains)}

请评估:
1. 整体风险等级(极高/高/中/低)
2. 业务影响评估
3. 合规性风险
4. 紧急修复项

请以JSON格式返回。"""

        system_prompt = """你是一个专业的风险评估专家,请用中文进行风险评估。
返回格式:
{
    "risk_level": "风险等级",
    "business_impact": "业务影响",
    "compliance_risk": "合规性风险",
    "urgent_items": ["紧急修复项列表"]
}"""

        response = self._call_llm(prompt, system_prompt, temperature=0.5)
        
        if response:
            try:
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        
        return None
    
    def _read_code_snippet(self, file_path: str, line_number: int, context: int = 10) -> str:
        """读取代码片段"""
        try:
            if not os.path.exists(file_path):
                return ""
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start = max(0, line_number - context - 1)
            end = min(len(lines), line_number + context)
            
            snippet_lines = []
            for i in range(start, end):
                line_no = i + 1
                marker = ">>>" if line_no == line_number else "   "
                snippet_lines.append(f"{marker} {line_no:4d} | {lines[i].rstrip()}")
            
            return "\n".join(snippet_lines)
            
        except Exception as e:
            print(f"[!] 读取代码片段失败: {e}")
            return ""
    
    def analyze_code_snippet(self, code: str, language: str = 'python') -> Dict[str, Any]:
        """
        分析代码片段
        
        Args:
            code: 代码内容
            language: 编程语言
            
        Returns:
            分析结果
        """
        prompt = f"""请分析以下{language}代码的安全问题:

```{language}
{code}
```

请识别:
1. 潜在的安全漏洞
2. 不安全的编码实践
3. 修复建议

请以JSON格式返回结果。"""

        system_prompt = """你是一个专业的代码安全审计专家。
返回格式:
{
    "vulnerabilities": [
        {
            "type": "漏洞类型",
            "line": 行号,
            "description": "描述",
            "severity": "严重程度",
            "fix": "修复建议"
        }
    ],
    "security_issues": ["安全问题列表"],
    "best_practices": ["最佳实践建议"]
}"""

        response = self._call_llm(prompt, system_prompt, temperature=0.5)
        
        result = {
            'status': 'success',
            'analysis': None
        }
        
        if response:
            try:
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    result['analysis'] = json.loads(json_match.group())
            except json.JSONDecodeError:
                result['analysis'] = {'raw': response}
        
        return result


# 简单测试
if __name__ == '__main__':
    print("="*60)
    print("大模型审计分析器测试")
    print("="*60)
    
    analyzer = LLMAuditAnalyzer()
    
    if analyzer.client:
        print("\n[+] 大模型客户端已就绪")
    else:
        print("\n[!] 大模型客户端未初始化,请配置API密钥")
    
    print("="*60)
