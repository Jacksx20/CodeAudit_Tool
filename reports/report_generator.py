# -*- coding: utf-8 -*-
"""
报告生成器 - 生成多格式漏洞报告
支持JSON、HTML、Markdown格式
"""
import os
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import AuditResult, Vulnerability, Config


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self, config: Config):
        self.config = config
        self.templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            'templates'
        )
    
    def generate(self, result: AuditResult, output_path: str, 
                format: str = 'json') -> str:
        """
        生成报告
        
        Args:
            result: 审计结果
            output_path: 输出路径
            format: 报告格式 (json, html, markdown)
            
        Returns:
            报告文件路径
        """
        if format == 'json':
            return self._generate_json(result, output_path)
        elif format == 'html':
            return self._generate_html(result, output_path)
        elif format == 'markdown' or format == 'md':
            return self._generate_markdown(result, output_path)
        else:
            raise ValueError(f"不支持的报告格式: {format}")
    
    def _generate_json(self, result: AuditResult, output_path: str) -> str:
        """生成JSON格式报告"""
        report_data = {
            'meta': {
                'tool': 'Code Audit Tool',
                'version': '1.0.0',
                'generated_at': datetime.now().isoformat(),
                'target_path': result.target_path,
                'scan_time': result.scan_time,
                'framework': result.framework.value
            },
            'summary': {
                'total_files': result.total_files,
                'scanned_files': result.scanned_files,
                'sources_found': result.sources_found,
                'sinks_found': result.sinks_found,
                'vulnerabilities_count': len(result.vulnerabilities),
                'attack_chains_count': len(result.attack_chains),
                'severity_distribution': result.get_summary()
            },
            'vulnerabilities': [v.to_dict() for v in result.vulnerabilities],
            'attack_chains': [ac.to_dict() for ac in result.attack_chains]
        }
        
        # 确保输出路径有正确的扩展名
        if not output_path.endswith('.json'):
            output_path += '.json'
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return output_path
    
    def _generate_html(self, result: AuditResult, output_path: str) -> str:
        """生成HTML格式报告"""
        # 确保输出路径有正确的扩展名
        if not output_path.endswith('.html'):
            output_path += '.html'
        
        # 读取模板
        template_path = os.path.join(self.templates_dir, 'html', 'report_template.html')
        
        if os.path.exists(template_path):
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        else:
            template = self._get_default_html_template()
        
        # 替换模板变量
        html_content = self._render_html_template(template, result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_markdown(self, result: AuditResult, output_path: str) -> str:
        """生成Markdown格式报告"""
        # 确保输出路径有正确的扩展名
        if not output_path.endswith('.md'):
            output_path += '.md'
        
        # 读取模板
        template_path = os.path.join(self.templates_dir, 'markdown', 'report_template.md')
        
        if os.path.exists(template_path):
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        else:
            template = self._get_default_markdown_template()
        
        # 替换模板变量
        md_content = self._render_markdown_template(template, result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return output_path
    
    def _get_default_html_template(self) -> str:
        """获取默认HTML模板"""
        return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代码安全审计报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #2c3e50; margin-bottom: 20px; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin: 20px 0 10px; }
        h3 { color: #3498db; margin: 15px 0 8px; }
        .summary { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .summary-item { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-item .label { font-size: 14px; color: #666; }
        .summary-item .value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .vulnerability { background: white; margin-bottom: 15px; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid #3498db; }
        .vulnerability.critical { border-left-color: #e74c3c; }
        .vulnerability.high { border-left-color: #e67e22; }
        .vulnerability.medium { border-left-color: #f1c40f; }
        .vulnerability.low { border-left-color: #3498db; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .vuln-id { font-weight: bold; color: #2c3e50; }
        .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; color: white; }
        .severity-badge.critical { background: #e74c3c; }
        .severity-badge.high { background: #e67e22; }
        .severity-badge.medium { background: #f1c40f; }
        .severity-badge.low { background: #3498db; }
        .code-block { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; margin: 10px 0; }
        .call-chain { background: #f8f9fa; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .attack-chain { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .meta { color: #666; font-size: 14px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; }
    </style>
</head>
<body>
    <div class="container">
        <h1>代码安全审计报告</h1>
        <div class="meta">
            <p>生成时间: {{generated_at}}</p>
            <p>目标路径: {{target_path}}</p>
            <p>扫描耗时: {{scan_time}}秒</p>
            <p>检测框架: {{framework}}</p>
        </div>
        
        <div class="summary">
            <h2>审计摘要</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="label">扫描文件数</div>
                    <div class="value">{{scanned_files}}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Source点</div>
                    <div class="value">{{sources_found}}</div>
                </div>
                <div class="summary-item">
                    <div class="label">Sink点</div>
                    <div class="value">{{sinks_found}}</div>
                </div>
                <div class="summary-item">
                    <div class="label">发现漏洞</div>
                    <div class="value">{{vulnerabilities_count}}</div>
                </div>
            </div>
        </div>
        
        <h2>漏洞详情</h2>
        {{vulnerabilities_html}}
        
        {{attack_chains_html}}
    </div>
</body>
</html>'''
    
    def _render_html_template(self, template: str, result: AuditResult) -> str:
        """渲染HTML模板"""
        summary = result.get_summary()
        
        # 生成漏洞HTML
        vulns_html = ""
        for vuln in result.vulnerabilities:
            severity_class = vuln.severity.value
            vulns_html += f'''
        <div class="vulnerability {severity_class}">
            <div class="vuln-header">
                <span class="vuln-id">{vuln.id}: {vuln.name}</span>
                <span class="severity-badge {severity_class}">{vuln.severity.value.upper()}</span>
            </div>
            <p><strong>漏洞类型:</strong> {vuln.vulnerability_type.value}</p>
            <p><strong>CWE:</strong> {vuln.cwe_id}</p>
            <p><strong>Source点:</strong> {vuln.source.function_name}() at {vuln.source.file_path}:{vuln.source.line_number}</p>
            <p><strong>Sink点:</strong> {vuln.sink.function_name}() at {vuln.sink.file_path}:{vuln.sink.line_number}</p>
            
            <h3>调用链</h3>
            <div class="call-chain">
                {' -> '.join([node.function_name for node in vuln.call_chain.nodes]) if vuln.call_chain else '直接调用'}
            </div>
            
            <h3>描述</h3>
            <p>{vuln.description}</p>
            
            <h3>修复建议</h3>
            <p>{vuln.remediation}</p>
            
            {self._generate_poc_html(vuln)}
        </div>
'''
        
        # 生成攻击链HTML
        attack_chains_html = ""
        if result.attack_chains:
            attack_chains_html = "<h2>攻击链分析</h2>"
            for i, chain in enumerate(result.attack_chains):
                attack_chains_html += f'''
            <div class="attack-chain">
                <h3>攻击链 #{i+1}</h3>
                <p><strong>描述:</strong> {chain.description}</p>
                <p><strong>影响:</strong> {chain.impact}</p>
                <p><strong>涉及漏洞:</strong> {', '.join([v.id for v in chain.vulnerabilities])}</p>
                <h4>攻击步骤:</h4>
                <ol>
                    {''.join([f'<li>{step}</li>' for step in chain.steps])}
                </ol>
            </div>
'''
        
        # 替换模板变量
        html = template.replace('{{generated_at}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        html = html.replace('{{target_path}}', result.target_path)
        html = html.replace('{{scan_time}}', f"{result.scan_time:.2f}")
        html = html.replace('{{framework}}', result.framework.value)
        html = html.replace('{{scanned_files}}', str(result.scanned_files))
        html = html.replace('{{sources_found}}', str(result.sources_found))
        html = html.replace('{{sinks_found}}', str(result.sinks_found))
        html = html.replace('{{vulnerabilities_count}}', str(len(result.vulnerabilities)))
        html = html.replace('{{vulnerabilities_html}}', vulns_html)
        html = html.replace('{{attack_chains_html}}', attack_chains_html)
        
        return html
    
    def _generate_poc_html(self, vuln: Vulnerability) -> str:
        """生成PoC的HTML内容"""
        if not vuln.poc:
            return ""
        
        poc = vuln.poc
        return f'''
            <h3>PoC</h3>
            <div class="code-block">
                <pre>{poc.curl_command}</pre>
            </div>
'''
    
    def _get_default_markdown_template(self) -> str:
        """获取默认Markdown模板"""
        return '''# 代码安全审计报告

## 审计信息

- **生成时间**: {{generated_at}}
- **目标路径**: {{target_path}}
- **扫描耗时**: {{scan_time}}秒
- **检测框架**: {{framework}}

## 审计摘要

| 指标 | 数值 |
|------|------|
| 扫描文件数 | {{scanned_files}} |
| Source点 | {{sources_found}} |
| Sink点 | {{sinks_found}} |
| 发现漏洞 | {{vulnerabilities_count}} |

## 漏洞详情

{{vulnerabilities_md}}

{{attack_chains_md}}
'''
    
    def _render_markdown_template(self, template: str, result: AuditResult) -> str:
        """渲染Markdown模板"""
        # 生成漏洞Markdown
        vulns_md = ""
        for vuln in result.vulnerabilities:
            vulns_md += f'''
### {vuln.id}: {vuln.name}

- **漏洞类型**: {vuln.vulnerability_type.value}
- **严重程度**: {vuln.severity.value.upper()}
- **CWE**: {vuln.cwe_id}

#### Source点

- 函数: `{vuln.source.function_name}()`
- 位置: `{vuln.source.file_path}:{vuln.source.line_number}`
- 路由: `{vuln.source.route}` [{vuln.source.http_method}]

#### Sink点

- 函数: `{vuln.sink.function_name}()`
- 位置: `{vuln.sink.file_path}:{vuln.sink.line_number}`

#### 调用链

```
{' -> '.join([node.function_name for node in vuln.call_chain.nodes]) if vuln.call_chain else '直接调用'}
```

#### 描述

{vuln.description}

#### 修复建议

{vuln.remediation}

---
'''
        
        # 生成攻击链Markdown
        attack_chains_md = ""
        if result.attack_chains:
            attack_chains_md = "## 攻击链分析\n\n"
            for i, chain in enumerate(result.attack_chains):
                attack_chains_md += f'''
### 攻击链 #{i+1}

**描述**: {chain.description}

**影响**: {chain.impact}

**涉及漏洞**: {', '.join([v.id for v in chain.vulnerabilities])}

**攻击步骤**:

'''
                for step in chain.steps:
                    attack_chains_md += f"{step}\n\n"
        
        # 替换模板变量
        md = template.replace('{{generated_at}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        md = md.replace('{{target_path}}', result.target_path)
        md = md.replace('{{scan_time}}', f"{result.scan_time:.2f}")
        md = md.replace('{{framework}}', result.framework.value)
        md = md.replace('{{scanned_files}}', str(result.scanned_files))
        md = md.replace('{{sources_found}}', str(result.sources_found))
        md = md.replace('{{sinks_found}}', str(result.sinks_found))
        md = md.replace('{{vulnerabilities_count}}', str(len(result.vulnerabilities)))
        md = md.replace('{{vulnerabilities_md}}', vulns_md)
        md = md.replace('{{attack_chains_md}}', attack_chains_md)
        
        return md
    
    def generate_all_formats(self, result: AuditResult, output_dir: str) -> Dict[str, str]:
        """
        生成所有格式的报告
        
        Args:
            result: 审计结果
            output_dir: 输出目录
            
        Returns:
            生成的报告文件路径字典
        """
        os.makedirs(output_dir, exist_ok=True)
        
        base_name = "audit_report"
        reports = {}
        
        # JSON报告
        json_path = os.path.join(output_dir, f"{base_name}.json")
        reports['json'] = self._generate_json(result, json_path)
        
        # HTML报告
        html_path = os.path.join(output_dir, f"{base_name}.html")
        reports['html'] = self._generate_html(result, html_path)
        
        # Markdown报告
        md_path = os.path.join(output_dir, f"{base_name}.md")
        reports['markdown'] = self._generate_markdown(result, md_path)
        
        return reports
