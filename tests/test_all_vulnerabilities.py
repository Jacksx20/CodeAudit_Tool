#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
包含所有漏洞类型的测试文件
用于验证规则库的完整支持
"""
from flask import Flask, request, redirect, Response
import os
import subprocess
import pickle
import yaml
import json
import xml.etree.ElementTree as ET
import xml.dom.minidom

# 可选导入：ldap 模块（用于 LDAP 注入测试）
try:
    import ldap
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

app = Flask(__name__)

@app.route('/')
def index():
    return "Welcome to Vulnerable App"

# 1. SQL注入
@app.route('/sql_injection')
def sql_injection():
    user_id = request.args.get('id')
    # 危险: SQL注入
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # 执行查询...
    return "SQL injection test"

# 2. 命令注入
@app.route('/command_injection')
def command_injection():
    hostname = request.args.get('host')
    # 危险: 命令注入
    result = subprocess.run(f"ping {hostname}", shell=True, capture_output=True)
    return f"Command: {result.stdout.decode()}"

# 3. 代码注入
@app.route('/code_injection')
def code_injection():
    code = request.args.get('code')
    # 危险: 代码注入
    result = eval(code)
    return f"Code execution: {result}"

# 4. 反序列化
@app.route('/deserialization')
def deserialization():
    data = request.get_data()
    # 危险: 反序列化
    result = pickle.loads(data)
    return f"Deserialization: {result}"

# 5. 路径遍历
@app.route('/path_traversal')
def path_traversal():
    filename = request.args.get('file')
    # 危险: 路径遍历
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"File content: {content}"
    except:
        return "File not found"

# 6. SSRF
@app.route('/ssrf')
def ssrf():
    url = request.args.get('url')
    # 危险: SSRF
    import urllib.request
    response = urllib.request.urlopen(url)
    return f"Response: {response.read()}"

# 7. XSS
@app.route('/xss')
def xss():
    user_input = request.args.get('input')
    # 危险: XSS
    return f"<div>{user_input}</div>"

# 8. XXE (XML注入)
@app.route('/xxe')
def xxe():
    xml_data = request.get_data()
    # 危险: XXE
    root = ET.fromstring(xml_data)
    return f"XML parsed: {root.tag}"

# 9. LDAP注入
@app.route('/ldap_injection')
def ldap_injection():
    if not LDAP_AVAILABLE:
        return "LDAP module not available. Install python-ldap to test LDAP injection."
    filter_str = request.args.get('filter')
    # 危险: LDAP注入
    conn = ldap.initialize('ldap://localhost')
    result = conn.search_s('dc=example,dc=com', filter_str)
    return f"LDAP result: {result}"

# 10. 开放重定向
@app.route('/open_redirect')
def open_redirect():
    target = request.args.get('url')
    # 危险: 开放重定向
    return redirect(target)

# 安全的版本作为对比
@app.route('/safe_sql')
def safe_sql():
    user_id = request.args.get('id')
    # 安全: 参数化查询
    query = "SELECT * FROM users WHERE id = %s"
    # 执行参数化查询...
    return "Safe SQL query"

@app.route('/safe_command')
def safe_command():
    hostname = request.args.get('host')
    # 安全: 列表形式参数
    result = subprocess.run(['ping', hostname], capture_output=True)
    return f"Safe command: {result.stdout.decode()}"

@app.route('/safe_redirect')
def safe_redirect():
    target = request.args.get('url')
    # 安全: 白名单验证
    allowed_urls = ['https://example.com', 'https://trusted.com']
    if target in allowed_urls:
        return redirect(target)
    return "Invalid redirect target"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
