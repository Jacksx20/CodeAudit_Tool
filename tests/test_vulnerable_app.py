# -*- coding: utf-8 -*-
"""
示例Flask应用 - 包含多种安全漏洞用于测试
"""
from flask import Flask, request, render_template_string, send_file
import sqlite3
import os
import subprocess
import pickle
import yaml

app = Flask(__name__)


@app.route('/')
def index():
    return "Welcome to Vulnerable App"


@app.route('/user/<user_id>')
def get_user(user_id):
    """SQL注入漏洞示例"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 漏洞: 直接拼接用户输入到SQL查询
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return str(user)


@app.route('/search')
def search():
    """SQL注入漏洞示例 - 使用request.args"""
    keyword = request.args.get('q', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 漏洞: 使用字符串格式化构建SQL查询
    query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return str(results)


@app.route('/cmd')
def execute_command():
    """命令注入漏洞示例"""
    cmd = request.args.get('cmd', '')
    
    # 漏洞: 直接执行用户输入的命令
    result = os.system(cmd)
    return f"Command executed: {result}"


@app.route('/ping')
def ping():
    """命令注入漏洞示例 - subprocess"""
    host = request.args.get('host', '')
    
    # 漏洞: 使用shell=True执行用户输入
    result = subprocess.run(f"ping -c 4 {host}", shell=True, capture_output=True)
    return result.stdout.decode()


@app.route('/read')
def read_file():
    """路径遍历漏洞示例"""
    filename = request.args.get('file', '')
    
    # 漏洞: 直接使用用户输入作为文件路径
    with open('/var/www/data/' + filename, 'r') as f:
        content = f.read()
    
    return content


@app.route('/download')
def download():
    """路径遍历漏洞示例 - send_file"""
    filepath = request.args.get('path', '')
    
    # 漏洞: send_file使用用户输入的路径
    return send_file(filepath)


@app.route('/fetch')
def fetch_url():
    """SSRF漏洞示例"""
    import urllib.request
    
    url = request.args.get('url', '')
    
    # 漏洞: 直接请求用户提供的URL
    response = urllib.request.urlopen(url)
    return response.read()


@app.route('/greet')
def greet():
    """XSS漏洞示例"""
    name = request.args.get('name', '')
    
    # 漏洞: 直接将用户输入渲染到模板
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route('/comment', methods=['POST'])
def add_comment():
    """XSS漏洞示例 - POST"""
    comment = request.form.get('comment', '')
    
    # 漏洞: 未转义用户输入
    html = f"<div class='comment'>{comment}</div>"
    return html


@app.route('/load_data', methods=['POST'])
def load_data():
    """反序列化漏洞示例 - pickle"""
    data = request.data
    
    # 漏洞: 反序列化用户提供的pickle数据
    obj = pickle.loads(data)
    return str(obj)


@app.route('/parse_config', methods=['POST'])
def parse_config():
    """反序列化漏洞示例 - yaml"""
    config = request.data.decode('utf-8')
    
    # 漏洞: 使用不安全的yaml.load
    data = yaml.load(config, Loader=yaml.Loader)
    return str(data)


@app.route('/eval')
def eval_code():
    """代码注入漏洞示例"""
    code = request.args.get('code', '')
    
    # 漏洞: 执行用户提供的代码
    result = eval(code)
    return str(result)


@app.route('/exec')
def exec_code():
    """代码注入漏洞示例 - exec"""
    code = request.args.get('code', '')
    
    # 漏洞: 执行用户提供的代码
    exec(code)
    return "Code executed"


# 安全示例 - 用于对比

@app.route('/safe_user/<user_id>')
def get_user_safe(user_id):
    """安全的SQL查询示例"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 安全: 使用参数化查询
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    user = cursor.fetchone()
    conn.close()
    return str(user)


@app.route('/safe_ping')
def ping_safe():
    """安全的命令执行示例"""
    host = request.args.get('host', '')
    
    # 安全: 使用列表形式，shell=False
    result = subprocess.run(['ping', '-c', '4', host], shell=False, capture_output=True)
    return result.stdout.decode()


if __name__ == '__main__':
    app.run(debug=True)
