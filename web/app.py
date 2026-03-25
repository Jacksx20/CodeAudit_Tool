# -*- coding: utf-8 -*-
"""
CodeAudit Web应用 - 代码安全审计Web界面
"""
import os
import sys
import json
import shutil
import zipfile
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# 添加项目根目录到路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from flask import Flask, request, jsonify, render_template, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from core.config import Config, AuditResult
from core.audit_engine import AuditEngine
from generators.poc_generator import PoCGenerator
from reports.report_generator import ReportGenerator

# 尝试导入大模型分析器
try:
    from web.llm_analyzer import LLMAuditAnalyzer
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    print("[!] 警告: 大模型分析器未安装,将使用基础审计功能")

app = Flask(__name__)
CORS(app)

# 配置
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 最大100MB
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['RESULT_FOLDER'] = os.path.join(os.path.dirname(__file__), 'results')
app.config['ALLOWED_EXTENSIONS'] = {'zip', 'py', 'js', 'java', 'go', 'php', 'cs', 'ts', 'rb', 'jsp', 'asp', 'aspx', 'cshtml'}
app.config['SECRET_KEY'] = 'codeaudit-secret-key-2024'

# 确保目录存在
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# 全局配置
audit_config = Config()
audit_engine = AuditEngine(audit_config)
report_generator = ReportGenerator(audit_config)

# 大模型分析器实例
llm_analyzer = None
if LLM_AVAILABLE:
    try:
        llm_analyzer = LLMAuditAnalyzer()
    except Exception as e:
        print(f"[!] 大模型分析器初始化失败: {e}")


def allowed_file(filename: str) -> bool:
    """检查文件扩展名是否允许"""
    if '.' in filename:
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in app.config['ALLOWED_EXTENSIONS']
    return False


def extract_archive(file_path: str, extract_to: str) -> bool:
    """解压压缩包"""
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            return True
        return False
    except Exception as e:
        print(f"解压失败: {e}")
        return False


def get_file_stats(directory: str) -> Dict[str, Any]:
    """获取目录文件统计信息"""
    stats = {
        'total_files': 0,
        'by_extension': {},
        'total_size': 0,
        'files': []
    }
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
                ext = os.path.splitext(file)[1].lower()
                
                stats['total_files'] += 1
                stats['total_size'] += size
                
                if ext not in stats['by_extension']:
                    stats['by_extension'][ext] = 0
                stats['by_extension'][ext] += 1
                
                # 只保存前100个文件信息
                if len(stats['files']) < 100:
                    rel_path = os.path.relpath(file_path, directory)
                    stats['files'].append({
                        'path': rel_path,
                        'size': size,
                        'extension': ext
                    })
            except Exception:
                continue
    
    return stats


def perform_audit(target_path: str, task_id: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """执行代码审计"""
    options = options or {}
    
    result_data = {
        'task_id': task_id,
        'status': 'processing',
        'start_time': datetime.now().isoformat(),
        'end_time': None,
        'error': None,
        'audit_result': None,
        'llm_analysis': None
    }
    
    try:
        # 1. 执行基础审计
        print(f"[{task_id}] 开始基础审计...")
        audit_result = audit_engine.audit(
            target_path,
            enable_forward=options.get('enable_forward', True),
            enable_reverse=options.get('enable_reverse', True),
            enable_attack_chain=options.get('enable_attack_chain', True)
        )
        
        result_data['audit_result'] = {
            'target_path': audit_result.target_path,
            'framework': audit_result.framework.value,
            'total_files': audit_result.total_files,
            'scanned_files': audit_result.scanned_files,
            'scan_time': audit_result.scan_time,
            'sources_found': audit_result.sources_found,
            'sinks_found': audit_result.sinks_found,
            'vulnerabilities': [],
            'summary': audit_result.get_summary(),
            'attack_chains': []
        }
        
        # 转换漏洞信息
        for vuln in audit_result.vulnerabilities:
            vuln_data = {
                'id': vuln.id,
                'name': vuln.name,
                'type': vuln.vulnerability_type.value,
                'severity': vuln.severity.value,
                'cwe_id': vuln.cwe_id,
                'description': vuln.description,
                'source': {
                    'file_path': vuln.source.file_path,
                    'line_number': vuln.source.line_number,
                    'function_name': vuln.source.function_name,
                    'route': vuln.source.route,
                    'http_method': vuln.source.http_method
                },
                'sink': {
                    'file_path': vuln.sink.file_path,
                    'line_number': vuln.sink.line_number,
                    'function_name': vuln.sink.function_name,
                    'dangerous_function': vuln.sink.function_name  # 使用function_name作为dangerous_function
                },
                'call_chain': None,
                'poc_code': vuln.poc.python_code if vuln.poc else None,  # 从poc对象获取python_code
                'remediation': vuln.remediation
            }
            
            if vuln.call_chain:
                vuln_data['call_chain'] = {
                    'nodes': [
                        {
                            'function_name': node.function_name,
                            'file_path': node.file_path,
                            'line_number': node.line_number
                        }
                        for node in vuln.call_chain.nodes
                    ],
                    'is_complete': vuln.call_chain.is_complete
                }
            
            result_data['audit_result']['vulnerabilities'].append(vuln_data)
        
        # 转换攻击链信息
        for chain in audit_result.attack_chains:
            chain_data = {
                'description': chain.description,
                'impact': chain.impact,
                'vulnerabilities': [v.id for v in chain.vulnerabilities],
                'poc_code': None  # AttackChain没有poc_code属性,设为None
            }
            result_data['audit_result']['attack_chains'].append(chain_data)
        
        # 2. 大模型增强分析
        if options.get('enable_llm', False):
            print(f"[{task_id}] 开始大模型分析...")
            try:
                # 获取大模型配置
                llm_config = options.get('llm_config', {})
                
                # 动态创建大模型分析器
                if llm_config:
                    from web.llm_analyzer import LLMAuditAnalyzer
                    dynamic_llm_analyzer = LLMAuditAnalyzer(
                        api_key=llm_config.get('api_key'),
                        model=llm_config.get('model'),
                        base_url=llm_config.get('base_url')
                    )
                    
                    if dynamic_llm_analyzer.client:
                        llm_result = dynamic_llm_analyzer.analyze_audit_result(
                            audit_result,
                            target_path,
                            options.get('llm_options', {})
                        )
                        result_data['llm_analysis'] = llm_result
                    else:
                        result_data['llm_analysis'] = {
                            'error': '大模型客户端初始化失败,请检查API配置',
                            'status': 'failed'
                        }
                else:
                    result_data['llm_analysis'] = {
                        'error': '未提供大模型配置',
                        'status': 'failed'
                    }
            except Exception as e:
                print(f"[{task_id}] 大模型分析失败: {e}")
                import traceback
                traceback.print_exc()
                result_data['llm_analysis'] = {
                    'error': str(e),
                    'status': 'failed'
                }
        
        # 3. 生成报告
        if options.get('generate_report', True):
            print(f"[{task_id}] 生成报告...")
            report_dir = os.path.join(app.config['RESULT_FOLDER'], task_id)
            os.makedirs(report_dir, exist_ok=True)
            
            reports = report_generator.generate_all_formats(audit_result, report_dir)
            result_data['reports'] = {
                'json': os.path.basename(reports.get('json', '')),
                'html': os.path.basename(reports.get('html', '')),
                'markdown': os.path.basename(reports.get('markdown', ''))
            }
        
        result_data['status'] = 'completed'
        
    except Exception as e:
        print(f"[{task_id}] 审计失败: {e}")
        import traceback
        traceback.print_exc()
        result_data['status'] = 'failed'
        result_data['error'] = str(e)
    
    result_data['end_time'] = datetime.now().isoformat()
    
    # 保存结果
    result_file = os.path.join(app.config['RESULT_FOLDER'], task_id, 'result.json')
    os.makedirs(os.path.dirname(result_file), exist_ok=True)
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, ensure_ascii=False, indent=2)
    
    return result_data


@app.route('/')
def index():
    """主页"""
    return render_template('index.html', llm_available=LLM_AVAILABLE)


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """上传代码文件"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': '未找到文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '未选择文件'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': f'不支持的文件类型,支持的类型: {", ".join(app.config["ALLOWED_EXTENSIONS"])}'}), 400
        
        # 生成任务ID
        task_id = str(uuid.uuid4())
        task_dir = os.path.join(app.config['UPLOAD_FOLDER'], task_id)
        os.makedirs(task_dir, exist_ok=True)
        
        # 保存文件
        filename = secure_filename(file.filename)
        file_path = os.path.join(task_dir, filename)
        file.save(file_path)
        
        # 如果是压缩包,解压
        target_path = task_dir
        if filename.endswith('.zip'):
            extract_dir = os.path.join(task_dir, 'extracted')
            os.makedirs(extract_dir, exist_ok=True)
            if extract_archive(file_path, extract_dir):
                target_path = extract_dir
            else:
                return jsonify({'error': '解压失败'}), 500
        
        # 获取文件统计
        file_stats = get_file_stats(target_path)
        
        return jsonify({
            'task_id': task_id,
            'filename': filename,
            'file_stats': file_stats,
            'target_path': target_path,
            'message': '文件上传成功'
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/audit', methods=['POST'])
def start_audit():
    """开始审计"""
    try:
        data = request.get_json()
        task_id = data.get('task_id')
        target_path = data.get('target_path')
        options = data.get('options', {})
        
        if not task_id or not target_path:
            return jsonify({'error': '缺少必要参数'}), 400
        
        if not os.path.exists(target_path):
            return jsonify({'error': '目标路径不存在'}), 400
        
        # 执行审计
        result = perform_audit(target_path, task_id, options)
        
        return jsonify(result)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/result/<task_id>')
def get_result(task_id):
    """获取审计结果"""
    try:
        result_file = os.path.join(app.config['RESULT_FOLDER'], task_id, 'result.json')
        if not os.path.exists(result_file):
            return jsonify({'error': '结果不存在'}), 404
        
        with open(result_file, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/<task_id>/<format_type>')
def download_report(task_id, format_type):
    """下载报告"""
    try:
        report_dir = os.path.join(app.config['RESULT_FOLDER'], task_id)
        
        if format_type == 'json':
            filename = f'audit_report.json'
        elif format_type == 'html':
            filename = f'audit_report.html'
        elif format_type == 'markdown' or format_type == 'md':
            filename = f'audit_report.md'
        else:
            return jsonify({'error': '不支持的报告格式'}), 400
        
        file_path = os.path.join(report_dir, filename)
        if not os.path.exists(file_path):
            # 尝试查找实际生成的报告文件
            for f in os.listdir(report_dir):
                if f.endswith(f'.{format_type}'):
                    file_path = os.path.join(report_dir, f)
                    break
        
        if not os.path.exists(file_path):
            return jsonify({'error': '报告文件不存在'}), 404
        
        return send_file(file_path, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tasks')
def list_tasks():
    """列出所有任务"""
    try:
        tasks = []
        result_dir = app.config['RESULT_FOLDER']
        
        for task_id in os.listdir(result_dir):
            task_dir = os.path.join(result_dir, task_id)
            result_file = os.path.join(task_dir, 'result.json')
            
            if os.path.isdir(task_dir) and os.path.exists(result_file):
                with open(result_file, 'r', encoding='utf-8') as f:
                    result = json.load(f)
                
                tasks.append({
                    'task_id': task_id,
                    'status': result.get('status'),
                    'start_time': result.get('start_time'),
                    'end_time': result.get('end_time'),
                    'vulnerabilities_count': len(result.get('audit_result', {}).get('vulnerabilities', []))
                })
        
        # 按时间排序
        tasks.sort(key=lambda x: x['start_time'], reverse=True)
        
        return jsonify({'tasks': tasks})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/llm/status')
def llm_status():
    """获取大模型状态"""
    return jsonify({
        'available': LLM_AVAILABLE,
        'initialized': llm_analyzer is not None
    })


@app.route('/static/<path:filename>')
def serve_static(filename):
    """提供静态文件"""
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'static'), filename)


if __name__ == '__main__':
    print("="*60)
    print("CodeAudit Web应用启动")
    print("="*60)
    llm_status_text = "已启用" if LLM_AVAILABLE else "未启用"
    print(f"大模型支持: {llm_status_text}")
    print(f"上传目录: {app.config['UPLOAD_FOLDER']}")
    print(f"结果目录: {app.config['RESULT_FOLDER']}")
    print("="*60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
