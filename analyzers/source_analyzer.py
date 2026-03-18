# -*- coding: utf-8 -*-
"""
Source点分析器 - 识别HTTP入口点
支持Flask、Django、FastAPI、Express、Spring、Gin等框架
"""
import os
import re
import ast
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import SourcePoint, Framework, Config


class SourceAnalyzer:
    """Source点分析器"""
    
    def __init__(self, config: Config):
        self.config = config
        self.sources: List[SourcePoint] = []
        self.detected_frameworks: Set[Framework] = set()
        
        # 框架检测模式
        self.framework_indicators = {
            Framework.FLASK: ['from flask', 'import flask', '@app.route', 'Flask(__name__)'],
            Framework.DJANGO: ['from django', 'import django', 'django.http', 'django.views'],
            Framework.FASTAPI: ['from fastapi', 'import fastapi', '@app.get', '@app.post', 'FastAPI()'],
            Framework.EXPRESS: ['express()', 'require("express")', "require('express')", 'router.'],
            Framework.SPRING: ['@RequestMapping', '@GetMapping', '@PostMapping', '@RestController'],
            Framework.GIN: ['gin.Default()', 'gin.New()', 'r.GET', 'r.POST', 'router.']
        }
        
        # 参数提取模式
        self.param_patterns = {
            Framework.FLASK: [
                r'request\.args\.get\s*\(\s*["\'](\w+)["\']',
                r'request\.form\.get\s*\(\s*["\'](\w+)["\']',
                r'request\.json\.get\s*\(\s*["\'](\w+)["\']',
                r'request\.values\.get\s*\(\s*["\'](\w+)["\']',
                r'request\.data',
                r'request\.files\.get\s*\(\s*["\'](\w+)["\']',
            ],
            Framework.DJANGO: [
                r'request\.GET\.get\s*\(\s*["\'](\w+)["\']',
                r'request\.POST\.get\s*\(\s*["\'](\w+)["\']',
                r'request\.body',
                r'request\.data',
                r'request\.FILES\.get\s*\(\s*["\'](\w+)["\']',
            ],
            Framework.FASTAPI: [
                r'(\w+)\s*:\s*(?:str|int|float|bool)\s*=\s*(?:Query|Path|Form|Body)',
                r'(\w+)\s*:\s*(?:str|int|float|bool)',
            ],
            Framework.EXPRESS: [
                r'req\.query\.(\w+)',
                r'req\.body\.(\w+)',
                r'req\.params\.(\w+)',
            ],
            Framework.SPRING: [
                r'@RequestParam\s*\(\s*["\'](\w+)["\']',
                r'@PathVariable\s*\(\s*["\'](\w+)["\']',
                r'@RequestBody',
            ],
            Framework.GIN: [
                r'c\.Query\s*\(\s*["\'](\w+)["\']',
                r'c\.PostForm\s*\(\s*["\'](\w+)["\']',
                r'c\.Param\s*\(\s*["\'](\w+)["\']',
            ]
        }
    
    def analyze(self, target_path: str) -> List[SourcePoint]:
        """分析目标路径，识别所有Source点"""
        self.sources = []
        self.detected_frameworks = set()
        
        # 检查是文件还是目录
        if os.path.isfile(target_path):
            # 单个文件
            ext = os.path.splitext(target_path)[1].lower()
            if ext in self.config.supported_extensions:
                self._analyze_file(target_path)
        else:
            # 遍历所有文件
            for root, dirs, files in os.walk(target_path):
                # 排除特定目录
                dirs[:] = [d for d in dirs if d not in self.config.exclude_dirs]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    ext = os.path.splitext(file)[1].lower()
                    
                    if ext in self.config.supported_extensions:
                        self._analyze_file(file_path)
        
        return self.sources
    
    def _analyze_file(self, file_path: str):
        """分析单个文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return
        
        # 检测框架
        framework = self._detect_framework(content)
        if framework == Framework.GENERIC:
            return
        
        self.detected_frameworks.add(framework)
        
        # 根据框架类型选择分析方法
        if framework in [Framework.FLASK, Framework.DJANGO, Framework.FASTAPI]:
            self._analyze_python_file(file_path, content, lines, framework)
        elif framework == Framework.EXPRESS:
            self._analyze_javascript_file(file_path, content, lines, framework)
        elif framework == Framework.SPRING:
            self._analyze_java_file(file_path, content, lines, framework)
        elif framework == Framework.GIN:
            self._analyze_go_file(file_path, content, lines, framework)
    
    def _detect_framework(self, content: str) -> Framework:
        """检测代码使用的框架"""
        for framework, indicators in self.framework_indicators.items():
            for indicator in indicators:
                if indicator in content:
                    return framework
        return Framework.GENERIC
    
    def _analyze_python_file(self, file_path: str, content: str, lines: List[str], framework: Framework):
        """分析Python文件(Flask/Django/FastAPI)"""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # 如果AST解析失败，使用正则表达式
            self._analyze_with_regex(file_path, content, lines, framework)
            return
        
        # 遍历AST
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._analyze_python_function(node, file_path, lines, framework)
            elif isinstance(node, ast.AsyncFunctionDef):
                self._analyze_python_function(node, file_path, lines, framework, is_async=True)
    
    def _analyze_python_function(self, node, file_path: str, lines: List[str], 
                                  framework: Framework, is_async: bool = False):
        """分析Python函数定义"""
        # 获取装饰器
        decorators = []
        for decorator in node.decorator_list:
            decorator_str = self._get_decorator_string(decorator)
            decorators.append(decorator_str)
        
        # 检查是否是路由处理函数
        route_info = self._extract_route_info(decorators, framework, node.name)
        if not route_info:
            return
        
        route, http_methods = route_info
        
        # 提取参数
        parameters = self._extract_python_parameters(node, framework)
        
        # 获取代码片段
        start_line = node.lineno - 1
        end_line = min(node.end_lineno or start_line + 20, len(lines))
        code_snippet = '\n'.join(lines[start_line:end_line])
        
        # 创建Source点
        source = SourcePoint(
            file_path=file_path,
            line_number=node.lineno,
            function_name=node.name,
            framework=framework,
            route=route,
            http_method=','.join(http_methods) if http_methods else 'GET',
            parameters=parameters,
            code_snippet=code_snippet,
            decorators=decorators,
            class_name=None
        )
        
        self.sources.append(source)
    
    def _get_decorator_string(self, decorator) -> str:
        """获取装饰器字符串"""
        if isinstance(decorator, ast.Name):
            return f"@{decorator.id}"
        elif isinstance(decorator, ast.Attribute):
            return f"@{self._get_attribute_string(decorator)}"
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                return f"@{decorator.func.id}(...)"
            elif isinstance(decorator.func, ast.Attribute):
                attr_str = self._get_attribute_string(decorator.func)
                # 提取参数
                args_str = ""
                if decorator.args:
                    args_str = ", ".join([self._get_arg_string(arg) for arg in decorator.args])
                return f"@{attr_str}({args_str})"
        return ""
    
    def _get_arg_string(self, arg) -> str:
        """获取参数字符串"""
        if isinstance(arg, ast.Constant):
            return repr(arg.value)
        elif isinstance(arg, ast.Str):  # Python 3.7兼容
            return repr(arg.s)
        return "..."
    
    def _get_attribute_string(self, node) -> str:
        """获取属性访问字符串"""
        if isinstance(node, ast.Attribute):
            return f"{self._get_attribute_string(node.value)}.{node.attr}"
        elif isinstance(node, ast.Name):
            return node.id
        return ""
    
    def _extract_route_info(self, decorators: List[str], framework: Framework, 
                           func_name: str) -> Optional[Tuple[str, List[str]]]:
        """从装饰器中提取路由信息"""
        for decorator in decorators:
            if framework == Framework.FLASK:
                # Flask: @app.route('/path') 或 @app.route('/path', methods=['POST'])
                match = re.search(r'@.*\.route\s*\(\s*["\']([^"\']+)["\']', decorator)
                if match:
                    route = match.group(1)
                    methods = ['GET']
                    method_match = re.search(r'methods\s*=\s*\[([^\]]+)\]', decorator)
                    if method_match:
                        methods = re.findall(r'["\'](\w+)["\']', method_match.group(1))
                    return route, methods
            
            elif framework == Framework.FASTAPI:
                # FastAPI: @app.get('/path'), @app.post('/path')
                match = re.search(r'@.*\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', decorator, re.I)
                if match:
                    method = match.group(1).upper()
                    route = match.group(2)
                    return route, [method]
        
        # Django视图函数
        if framework == Framework.DJANGO:
            # 检查函数名是否包含常见视图后缀
            if any(suffix in func_name.lower() for suffix in ['view', 'api', 'handler', 'endpoint']):
                return f'/{func_name}', ['GET', 'POST']
        
        return None
    
    def _extract_python_parameters(self, node, framework: Framework) -> List[str]:
        """从Python函数中提取参数"""
        parameters = []
        
        for arg in node.args.args:
            param_name = arg.arg
            if param_name not in ['self', 'cls', 'request']:
                parameters.append(param_name)
        
        return parameters
    
    def _analyze_javascript_file(self, file_path: str, content: str, 
                                  lines: List[str], framework: Framework):
        """分析JavaScript文件(Express)"""
        # Express路由模式: app.get('/path', handler) 或 router.get('/path', handler)
        patterns = [
            r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.I):
                method = match.group(1).upper()
                route = match.group(2)
                line_num = content[:match.start()].count('\n') + 1
                
                # 提取参数
                parameters = self._extract_js_parameters(content, match.start())
                
                # 获取代码片段
                start_line = max(0, line_num - 1)
                end_line = min(len(lines), line_num + 10)
                code_snippet = '\n'.join(lines[start_line:end_line])
                
                source = SourcePoint(
                    file_path=file_path,
                    line_number=line_num,
                    function_name=f'anonymous_handler_{line_num}',
                    framework=framework,
                    route=route,
                    http_method=method,
                    parameters=parameters,
                    code_snippet=code_snippet
                )
                
                self.sources.append(source)
    
    def _extract_js_parameters(self, content: str, start_pos: int) -> List[str]:
        """从Express路由处理函数中提取参数"""
        parameters = []
        
        # 查找req.query.xxx, req.body.xxx, req.params.xxx
        handler_content = content[start_pos:start_pos + 2000]
        
        for pattern in [r'req\.query\.(\w+)', r'req\.body\.(\w+)', r'req\.params\.(\w+)']:
            for match in re.finditer(pattern, handler_content):
                param = match.group(1)
                if param not in parameters:
                    parameters.append(param)
        
        return parameters
    
    def _analyze_java_file(self, file_path: str, content: str, 
                          lines: List[str], framework: Framework):
        """分析Java文件(Spring)"""
        # Spring注解模式
        patterns = [
            (r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*["\']([^"\']+)["\']', 'method_from_annotation'),
            (r'@RequestMapping\s*\([^)]*value\s*=\s*["\']([^"\']+)["\']', 'mixed'),
        ]
        
        for pattern, method_type in patterns:
            for match in re.finditer(pattern, content):
                route = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                # 确定HTTP方法
                if 'GetMapping' in content[max(0, match.start()-20):match.start()]:
                    http_method = 'GET'
                elif 'PostMapping' in content[max(0, match.start()-20):match.start()]:
                    http_method = 'POST'
                elif 'PutMapping' in content[max(0, match.start()-20):match.start()]:
                    http_method = 'PUT'
                elif 'DeleteMapping' in content[max(0, match.start()-20):match.start()]:
                    http_method = 'DELETE'
                else:
                    http_method = 'GET'
                
                # 查找方法名
                method_match = re.search(r'public\s+\w+\s+(\w+)\s*\(', content[match.start():match.start()+500])
                func_name = method_match.group(1) if method_match else 'unknown'
                
                # 提取参数
                parameters = self._extract_java_parameters(content[match.start():match.start()+500])
                
                # 获取代码片段
                start_line = max(0, line_num - 1)
                end_line = min(len(lines), line_num + 15)
                code_snippet = '\n'.join(lines[start_line:end_line])
                
                source = SourcePoint(
                    file_path=file_path,
                    line_number=line_num,
                    function_name=func_name,
                    framework=framework,
                    route=route,
                    http_method=http_method,
                    parameters=parameters,
                    code_snippet=code_snippet
                )
                
                self.sources.append(source)
    
    def _extract_java_parameters(self, content: str) -> List[str]:
        """从Spring方法中提取参数"""
        parameters = []
        
        patterns = [
            r'@RequestParam\s*\(\s*["\'](\w+)["\']',
            r'@PathVariable\s*\(\s*["\'](\w+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                param = match.group(1)
                if param not in parameters:
                    parameters.append(param)
        
        return parameters
    
    def _analyze_go_file(self, file_path: str, content: str, 
                        lines: List[str], framework: Framework):
        """分析Go文件(Gin)"""
        # Gin路由模式: r.GET("/path", handler) 或 router.GET("/path", handler)
        pattern = r'(?:r|router)\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*["\']([^"\']+)["\']'
        
        for match in re.finditer(pattern, content):
            method = match.group(1)
            route = match.group(2)
            line_num = content[:match.start()].count('\n') + 1
            
            # 查找处理函数名
            handler_match = re.search(r',\s*(\w+)', content[match.start():match.start()+100])
            func_name = handler_match.group(1) if handler_match else 'anonymous'
            
            # 提取参数
            parameters = self._extract_go_parameters(content, match.start())
            
            # 获取代码片段
            start_line = max(0, line_num - 1)
            end_line = min(len(lines), line_num + 10)
            code_snippet = '\n'.join(lines[start_line:end_line])
            
            source = SourcePoint(
                file_path=file_path,
                line_number=line_num,
                function_name=func_name,
                framework=framework,
                route=route,
                http_method=method,
                parameters=parameters,
                code_snippet=code_snippet
            )
            
            self.sources.append(source)
    
    def _extract_go_parameters(self, content: str, start_pos: int) -> List[str]:
        """从Gin处理函数中提取参数"""
        parameters = []
        
        # 查找c.Query, c.PostForm, c.Param
        handler_content = content[start_pos:start_pos + 2000]
        
        patterns = [
            r'c\.Query\s*\(\s*["\'](\w+)["\']',
            r'c\.PostForm\s*\(\s*["\'](\w+)["\']',
            r'c\.Param\s*\(\s*["\'](\w+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, handler_content):
                param = match.group(1)
                if param not in parameters:
                    parameters.append(param)
        
        return parameters
    
    def _analyze_with_regex(self, file_path: str, content: str, 
                           lines: List[str], framework: Framework):
        """使用正则表达式分析文件(当AST解析失败时)"""
        # 简化的路由检测
        if framework == Framework.FLASK:
            pattern = r'@.*\.route\s*\(\s*["\']([^"\']+)["\']'
            for match in re.finditer(pattern, content):
                route = match.group(1)
                line_num = content[:match.start()].count('\n') + 1
                
                # 查找函数名
                func_match = re.search(r'def\s+(\w+)\s*\(', content[match.start():match.start()+200])
                func_name = func_match.group(1) if func_match else 'unknown'
                
                start_line = max(0, line_num - 1)
                end_line = min(len(lines), line_num + 10)
                code_snippet = '\n'.join(lines[start_line:end_line])
                
                source = SourcePoint(
                    file_path=file_path,
                    line_number=line_num,
                    function_name=func_name,
                    framework=framework,
                    route=route,
                    http_method='GET',
                    parameters=[],
                    code_snippet=code_snippet
                )
                
                self.sources.append(source)
    
    def get_detected_frameworks(self) -> Set[Framework]:
        """获取检测到的框架"""
        return self.detected_frameworks
