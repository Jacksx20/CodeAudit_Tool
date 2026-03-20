# -*- coding: utf-8 -*-
"""
代码安全审计工具
"""
from .core.config import Config, AuditResult, Vulnerability
from .core.audit_engine import AuditEngine
from .analyzers import SourceAnalyzer, SinkAnalyzer, CallChainAnalyzer
from .generators import PoCGenerator
from .reports import ReportGenerator

__version__ = '1.1.2'
__author__ = 'Code Audit Tool'

__all__ = [
    'Config',
    'AuditResult',
    'Vulnerability',
    'AuditEngine',
    'SourceAnalyzer',
    'SinkAnalyzer',
    'CallChainAnalyzer',
    'PoCGenerator',
    'ReportGenerator'
]
