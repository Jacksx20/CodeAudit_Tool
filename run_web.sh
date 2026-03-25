#!/bin/bash

echo "============================================================"
echo "CodeAudit Web应用启动脚本"
echo "============================================================"
echo

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未检测到Python,请先安装Python 3.7+"
    exit 1
fi

# 切换到web目录
cd "$(dirname "$0")/web"

# 检查依赖是否安装
echo "[*] 检查依赖..."
if ! python3 -c "import flask" &> /dev/null; then
    echo "[!] Flask未安装,正在安装依赖..."
    pip3 install -r ../requirements.txt
fi

echo
echo "============================================================"
echo "启动Web服务"
echo "============================================================"
echo "访问地址: http://localhost:5000"
echo "按 Ctrl+C 停止服务"
echo "============================================================"
echo

# 启动Flask应用
python3 app.py
