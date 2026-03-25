@echo off
chcp 65001 >nul
echo ============================================================
echo CodeAudit Web应用启动脚本
echo ============================================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到Python,请先安装Python 3.7+
    pause
    exit /b 1
)

REM 切换到web目录
cd /d "%~dp0web"

REM 检查依赖是否安装
echo [*] 检查依赖...
pip show flask >nul 2>&1
if errorlevel 1 (
    echo [!] Flask未安装,正在安装依赖...
    pip install -r ..\requirements.txt
)

echo.
echo ============================================================
echo 启动Web服务
echo ============================================================
echo 访问地址: http://localhost:5000
echo 按 Ctrl+C 停止服务
echo ============================================================
echo.

REM 启动Flask应用
python app.py

pause
