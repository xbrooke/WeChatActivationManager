@echo off
REM WeChat Activation Manager - Windows 一键启动脚本
REM 项目地址: https://github.com/xbrooke/WeChatActivationManager.git
REM 开发者: 徐大兵
REM 版本: 1.0.0
REM 许可证: MIT
REM 用途: 在 Windows 本地快速启动 Flask 应用用于调试

setlocal enabledelayedexpansion

REM 设置编码为 UTF-8
chcp 65001 >nul

cls
echo.
echo ════════════════════════════════════════════════════════
echo   WeChat Activation Manager - Windows 快速启动脚本
echo ════════════════════════════════════════════════════════
echo.

REM 获取脚本所在目录
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

echo 📁 项目目录: %cd%
echo.

REM 检查 Python 是否已安装
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ 错误: Python 未安装或不在环境变量中
    echo.
    echo 请先安装 Python: https://www.python.org/downloads/
    echo 安装时请勾选 "Add Python to PATH"
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo ✅ %PYTHON_VERSION%
echo.

REM 创建必要的目录
echo 📂 创建必要的目录...
if not exist "logs" mkdir logs
if not exist "data" mkdir data
echo ✅ 目录已准备
echo.

REM 检查 requirements.txt
if not exist "requirements.txt" (
    echo ❌ 错误: requirements.txt 不存在!
    pause
    exit /b 1
)
echo ✅ requirements.txt 已检查
echo.

REM 检查并创建虚拟环境
echo 🐍 检查 Python 虚拟环境...
if not exist "venv" (
    echo ⏳ 创建虚拟环境...
    python -m venv venv
    if errorlevel 1 (
        echo ❌ 虚拟环境创建失败
        pause
        exit /b 1
    )
    echo ✅ 虚拟环境已创建
) else (
    echo ✅ 虚拟环境已存在
)
echo.

REM 激活虚拟环境
echo 🔄 激活虚拟环境...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ 虚拟环境激活失败
    pause
    exit /b 1
)
echo ✅ 虚拟环境已激活
echo.

REM 安装依赖
echo 📦 检查并安装依赖...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo ⚠️  依赖安装出现问题，尝试重新安装...
    pip install --upgrade pip setuptools wheel >nul 2>&1
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ❌ 依赖安装失败，请查看上面的错误信息
        pause
        exit /b 1
    )
)
echo ✅ 依赖已安装
echo.

REM 检查并创建 .env 文件
echo ⚙️  检查环境变量配置...
if not exist ".env" (
    echo ❌ 错误: .env 文件不存在!
    echo 请确保 .env 文件存在于项目根目录
    pause
    exit /b 1
) else (
    echo ✅ .env 文件已存在
)
echo.

REM 显示启动信息
echo ════════════════════════════════════════════════════════
echo   应用启动信息
echo ════════════════════════════════════════════════════════
echo.
echo 🌐 应用地址: http://localhost:5000
echo 🔐 默认账号: admin
echo 🔑 默认密码: admin123
echo 📝 日志文件: logs/app.log
echo.
echo 按 Ctrl+C 停止应用
echo.
echo ════════════════════════════════════════════════════════
echo.

REM 启动应用
echo 🚀 启动 Flask 应用...
python -m flask run --host=0.0.0.0 --port=5000 --debug

REM 如果 Flask run 失败，尝试用 Python 直接运行
if errorlevel 1 (
    echo.
    echo ⚠️  Flask 启动失败，尝试直接运行 app.py...
    python app.py
)

echo.
echo ⏹️  应用已停止
pause
