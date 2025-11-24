# 🚀 安装与配置指南

## 系统要求

- **Python**: 3.8 或更高版本
- **操作系统**: Windows、Linux、macOS
- **数据库**: MySQL 5.7+ 或 SQLite（可选）
- **浏览器**: Chrome、Firefox、Safari 最新版本

## 安装步骤

### 1. 克隆或下载项目

```bash
# 使用 Git
git clone https://github.com/your-username/wechat-activation-manager.git
cd wechat-activation-manager

# 或直接下载 ZIP 文件后解压
```

### 2. 创建虚拟环境（推荐）

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量

```bash
# 复制配置模板
cp .env.example .env

# 编辑 .env 文件，填入你的配置
# 必须配置项：
# - WECHAT_APPID: 你的微信公众号 AppID
# - WECHAT_APPSECRET: 你的微信公众号 AppSecret
# - WECHAT_TOKEN: 你的微信服务器验证 Token
# - ADMIN_PASSWORD: 管理员密码
```

### 5. 初始化数据库（可选）

```bash
# 如果使用数据库模式（USE_DATABASE=true），需要初始化
# 数据库会在首次启动时自动创建表
```

### 6. 运行应用

```bash
# 方式一：直接运行（推荐开发环境）
python app.py

# 方式二：Windows 一键启动脚本
run.bat

# 方式三：使用 Flask CLI
python -m flask run
```

### 7. 访问应用

```
本地地址: http://127.0.0.1:5000
默认账号: admin
默认密码: admin123
```

## 配置选项

### 数据存储方式选择

#### 方式1：JSON 文件存储（默认，推荐用于开发）

```env
USE_DATABASE=false
DATA_DIR=data
CODES_FILE=data/codes.json
USERS_FILE=data/users.json
```

**优点**：无需额外配置，开箱即用  
**缺点**：单机性能，并发能力有限  
**适用场景**：开发测试、小规模应用  

#### 方式2：MySQL 数据库（推荐用于生产）

```env
USE_DATABASE=true
DATABASE_URL=mysql+pymysql://user:password@localhost:3306/database
```

**优点**：高并发、分布式、数据安全  
**缺点**：需要数据库服务  
**适用场景**：生产环境、大规模应用  

#### 方式3：SQLite 数据库（轻量级选项）

```env
USE_DATABASE=true
DATABASE_URL=sqlite:///app.db
```

**优点**：文件存储，易于备份  
**缺点**：并发能力限制  
**适用场景**：单机部署、中等规模应用  

## 必需配置项详解

```env
# Flask 配置
FLASK_ENV=production              # 运行环境
FLASK_SECRET_KEY=your-key-here    # 应用密钥（务必修改）
FLASK_DEBUG=0                     # 生产环境关闭调试

# 微信配置
WECHAT_APPID=your-appid           # 微信公众号 AppID
WECHAT_APPSECRET=your-secret      # 微信公众号 AppSecret
WECHAT_TOKEN=your-token           # 微信服务器验证 Token
WECHAT_ENCODING_AES_KEY=your-key  # 消息加密密钥（可选）

# 服务器配置
SERVER_HOST=0.0.0.0               # 绑定地址
SERVER_PORT=5000                  # 绑定端口
SERVER_WORKERS=4                  # Gunicorn 工作进程

# 认证配置
ADMIN_USERNAME=admin              # 管理员用户名
ADMIN_PASSWORD=your-password      # 管理员密码（务必修改）

# 日志配置
LOG_LEVEL=INFO                    # 日志级别
LOG_FILE=logs/app.log             # 日志文件路径
LOG_TO_CONSOLE=true               # 同时输出到控制台

# 激活码配置
ACTIVATION_CODE_EXPIRE_DAYS=1     # 普通码有效期（天）
VIP_CODE_EXPIRE_DAYS=30           # VIP码有效期（天）
BATCH_GENERATE_MAX_COUNT=1000     # 最大批量生成数量

# 时区
TIMEZONE=Asia/Shanghai            # 中国时区
```

## 常见问题

### 应用启动失败

```bash
# 检查依赖
pip install -r requirements.txt

# 查看日志
tail -f logs/app.log
```

### 数据库连接失败

```bash
# 检查配置是否正确
grep DATABASE_URL .env

# 确保数据库服务器可访问
mysql -h <your-host> -u <your-user> -p -D <your-database>
```

### 微信消息无法接收

1. 检查 Token 配置是否与微信后台一致
2. 确保服务器 URL 已配置在微信后台
3. 查看应用日志中的"微信验证"记录

