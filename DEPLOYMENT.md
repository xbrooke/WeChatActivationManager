# 🚀 部署指南

## 本地开发

```bash
# 1. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 4. 运行应用
python app.py
# 访问 http://localhost:5000
```

---

## 生产环境部署

### 方案1：Gunicorn + Nginx

#### 安装 Gunicorn

```bash
pip install gunicorn
```

#### 启动应用

```bash
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 app:app
```

#### Nginx 配置示例

```nginx
upstream wechat_app {
    server 127.0.0.1:5000;
    keepalive 32;
}

server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://wechat_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 静态文件不需要代理
    location /static {
        alias /path/to/project/static;
        expires 7d;
    }
}
```

### 方案2：Docker 部署

#### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

#### 构建与运行

```bash
# 构建镜像
docker build -t wechat-activation-manager:latest .

# 运行容器
docker run -d \
  --name wechat \
  -p 5000:5000 \
  --env-file .env \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/data:/app/data \
  wechat-activation-manager:latest
```

### 方案3：systemd 服务（Linux）

#### 创建服务文件

`/etc/systemd/system/wechat.service`:

```ini
[Unit]
Description=WeChat Activation Manager
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/path/to/project
Environment="PATH=/path/to/project/venv/bin"
ExecStart=/path/to/project/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl start wechat
sudo systemctl enable wechat
```

---

## HTTPS 配置

### 使用 Let's Encrypt（推荐）

```bash
# 安装 Certbot
sudo apt-get install certbot python3-certbot-nginx

# 获取证书
sudo certbot certonly --standalone -d your-domain.com

# 更新 Nginx 配置
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # ... 其他配置 ...
}

# HTTP 重定向到 HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 数据备份

### 数据库备份

#### MySQL

```bash
# 备份
mysqldump -u username -p database_name > backup_$(date +%Y%m%d).sql

# 恢复
mysql -u username -p database_name < backup_20250101.sql
```

#### SQLite

```bash
# 备份（简单复制）
cp app.db backup_app_$(date +%Y%m%d).db
```

### 应用数据备份

```bash
# 备份所有数据文件
tar -czf backup_data_$(date +%Y%m%d).tar.gz data/ logs/
```

### 自动化备份脚本

```bash
#!/bin/bash

BACKUP_DIR="/path/to/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="wechat"
DB_USER="root"
DB_PASS="password"

# 创建备份目录
mkdir -p $BACKUP_DIR

# 备份数据库
mysqldump -u$DB_USER -p$DB_PASS $DB_NAME | gzip > $BACKUP_DIR/db_$DATE.sql.gz

# 备份应用数据
tar -czf $BACKUP_DIR/data_$DATE.tar.gz /path/to/project/data

# 删除7天前的备份
find $BACKUP_DIR -name "*.gz" -mtime +7 -delete

echo "Backup completed at $DATE"
```

---

## 日志管理

### 日志轮转（logrotate）

创建 `/etc/logrotate.d/wechat`:

```conf
/path/to/project/logs/app.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload wechat > /dev/null 2>&1 || true
    endscript
}
```

### 查看日志

```bash
# 实时日志
tail -f logs/app.log

# 查看错误
grep ERROR logs/app.log

# 查看性能
grep "ms" logs/app.log | tail -20

# 按日期查看
grep "2025-01-" logs/app.log
```

---

## 监控与维护

### 系统监控

```bash
# 查看进程状态
ps aux | grep gunicorn

# 查看端口占用
netstat -tlnp | grep 5000

# 查看资源使用
top -p $(pgrep -f gunicorn)
```

### 数据库监控

```bash
# MySQL 连接数
mysql -u root -p -e "SHOW PROCESSLIST;" database_name

# 查看数据库大小
du -sh /var/lib/mysql/database_name
```

### 定期检查清单

- [ ] 检查日志中是否有错误
- [ ] 验证微信 API 连接正常
- [ ] 检查数据库备份是否成功
- [ ] 监控服务器磁盘空间
- [ ] 检查应用性能指标
- [ ] 更新依赖包（定期）

---

## 上线前检查清单

- [ ] 更新微信配置（AppID、AppSecret、Token）
- [ ] 修改管理员密码
- [ ] 配置生产数据库
- [ ] 启用 HTTPS
- [ ] 配置日志轮转
- [ ] 设置定期备份
- [ ] 测试所有功能页面
- [ ] 验证微信消息接收
- [ ] 检查错误日志
- [ ] 性能压力测试
- [ ] 配置监控告警
- [ ] 准备灾难恢复方案

