# 📚 项目文档导航

## 快速导航

本项目的详细文档分为以下几部分，请根据你的需求查看对应文档：

### 📖 README.md（项目概览）
项目基本信息、核心功能、系统特性、快速开始等
**推荐**：首次了解项目时阅读

### 🚀 INSTALLATION.md（安装与配置）
详细的安装步骤、环境配置、数据库选择、常见问题排查
**推荐**：准备搭建项目时阅读

### 📖 USAGE_GUIDE.md（功能使用指南）
各功能模块的详细使用说明、操作步骤、配置示例
**推荐**：需要使用具体功能时阅读

### 🚀 DEPLOYMENT.md（部署指南）
生产环境部署方案（Gunicorn + Nginx、Docker、systemd）、HTTPS配置、数据备份、日志管理、监控维护
**推荐**：准备上线部署时阅读

### 📋 .env.example（环境配置模板）
所有配置项说明和可选值
**推荐**：配置环境变量时参考

### 📜 LICENSE（MIT 许可证）
项目许可证

### 🤝 CONTRIBUTING.md（贡献指南）
开发者贡献指南
**推荐**：想要贡献代码时阅读

---

## 按用途快速查找

### \"我想快速上手\"
1. 阅读 README.md 了解项目
2. 按 INSTALLATION.md 安装
3. 访问 http://localhost:5000

### \"我想了解如何使用各功能\"
1. 查看 USAGE_GUIDE.md
2. 对应功能模块找到使用说明
3. 按步骤操作

### \"我想部署到生产环境\"
1. 完成 INSTALLATION.md 中的配置
2. 查看 DEPLOYMENT.md 选择部署方案
3. 按部署步骤执行
4. 完成上线前检查清单

### \"我遇到问题了\"
1. 查看 INSTALLATION.md 中的\"常见问题\"部分
2. 查看应用日志 `logs/app.log`
3. 检查 .env 配置是否正确

---

## 文件结构

```
wechat-activation-manager/
├── README.md                # 项目概览（主文档）
├── INSTALLATION.md          # 安装与配置指南
├── USAGE_GUIDE.md           # 功能使用指南  
├── DEPLOYMENT.md            # 部署指南
├── DOCUMENTATION.md         # 文档导航（本文件）
├── LICENSE                  # MIT 许可证
├── CONTRIBUTING.md          # 贡献指南
├── .env.example             # 环境配置模板
├── app.py                   # 主应用程序
├── database.py              # 数据库模型
├── requirements.txt         # Python 依赖
├── run.bat                  # Windows 启动脚本
├── templates/               # HTML 模板
├── static/                  # 静态资源
├── data/                    # 数据文件
└── logs/                    # 应用日志
```

---

## 核心概念速查表

### 激活码
- **用途**：用于用户验证和激活
- **类型**：普通码、VIP码
- **状态**：未使用、已使用、已过期
- **有效期**：普通码1天、VIP码30天（可配置）

### 用户激活流程
1. 用户订阅公众号
2. 系统记录用户信息
3. 用户获得激活码
4. 用户在公众号内验证激活码
5. 系统确认用户已激活

### 自定义回复
- 支持文本回复
- 两种匹配模式（精确、包含）
- 优先级控制

### 触发关键词
- 用户回复指定关键词时自动触发
- 可配置回复内容
- 支持自动生成激活码

---

## 常用命令

```bash
# 启动应用
python app.py

# 查看日志
tail -f logs/app.log

# 配置环境变量
cp .env.example .env
# 编辑 .env 文件

# 生产部署
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Docker 部署
docker build -t wechat .
docker run -p 5000:5000 wechat

# 备份数据
tar -czf backup.tar.gz data/
```

---

## 获得帮助

- 📧 提交 Issue 报告问题
- 💬 讨论与建议
- 📚 查看对应的文档文件
- 🔍 搜索应用日志中的错误信息

---

**最后更新**: 2025年11月24日  
**项目版本**: 1.0.0  
**开发者**: 徐大兵
"