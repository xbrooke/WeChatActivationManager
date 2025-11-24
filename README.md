# 🎯 WeChat Activation Manager

**中文名称**: 微信激活码管理系统  
**开发者**: 徐大兵

> 一个功能完整、可靠安全的微信公众号激活码管理系统。支持激活码管理、用户管理、自定义回复和触发关键词配置.



---

## ✨ 核心功能

- 🎯 **激活码管理** - 生成、管理、验证激活码，支持VIP码
- 👥 **用户管理** - 自动同步微信用户，追踪激活状态
- 📋 **自定义回复** - 文本回复，两种匹配模式
- ⚙️ **触发关键词** - 关键词自动触发激活码发放
- 📊 **数据统计** - 实时统计和数据分析
- 🔍 **系统管理** - 日志查看、系统监控

---

## 🚀 快速开始

### 最快开始（3分钟）

```bash
# 1. 克隆项目
git clone https://github.com/your-username/wechat-activation-manager.git
cd wechat-activation-manager

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置环境
cp .env.example .env
# 编辑 .env 填入微信配置

# 4. 运行
python app.py
# 访问 http://localhost:5000 (账号: admin / 密码: admin123)
```

### 详细说明请查看

- 📖 [安装与配置](./INSTALLATION.md) - 详细安装步骤和配置说明
- 🔧 [环境配置](./INSTALLATION.md#必需配置项详解) - 所有配置项说明
- 📋 [.env.example](./.env.example) - 配置文件模板

---

## 📁 项目结构

```
wechat-activation-manager/
├── README.md                # 项目概览（本文件）
├── INSTALLATION.md          # 安装与配置指南
├── USAGE_GUIDE.md           # 功能使用指南  
├── DEPLOYMENT.md            # 部署指南
├── DOCUMENTATION.md         # 文档导航
├── LICENSE                  # MIT 许可证
├── CONTRIBUTING.md          # 贡献指南
├── .env.example             # 环境配置模板
│
├── app.py                   # Flask 主应用
├── database.py              # 数据库模型和管理
├── requirements.txt         # Python 依赖
├── run.bat                  # Windows 启动脚本
│
├── templates/               # HTML 前端模板
├── static/                  # CSS、JS、图标等静态资源
├── data/                    # JSON 数据文件（开发模式）
└── logs/                    # 应用日志
```

---

## 🔐 系统特性

### 🛡️ 安全
- Token验证、签名验证、SQL注入防护
- XML注入防护、会话认证、CSRF保护

### ⚡ 性能
- 数据库连接池、AccessToken缓存
- 日志分级管理、静态文件缓存
- 平均响应时间 <200ms

### 🎨 用户体验
- 响应式设计、移动适配
- 实时交互、清晰的错误提示
- 实时数据预览

### 📱 API友好
- RESTful API设计、完整API文档
- 错误处理完善、支持JSON和XML

---

## 📚 文档导航

[📖 README](./README.md) | [⚙️ 安装配置](./INSTALLATION.md) | [📋 使用指南](./USAGE_GUIDE.md) | [🚀 部署指南](./DEPLOYMENT.md) | [📑 文档索引](./DOCUMENTATION.md) | [🤝 贡献指南](./CONTRIBUTING.md) | [📄 许可证](./LICENSE)

---


## 🚀 部署

### 本地开发

```bash
python app.py
```

### 生产部署

- **Gunicorn + Nginx** - 详见 [DEPLOYMENT.md#生产环境部署](./DEPLOYMENT.md#生产环境部署)
- **Docker** - 详见 [DEPLOYMENT.md#docker-部署](./DEPLOYMENT.md#docker-部署)
- **systemd 服务** - 详见 [DEPLOYMENT.md#方案3systemd-服务linux](./DEPLOYMENT.md#方案3systemd-服务linux)

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！详见 [CONTRIBUTING.md](./CONTRIBUTING.md)

---

## 📄 许可证

MIT License - 详见 [LICENSE](./LICENSE)

---

**版本**: 1.0.0  
**开发者**: 徐大兵  
**最后更新**: 2025年11月24日  
**GitHub**: [wechat-activation-manager](https://github.com/your-username/wechat-activation-manager)
