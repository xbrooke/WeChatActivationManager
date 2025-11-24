#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
WeChat Activation Manager - Flask应用主文件
支持JSON和SQLAlchemy双存储方案
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
import io
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import random
import string
import os
import logging
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path
from functools import wraps
import requests
import base64
import pytz
import socket
from dotenv import load_dotenv
from database import init_database, DatabaseManager, get_current_time

# ===================== 加载环境变量 =====================
load_dotenv()

# ===================== 日志配置（必须最先初始化）=====================
log_dir = Path(os.getenv('LOG_FILE', 'logs/app.log')).parent
log_dir.mkdir(exist_ok=True)

log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# 自定义日志格式化器，使用北京时间
class BeijingTimeFormatter(logging.Formatter):
    """使用北京时间的日志格式化器"""
    converter = lambda *args: datetime.now(pytz.timezone('Asia/Shanghai')).timetuple()

handlers = []
if os.getenv('LOG_FILE', 'logs/app.log'):
    file_handler = logging.FileHandler(os.getenv('LOG_FILE', 'logs/app.log'), encoding='utf-8')
    file_handler.setFormatter(BeijingTimeFormatter(log_format))
    handlers.append(file_handler)
if os.getenv('LOG_TO_CONSOLE', 'true').lower() == 'true':
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(BeijingTimeFormatter(log_format))
    handlers.append(console_handler)

logging.basicConfig(
    level=log_level,
    format=log_format,
    handlers=handlers
)
logger = logging.getLogger(__name__)

logger.info('='*60)
logger.info('Flask 应用启动中...')
logger.info('='*60)
logger.info(f'环境变量 USE_DATABASE: {os.getenv("USE_DATABASE", "false")}')

# ===================== Flask应用初始化 =====================
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-change-in-production')
logger.info('✓ Flask 应用已初始化')

# ===================== 应用配置 =====================
# 激活码配置
ACTIVATION_CODE_EXPIRE_DAYS = int(os.getenv('ACTIVATION_CODE_EXPIRE_DAYS', '7'))
VIP_CODE_EXPIRE_DAYS = int(os.getenv('VIP_CODE_EXPIRE_DAYS', '30'))
BATCH_GENERATE_DEFAULT_COUNT = int(os.getenv('BATCH_GENERATE_DEFAULT_COUNT', '10'))
BATCH_GENERATE_MAX_COUNT = int(os.getenv('BATCH_GENERATE_MAX_COUNT', '1000'))

# 认证配置
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

# 微信配置
WECHAT_TOKEN = os.getenv('WECHAT_TOKEN', '')
WECHAT_APPID = os.getenv('WECHAT_APPID', '')
WECHAT_APPSECRET = os.getenv('WECHAT_APPSECRET', '')
WECHAT_ENCODING_AES_KEY = os.getenv('WECHAT_ENCODING_AES_KEY', '')
WECHAT_ACCESS_TOKEN_URL = 'https://api.weixin.qq.com/cgi-bin/token'


# 微信 AccessToken 缓存
_wechat_access_token = None
_wechat_token_expires_at = None

# ===================== 数据库配置 =====================
USE_DATABASE = os.getenv('USE_DATABASE', 'false').lower() == 'true'
logger.info(f'USE_DATABASE 环境变量: {os.getenv("USE_DATABASE", "false")}')
if USE_DATABASE:
    database_url = os.getenv('DATABASE_URL', 'sqlite:///app.db')
    logger.info(f'配置数据库: {database_url}')
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
else:
    logger.info('使用 JSON 文件存储')
db_manager = init_database(app, use_db=USE_DATABASE)
logger.info(f'✓ 存储模式已启用: {"SQLAlchemy数据库 (MySQL)" if USE_DATABASE else "JSON文件"}')
if USE_DATABASE:
    logger.info(f'  数据库地址: {os.getenv("DATABASE_URL", "sqlite:///app.db")}')

# ===================== 工具函数 =====================
def generate_code(is_vip=False):
    """生成激活码"""
    chars = string.ascii_uppercase + string.digits
    if is_vip:
        code = 'VIP-' + ''.join(random.choices(chars, k=6))
    else:
        code = ''.join(random.choices(chars, k=8))
    return code


def require_login(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def generate_avatar_svg(avatar_type, size=64):
    """生成SVG头像"""
    avatars = {
        'user': {'color': '#3b82f6', 'icon': '👤'},
        'astronaut': {'color': '#8b5cf6', 'icon': '🧑‍🚀'},
        'secret': {'color': '#ec4899', 'icon': '🕵️'},
        'ninja': {'color': '#06b6d4', 'icon': '🥷'},
        'smile': {'color': '#f59e0b', 'icon': '😊'},
        'heart': {'color': '#ef4444', 'icon': '😍'},
        'graduate': {'color': '#06b6d4', 'icon': '🎓'},
        'doctor': {'color': '#10b981', 'icon': '⚕️'},
        'admin': {'color': '#667eea', 'icon': '👑'},
        'admin-logo': {'color': '#667eea', 'icon': '👑'},  # logo.ico
        'admin-gold': {'color': '#fbbf24', 'icon': '👑'},  # 金色皇冠
        'admin-red': {'color': '#ef4444', 'icon': '👑'},   # 红色皇冠
        'admin-green': {'color': '#10b981', 'icon': '👑'}, # 绿色皇冠
        'admin-blue': {'color': '#3b82f6', 'icon': '👑'},  # 蓝色皇冠
        'admin-purple': {'color': '#a855f7', 'icon': '👑'}, # 紫色皇冠
        'star': {'color': '#fbbf24', 'icon': '⭐'},
        'rocket': {'color': '#f97316', 'icon': '🚀'},
        'lightning': {'color': '#eab308', 'icon': '⚡'},
        'shield': {'color': '#22c55e', 'icon': '🛡️'},
        'crown': {'color': '#a855f7', 'icon': '👸'},
    }
    
    avatar_info = avatars.get(avatar_type, avatars['user'])
    color = avatar_info['color']
    
    svg = f'''<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
        <circle cx="{size//2}" cy="{size//2}" r="{size//2}" fill="{color}"/>
        <text x="50%" y="50%" font-size="{size//2}" text-anchor="middle" dominant-baseline="central" font-family="Arial, sans-serif">{avatar_info['icon']}</text>
    </svg>'''
    
    return svg


# ===================== 微信工具函数 =====================

def get_wechat_followers():
    """
    获取微信公众号的所有关注者列表
    官方API：GET https://api.weixin.qq.com/cgi-bin/user/get
    """
    access_token = get_wechat_access_token()
    if not access_token:
        logger.error('无法获取 AccessToken，无法同步用户列表')
        return []
    
    try:
        all_followers = []
        marker = None  # 用于分页
        
        while True:
            # 获取用户列表（最多10000个）
            url = 'https://api.weixin.qq.com/cgi-bin/user/get'
            params = {'access_token': access_token}
            if marker:
                params['marker'] = marker
            
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            if 'errcode' in data and data['errcode'] != 0:
                error_msg = data.get('errmsg', '未知错误')
                logger.error(f'获取用户列表失败: {error_msg}')
                break
            
            # 添加用户
            if 'data' in data and 'openid' in data['data']:
                all_followers.extend(data['data']['openid'])
            
            # 检查是否还有更多数据
            if 'next_marker' in data and data['next_marker']:
                marker = data['next_marker']
            else:
                break
        
        logger.info(f'✓ 获取微信关注者列表成功: {len(all_followers)} 个用户')
        return all_followers
    except Exception as e:
        logger.error(f'获取用户列表异常: {e}')
        return []


def get_wechat_user_info(openid: str):
    """
    获取单个用户的详细信息
    官方API：GET https://api.weixin.qq.com/cgi-bin/user/info
    
    返回数据结构：
    {
        'subscribe': 1,  # 1=已关注，0=已取关
        'openid': 'OPENID',
        'nickname': '用户昵称',
        'sex': 1,  # 1=男，2=女，0=未知
        'language': 'zh_CN',
        'city': '城市',
        'province': '省份',
        'country': '国家',
        'headimgurl': '头像URL',
        'subscribe_time': 1234567890,  # 时间戳
        'union_id': 'UNIONID'
    }
    """
    access_token = get_wechat_access_token()
    if not access_token:
        logger.warning(f'无法获取用户信息：{openid}，缺少 AccessToken')
        return None
    
    try:
        url = 'https://api.weixin.qq.com/cgi-bin/user/info'
        params = {
            'access_token': access_token,
            'openid': openid,
            'lang': 'zh_CN'
        }
        
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        if 'errcode' in data and data['errcode'] != 0:
            error_msg = data.get('errmsg', '未知错误')
            logger.warning(f'获取用户信息失败 [{openid}]: {error_msg}')
            return None
        
        # 验证用户是否仍在关注
        if data.get('subscribe', 0) == 0:
            logger.debug(f'用户已取关: {openid}')
            return None
        
        logger.debug(f'✓ 获取用户信息成功: {openid} - {data.get("nickname")}')
        return data
    except Exception as e:
        logger.error(f'获取用户信息异常 [{openid}]: {e}')
        return None


def get_wechat_access_token():
    """
    获取微信 AccessToken
    缓存有效期为 7200 秒（2小时）
    """
    global _wechat_access_token, _wechat_token_expires_at
    
    # 检查缓存是否有效
    if _wechat_access_token and _wechat_token_expires_at:
        if get_current_time() < _wechat_token_expires_at:
            logger.debug('使用缓存的 AccessToken')
            return _wechat_access_token
    
    # 从微信服务器获取新的 AccessToken
    try:
        logger.info('正在获取微信 AccessToken...')
        params = {
            'grant_type': 'client_credential',
            'appid': WECHAT_APPID,
            'secret': WECHAT_APPSECRET
        }
        response = requests.get(WECHAT_ACCESS_TOKEN_URL, params=params, timeout=5)
        data = response.json()
        
        if 'access_token' in data:
            _wechat_access_token = data['access_token']
            expires_in = data.get('expires_in', 7200)
            _wechat_token_expires_at = get_current_time() + timedelta(seconds=expires_in - 300)  # 提前5分钟过期
            logger.info(f'✓ 获取 AccessToken 成功，有效期: {expires_in} 秒')
            return _wechat_access_token
        else:
            error_msg = data.get('errmsg', '未知错误')
            logger.error(f'✗ 获取 AccessToken 失败: {error_msg}')
            return None
    except Exception as e:
        logger.error(f'获取 AccessToken 异常: {e}')
        return None


def decrypt_wechat_message(encrypt_type, msg_signature, timestamp, nonce, data):
    """
    解密微信安全模式的消息
    """
    if encrypt_type != 'aes':
        return None
    
    try:
        # 验证签名（此时使用的是不包含加密数据的签名）
        sign_list = sorted([WECHAT_TOKEN, timestamp, nonce])
        sign_str = ''.join(sign_list)
        computed_signature = hashlib.sha1(sign_str.encode()).hexdigest()
        
        # 注意：验证的签名是会话消息节点下发送的整个 POST 请求的签名，而不是单独重新计算
        # 实际上应该直接使用微信发来的 msg_signature 值，这里是为了演示
        # 在真实场景中，你会接收到 msg_signature 作为请求参数
        
        # 解密消息
        key = base64.b64decode(WECHAT_ENCODING_AES_KEY + '=')
        encrypted_data = base64.b64decode(data)
        
        # 提取 IV（前 16 个字节）
        iv = encrypted_data[:16]
        cipher_text = encrypted_data[16:]
        
        # 使用 AES 解密
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cipher_text)
        
        # 移除 PKCS7 填充
        content = decrypted[:-decrypted[-1]].decode('utf-8')
        logger.debug(f'消息解密成功: {content[:100]}...')
        return content
    except Exception as e:
        logger.error(f'消息解密失败: {e}')
        return None


def encrypt_wechat_message(msg_content, timestamp, nonce):
    """
    加密微信安全模式的回复消息
    """
    try:
        from Crypto.Cipher import AES
        import struct
        
        # 生成随机初始化向量
        key = base64.b64decode(WECHAT_ENCODING_AES_KEY + '=')
        iv = os.urandom(16)
        
        # PKCS7 填充
        msg_bytes = msg_content.encode('utf-8')
        padding_length = 32 - (len(msg_bytes) % 32)
        padded_msg = msg_bytes + bytes([padding_length] * padding_length)
        
        # AES 加密
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_msg = cipher.encrypt(padded_msg)
        
        # 合并结果
        encrypted_data = iv + encrypted_msg
        encrypt_str = base64.b64encode(encrypted_data).decode('utf-8')
        
        # 生成签名
        sign_list = sorted([WECHAT_TOKEN, timestamp, nonce, encrypt_str])
        sign_str = ''.join(sign_list)
        msg_signature = hashlib.sha1(sign_str.encode()).hexdigest()
        
        logger.debug(f'消息加密成功')
        return {
            'encrypt': encrypt_str,
            'msg_signature': msg_signature
        }
    except Exception as e:
        logger.error(f'消息加密失败: {e}')
        return None





# ===================== 静态资源路由 =====================
@app.route('/static/favicon.ico')
def favicon():
    """返回favicon.ico"""
    favicon_path = 'logo.ico'
    if os.path.exists(favicon_path):
        return send_file(favicon_path, mimetype='image/x-icon')
    # 如果文件不存在，返回一个默认的空ICO响应
    return '', 204


# ===================== 页面路由 =====================
@app.route('/')
def home():
    """首页"""
    logger.info('用户访问首页')
    return render_template('home.html')


@app.route('/login', methods=['GET'])
def login():
    """登录页面"""
    return render_template('login.html')


@app.route('/admin')
@require_login
def admin_dashboard():
    """管理后台仪表盘"""
    logger.info(f'用户 {session.get("user")} 访问仪表盘')
    return render_template('admin/dashboard.html')


@app.route('/admin/activation-codes')
@require_login
def admin_activation_codes():
    """激活码管理页面"""
    return render_template('admin/activation_codes.html')


@app.route('/admin/users')
@require_login
def admin_users():
    """用户管理页面"""
    return render_template('admin/users.html')


@app.route('/admin/statistics')
@require_login
def admin_statistics():
    """数据统计页面"""
    return render_template('admin/statistics.html')


@app.route('/admin/custom-reply')
@require_login
def admin_custom_reply():
    """自定义回复页面"""
    return render_template('admin/custom_reply.html')


@app.route('/admin/trigger-keywords')
@require_login
def admin_trigger_keywords():
    """自定义触发关键词页面"""
    return render_template('admin/trigger_keywords.html')


@app.route('/admin/wechat-api-guide')
@require_login
def admin_wechat_guide():
    """微信API指南页面"""
    return render_template('admin/wechat_guide.html')


@app.route('/admin/logs')
@require_login
def admin_logs():
    """系统日志页面"""
    return render_template('admin/logs.html')


@app.route('/admin/api-docs')
@require_login
def admin_api_docs():
    """API接口文档页面"""
    return render_template('admin/api_docs.html')


@app.route('/system-status')
@require_login
def system_status():
    """系统环境信息页面"""
    import platform
    
    try:
        # 获取系统信息
        system_info = {
            'app_name': '激活码管理系统',
            'version': '1.0.0',
            'author': '',
            'storage_mode': 'SQLAlchemy数据库' if USE_DATABASE else 'JSON文件',
            'timezone': 'Asia/Shanghai',
            'python_version': platform.python_version(),
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'hostname': platform.node(),
            'timestamp': get_current_time().isoformat(),
            'flask_version': __import__('flask').__version__,
            'database_url': os.getenv('DATABASE_URL', 'JSON文件存储') if USE_DATABASE else 'JSON文件存储',
        }
        
        # ==================== 网络环境信息 ====================
        network_info = {'status': '正常', 'details': []}
        
        try:
            # 获取本机IP地址
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network_info['local_ip'] = local_ip
            network_info['details'].append(f'本地IP: {local_ip}')
        except Exception as e:
            network_info['status'] = '异常'
            logger.warning(f'获取本机IP失败: {e}')
        
        try:
            # 检查网络连接（测试DNS解析）
            socket.gethostbyname('www.baidu.com')
            network_info['internet_status'] = '已连接'
            network_info['details'].append('外网连接: 已连接')
        except Exception as e:
            network_info['internet_status'] = '未连接'
            network_info['details'].append('外网连接: 未连接')
            if network_info['status'] == '正常':
                network_info['status'] = '警告'
            logger.warning(f'网络连接异常: {e}')
        
        try:
            # 检查微信API连通性
            if WECHAT_APPID and WECHAT_APPSECRET:
                response = requests.get(WECHAT_ACCESS_TOKEN_URL, params={
                    'grant_type': 'client_credential',
                    'appid': WECHAT_APPID,
                    'secret': WECHAT_APPSECRET
                }, timeout=3)
                if response.status_code == 200:
                    network_info['wechat_api'] = '正常'
                    network_info['details'].append('微信API: 正常')
                else:
                    network_info['wechat_api'] = '异常'
                    network_info['details'].append('微信API: 异常')
            else:
                network_info['wechat_api'] = '未配置'
                network_info['details'].append('微信API: 未配置')
        except Exception as e:
            network_info['wechat_api'] = '异常'
            network_info['details'].append('微信API: 无法连接')
            logger.warning(f'微信API连接异常: {e}')
        
        system_info['network_info'] = network_info
        
        # ==================== 数据库信息 ====================
        database_info = {'status': '正常', 'details': []}
        
        try:
            if USE_DATABASE:
                # 测试数据库连接
                codes = db_manager.get_codes()
                users = db_manager.get_users()
                database_info['connected'] = True
                database_info['type'] = 'MySQL (SQLAlchemy)'
                database_info['details'].append(f'数据库类型: MySQL')
                database_info['details'].append(f'激活码表: {len(codes)} 条记录')
                database_info['details'].append(f'用户表: {len(users)} 条记录')
                # 解析数据库URL
                db_url = os.getenv('DATABASE_URL', '')
                if 'mysql' in db_url.lower():
                    try:
                        # 从URL中提取主机
                        host_match = db_url.split('@')[1].split('/')[0] if '@' in db_url else '本地'
                        database_info['details'].append(f'数据库主机: {host_match}')
                    except:
                        pass
            else:
                database_info['type'] = 'JSON文件'
                database_info['details'].append('存储方式: JSON文件')
                database_info['details'].append(f'数据文件目录: {os.path.abspath("data")}')
                # 检查数据文件
                try:
                    if os.path.exists('data/codes.json'):
                        codes_file_size = os.path.getsize('data/codes.json')
                        database_info['details'].append(f'激活码文件大小: {codes_file_size} 字节')
                    if os.path.exists('data/replies_README.txt'):
                        database_info['details'].append('自定义回复: 已配置')
                except:
                    pass
        except Exception as e:
            database_info['status'] = '异常'
            database_info['connected'] = False
            database_info['details'].append(f'错误: {str(e)}')
            logger.error(f'数据库连接异常: {e}')
        
        system_info['database_info'] = database_info
        
        # ==================== 配置信息 ====================
        config_info = {
            'details': []
        }
        
        try:
            # 环境变量配置
            config_info['details'].append(f'日志级别: {os.getenv("LOG_LEVEL", "INFO")}')
            config_info['details'].append(f'日志文件: {os.getenv("LOG_FILE", "logs/app.log")}')
            config_info['details'].append(f'激活码有效期: {ACTIVATION_CODE_EXPIRE_DAYS} 天')
            config_info['details'].append(f'VIP码有效期: {VIP_CODE_EXPIRE_DAYS} 天')
            
            # 微信配置状态
            wechat_configured = bool(WECHAT_APPID and WECHAT_APPSECRET and WECHAT_TOKEN)
            config_info['details'].append(f'微信配置: {"已配置" if wechat_configured else "未配置"}')
            
            # 数据库配置状态  
            config_info['details'].append(f'数据库模式: {"启用" if USE_DATABASE else "禁用"}')
            if USE_DATABASE:
                config_info['details'].append(f'数据库URI: {os.getenv("DATABASE_URL", "未配置")}')
            
            # 其他配置
            config_info['details'].append(f'Flask密钥: {"已配置" if os.getenv("FLASK_SECRET_KEY") else "使用默认值"}')
        except Exception as e:
            logger.error(f'获取配置信息异常: {e}')
        
        system_info['config_info'] = config_info
        
    except Exception as e:
        logger.error(f'获取系统信息异常: {e}')
        system_info = {'error': str(e)}
    
    logger.info('用户访问系统环境信息页面')
    return render_template('system_status.html', system_info=system_info)


# ===================== 认证接口 =====================
@app.route('/api/login', methods=['POST'])
def api_login():
    """登录API"""
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['is_authenticated'] = True
        session['user'] = username
        logger.info(f'用户登录成功: {username}')
        return jsonify({'success': True, 'message': '登录成功'})
    
    logger.warning(f'登录失败: 用户名={username}')
    return jsonify({'success': False, 'message': '用户名或密码错误'}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """登出API"""
    username = session.get('user')
    session.clear()
    logger.info(f'用户登出: {username}')
    return jsonify({'success': True, 'message': '已退出登录'})


@app.route('/api/check-session', methods=['GET'])
def check_session():
    """检查会话状态"""
    is_authenticated = session.get('is_authenticated', False)
    username = session.get('user')
    return jsonify({
        'authenticated': is_authenticated,
        'user': username
    })


# ===================== IP定位接口（客户端使用） =====================
@app.route('/api/get-location', methods=['GET', 'POST'])
def get_location():
    """获取客户端IP和地址信息
    支持多种方式获取：
    1. 从请求头获取客户端IP
    2. 调用免费IP定位服务获取地理位置
    """
    try:
        # 获取客户端IP地址（支持代理情况）
        client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        if not client_ip or client_ip == '127.0.0.1':
            client_ip = request.remote_addr
        
        logger.debug(f'获取客户端IP: {client_ip}')
        
        # 使用免费IP定位服务查询城市信息
        location_info = {
            'ip': client_ip,
            'city': '未知',
            'province': '未知',
            'country': '中国',
            'timestamp': get_current_time().isoformat()
        }
        
        try:
            # 使用IP138 API（免费，无需密钥）
            response = requests.get(
                'https://ip138.com/ip2city.php',
                params={'ip': client_ip},
                timeout=3,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            if response.status_code == 200:
                # IP138返回格式: "IP地址=xxxx|归属地=xxxx"
                content = response.text.strip()
                if '归属地=' in content:
                    parts = content.split('|')
                    location_str = parts[1].replace('归属地=', '') if len(parts) > 1 else '未知'
                    # 解析 "省份 城市" 格式
                    location_parts = location_str.split()
                    if len(location_parts) >= 2:
                        location_info['province'] = location_parts[0]
                        location_info['city'] = location_parts[1] if len(location_parts) > 1 else location_parts[0]
                    elif location_parts:
                        location_info['city'] = location_parts[0]
        except:
            # IP138失败，尝试其他服务
            try:
                response = requests.get(
                    'https://ipapi.co/json/',
                    params={'ip': client_ip},
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    location_info['city'] = data.get('city', '未知')
                    location_info['province'] = data.get('region', '未知')
                    location_info['country'] = data.get('country_name', '未知')
            except:
                pass
        
        logger.info(f'IP定位成功: {client_ip} -> {location_info["province"]} {location_info["city"]}')
        return jsonify({
            'success': True,
            'data': location_info
        })
        
    except Exception as e:
        logger.error(f'获取IP定位信息异常: {e}')
        return jsonify({
            'success': False,
            'message': '获取位置信息失败',
            'ip': request.remote_addr
        })


@app.route('/api/report-client-info', methods=['POST'])
def report_client_info():
    """客户端上报自身信息（IP、城市、机器信息等）
    无需认证，客户端可直接调用
    """
    try:
        data = request.get_json() or {}
        client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        if not client_ip:
            client_ip = request.remote_addr
        
        # 从请求中提取客户端上报的信息
        city = data.get('city', '未知')
        province = data.get('province', '未知')
        machine_id = data.get('machine_id', '')  # 机器唯一标识
        app_name = data.get('app_name', '')  # 应用名称
        app_version = data.get('app_version', '')  # 应用版本
        
        logger.info(f'客户端上报: IP={client_ip}, 城市={province}{city}, 应用={app_name} {app_version}')
        
        # 如果提供了machine_id，尝试关联到用户
        if machine_id:
            user = db_manager.get_user_by_openid(machine_id)
            if user:
                # 更新用户的IP和城市信息
                update_data = {
                    'city': city,
                    'last_ip': client_ip,
                    'last_login_time': get_current_time().isoformat()
                }
                db_manager.update_user(user['id'], update_data)
                logger.info(f'更新用户位置信息: {machine_id}')
        
        return jsonify({
            'success': True,
            'message': '信息上报成功',
            'received': {
                'ip': client_ip,
                'city': city,
                'province': province
            }
        })
        
    except Exception as e:
        logger.error(f'处理客户端信息上报异常: {e}')
        return jsonify({
            'success': False,
            'message': '服务器错误'
        }), 500


# ===================== 头像接口 =====================
@app.route('/api/avatar/<avatar_type>', methods=['GET'])
def get_avatar(avatar_type):
    """获取SVG头像"""
    # 处理管理员头像 - 优先返回顯示效果
    if avatar_type in ['admin', 'admin-logo']:
        # admin 和 admin-logo 都优先使用 logo.ico
        logo_paths = [
            os.path.join(os.path.dirname(__file__), 'logo.ico'),
            'logo.ico',
            os.path.expanduser('~/Desktop/wechat2/logo.ico'),
        ]
        
        for logo_path in logo_paths:
            if os.path.exists(logo_path):
                try:
                    logger.debug(f'返回logo.ico: {logo_path}')
                    return send_file(logo_path, mimetype='image/x-icon')
                except Exception as e:
                    logger.warning(f'读取logo.ico失败 [{logo_path}]: {e}')
        
        # 如果文件不存在，使用第一个SVG备用方案
        logger.debug('使用logo.ico备用方案：生成SVG')
        svg = generate_avatar_svg('admin', 128)
        return svg, 200, {'Content-Type': 'image/svg+xml; charset=utf-8'}
    
    # 处理admin的其他颈色 - 生成带颜色的SVG
    size = request.args.get('size', 64, type=int)
    if size > 512:
        size = 512
    elif size < 16:
        size = 16
    
    svg = generate_avatar_svg(avatar_type, size)
    return svg, 200, {'Content-Type': 'image/svg+xml; charset=utf-8'}


@app.route('/api/avatar/preview/<avatar_type>', methods=['GET'])
def preview_avatar(avatar_type):
    """预览头像(同步端点)"""
    size = request.args.get('size', 64, type=int)
    if size > 512:
        size = 512
    elif size < 16:
        size = 16
    
    svg = generate_avatar_svg(avatar_type, size)
    return svg, 200, {'Content-Type': 'image/svg+xml; charset=utf-8'}


# ===================== 激活码接口 =====================
@app.route('/api/codes', methods=['GET'])
@require_login
def get_codes():
    """获取激活码列表"""
    codes = db_manager.get_codes()
    logger.debug(f'获取激活码列表, 共 {len(codes)} 条')
    response = jsonify(codes)
    response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/codes', methods=['POST'])
@require_login
def add_code():
    """添加激活码"""
    data = request.get_json() or {}
    is_vip = data.get('is_vip', False)
    
    new_code = {
        'id': f"code-{int(get_current_time().timestamp() * 1000)}",
        'code': generate_code(is_vip),
        'createdAt': get_current_time().isoformat(),
        'expiresAt': (get_current_time() + timedelta(days=VIP_CODE_EXPIRE_DAYS if is_vip else ACTIVATION_CODE_EXPIRE_DAYS)).isoformat(),
        'status': 'unused',
        'isVIP': is_vip
    }
    
    if is_vip:
        new_code['vipLevel'] = data.get('vipLevel', 1)
        new_code['features'] = data.get('features', [])
    
    result = db_manager.add_code(new_code)
    logger.info(f'添加激活码: {new_code["code"]}')
    
    return jsonify({'success': True, 'code': result})


@app.route('/api/codes/generate', methods=['POST'])
@require_login
def generate_code_endpoint():
    """使用高级逻辑生成激活码（来自旧版本）"""
    data = request.get_json() or {}
    openid = data.get('openid', '')
    length = data.get('length', 8)
    format_type = data.get('format_type', 'ALPHANUMERIC')
    is_vip = data.get('is_vip', False)
    
    # 验证长度
    if length < 4 or length > 32:
        return jsonify({'success': False, 'message': '激活码长度必须在4-32之间'}), 400
    
    result = db_manager.generate_code_advanced(openid, length, format_type, is_vip)
    
    if result['success']:
        logger.info(f'生成激活码: {result["code"]}')
    else:
        logger.warning(f'生成激活码失败: {result["message"]}')
    
    return jsonify(result)


# ===================== 客户端激活码验证接口（无需登录） =====================
@app.route('/api/validate-code', methods=['GET', 'POST'])
def validate_code():
    """验证激活码是否有效（客户端使用）
    不消耗激活码，仅检查其状态
    """
    try:
        # 同时支持 GET 和 POST 请求
        if request.method == 'GET':
            code = request.args.get('code', '').strip().upper()
        else:
            data = request.get_json() or {}
            code = data.get('code', '').strip().upper()
        
        if not code:
            return jsonify({'success': False, 'valid': False, 'message': '激活码不能为空'}), 400
        
        # 从数据库中查询激活码
        codes = db_manager.get_codes()
        
        # 查找匹配的激活码
        code_obj = None
        for c in codes:
            if c.get('code', '').upper() == code:
                code_obj = c
                break
        
        if not code_obj:
            logger.warning(f'客户端验证：激活码不存在: {code}')
            return jsonify({
                'success': True,
                'valid': False,
                'status': 'NOT_FOUND',
                'message': '激活码不存在或无效'
            })
        
        # 检查激活码状态
        status = code_obj.get('status', 'unused')
        
        if status == 'used':
            logger.warning(f'客户端验证：激活码已被使用: {code}')
            return jsonify({
                'success': True,
                'valid': False,
                'status': 'USED',
                'message': '激活码已被使用'
            })
        
        if status == 'expired':
            logger.warning(f'客户端验证：激活码已过期: {code}')
            return jsonify({
                'success': True,
                'valid': False,
                'status': 'EXPIRED',
                'message': '激活码已过期'
            })
        
        # 检查过期时间
        expires_at = code_obj.get('expiresAt', '')
        if expires_at:
            try:
                expires_dt = datetime.fromisoformat(expires_at)
                if get_current_time() > expires_dt:
                    logger.warning(f'客户端验证：激活码已过期: {code}')
                    return jsonify({
                        'success': True,
                        'valid': False,
                        'status': 'EXPIRED',
                        'message': '激活码已过期'
                    })
            except:
                pass
        
        # 激活码有效
        logger.info(f'客户端验证：激活码有效: {code}')
        return jsonify({
            'success': True,
            'valid': True,
            'status': 'VALID',
            'message': '激活码有效'
        })
        
    except Exception as e:
        logger.error(f'验证激活码异常: {e}')
        return jsonify({
            'success': False,
            'valid': False,
            'message': '服务器错误'
        }), 500


@app.route('/api/use-code', methods=['GET', 'POST'])
def use_code():
    """标记激活码为已使用（客户端使用）"""
    try:
        # 同时支持 GET 和 POST 请求
        if request.method == 'GET':
            code = request.args.get('code', '').strip().upper()
        else:
            data = request.get_json() or {}
            code = data.get('code', '').strip().upper()
        
        if not code:
            return jsonify({'success': False, 'message': '激活码不能为空'}), 400
        
        # 使用高级激活码验证和标记逻辑
        result = db_manager.use_code_advanced(code)
        
        if result['success']:
            # 获取客户端IP（支持代理）
            client_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            if not client_ip:
                client_ip = request.remote_addr
            
            # 从激活码查找关联的用户并更新其IP和城市信息
            codes = db_manager.get_codes()
            code_obj = None
            for c in codes:
                if c.get('code') == code:
                    code_obj = c
                    break
            
            if code_obj and code_obj.get('openid'):
                openid = code_obj.get('openid')
                user = db_manager.get_user_by_openid(openid)
                if user:
                    # 更新用户的IP和城市信息
                    # 获取城市信息（从请求中如果有的话）
                    if request.method == 'POST':
                        data = request.get_json() or {}
                        city = data.get('city', '')
                    else:
                        city = request.args.get('city', '')
                    
                    update_data = {
                        'last_ip': client_ip,
                        'last_login_time': get_current_time().isoformat()
                    }
                    
                    # 如果客户端没有提供城市信息，服务器根据 IP 自动获取
                    if not city or city == '未知':
                        logger.info(f'客户端未提供城市信息，服务器根据 IP {client_ip} 自动获取...')
                        try:
                            # 调用本服务器的位置获取接口，传入客户端IP
                            # 这会自动获取该IP对应的城市信息
                            location_info = {
                                'ip': client_ip,
                                'city': '未知',
                                'province': '未知',
                                'country': '中国',
                                'timestamp': get_current_time().isoformat()
                            }
                            
                            try:
                                # 使用IP138 API（免费，无需密钥）
                                import requests as req_module
                                response = req_module.get(
                                    'https://ip138.com/ip2city.php',
                                    params={'ip': client_ip},
                                    timeout=3,
                                    headers={'User-Agent': 'Mozilla/5.0'}
                                )
                                if response.status_code == 200:
                                    # IP138返回格式: "IP地址=xxxx|归属地=xxxx"
                                    content = response.text.strip()
                                    if '归属地=' in content:
                                        parts = content.split('|')
                                        location_str = parts[1].replace('归属地=', '') if len(parts) > 1 else '未知'
                                        # 解析 "省份 城市" 格式
                                        location_parts = location_str.split()
                                        if len(location_parts) >= 2:
                                            location_info['province'] = location_parts[0]
                                            location_info['city'] = location_parts[1] if len(location_parts) > 1 else location_parts[0]
                                        elif location_parts:
                                            location_info['city'] = location_parts[0]
                            except:
                                # IP138失败，尝试其他服务
                                try:
                                    response = req_module.get(
                                        'https://ipapi.co/json/',
                                        params={'ip': client_ip},
                                        timeout=3
                                    )
                                    if response.status_code == 200:
                                        data_api = response.json()
                                        location_info['city'] = data_api.get('city', '未知')
                                        location_info['province'] = data_api.get('region', '未知')
                                        location_info['country'] = data_api.get('country_name', '未知')
                                except:
                                    pass
                            
                            city = location_info.get('city', '未知')
                            province = location_info.get('province', '未知')
                            logger.info(f'服务器自动获取位置: IP={client_ip} -> {province} {city}')
                        except Exception as e:
                            logger.warning(f'服务器自动获取位置失败: {e}')
                            city = '未知'
                    
                    # 添加城市信息到更新数据
                    if city and city != '未知':
                        update_data['city'] = city
                    
                    db_manager.update_user(user['id'], update_data)
                    logger.info(f'更新用户位置信息: {openid}, IP={client_ip}, 城市={city}')
            
            logger.info(f'客户端标记激活码为已使用: {code}')
        else:
            logger.warning(f'客户端标记激活码失败: {code} - {result.get("message", "未知错误")}')
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f'标记激活码为已使用异常: {e}')
        return jsonify({
            'success': False,
            'message': '服务器错误'
        }), 500


@app.route('/api/codes/verify', methods=['POST'])
@require_login
def verify_code_endpoint():
    """验证激活码（来自旧版本）"""
    data = request.get_json() or {}
    code = data.get('code', '').strip().upper()
    
    if not code:
        return jsonify({'success': False, 'message': '激活码不能为空'}), 400
    
    result = db_manager.use_code_advanced(code)
    
    if result['success']:
        logger.info(f'验证激活码成功: {code}')
    else:
        logger.warning(f'验证激活码失败: {code} - {result["message"]}')
    
    return jsonify(result)


@app.route('/api/codes/batch', methods=['POST'])
@require_login
def batch_generate_codes():
    """批量生成激活码"""
    data = request.get_json() or {}
    count = data.get('count', 10)
    is_vip = data.get('is_vip', False)
    
    new_codes = []
    # 验证输入数量
    if count > BATCH_GENERATE_MAX_COUNT:
        return jsonify({'success': False, 'message': f'数量不能超过 {BATCH_GENERATE_MAX_COUNT}'}), 400
    
    for i in range(count):
        new_code = {
            'id': f"code-{int(get_current_time().timestamp() * 1000)}-{i}",
            'code': generate_code(is_vip),
            'createdAt': get_current_time().isoformat(),
            'expiresAt': (get_current_time() + timedelta(days=VIP_CODE_EXPIRE_DAYS if is_vip else ACTIVATION_CODE_EXPIRE_DAYS)).isoformat(),
            'status': 'unused',
            'isVIP': is_vip
        }
        
        if is_vip:
            new_code['vipLevel'] = random.randint(1, 5)
            new_code['features'] = []
        
        new_codes.append(db_manager.add_code(new_code))
    
    logger.info(f'批量生成激活码: {count} 个')
    return jsonify({'success': True, 'codes': new_codes, 'count': count})


@app.route('/api/codes/<code_id>', methods=['DELETE'])
@require_login
def delete_code(code_id):
    """删除激活码"""
    db_manager.delete_code(code_id)
    logger.info(f'删除激活码: {code_id}')
    return jsonify({'success': True})


@app.route('/api/codes/<code_id>', methods=['PUT'])
@require_login
def update_code(code_id):
    """更新激活码"""
    data = request.get_json() or {}
    result = db_manager.update_code(code_id, data)
    logger.info(f'更新激活码: {code_id}')
    return jsonify({'success': True, 'code': result})


# ===================== 用户接口 =====================
@app.route('/api/users', methods=['GET'])
@require_login
def get_users():
    """获取用户列表"""
    users = db_manager.get_users()
    logger.debug(f'获取用户列表, 共 {len(users)} 条')
    response = jsonify(users)
    response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/users/<user_id>', methods=['GET'])
@require_login
def get_user(user_id):
    """获取单个用户"""
    user = db_manager.get_user(user_id)
    if user:
        logger.debug(f'获取用户: {user_id}')
        return jsonify(user)
    else:
        logger.warning(f'用户不存在: {user_id}')
        return jsonify({'success': False, 'message': '用户不存在'}), 404


@app.route('/api/users/<user_id>', methods=['PUT'])
@require_login
def update_user(user_id):
    """更新用户信息"""
    data = request.get_json() or {}
    result = db_manager.update_user(user_id, data)
    if result:
        logger.info(f'更新用户: {user_id}')
        return jsonify({'success': True, 'user': result})
    else:
        logger.warning(f'更新用户失败: {user_id}')
        return jsonify({'success': False, 'message': '用户不存在'}), 404


@app.route('/api/users/<user_id>', methods=['DELETE'])
@require_login
def delete_user(user_id):
    """删除用户"""
    db_manager.delete_user(user_id)
    logger.info(f'删除用户: {user_id}')
    return jsonify({'success': True})


@app.route('/api/users/search', methods=['POST'])
@require_login
def search_users():
    """搜索用户"""
    data = request.get_json() or {}
    keyword = data.get('keyword', '').strip()
    
    if not keyword:
        return jsonify({'success': False, 'message': '搜索条件不能为空'}), 400
    
    results = db_manager.search_users(keyword)
    logger.info(f'搜索用户: {keyword}, 找到 {len(results)} 条')
    return jsonify({'success': True, 'results': results, 'count': len(results)})


@app.route('/api/users/status/<status>', methods=['GET'])
@require_login
def get_users_by_status(status):
    """按激活状态获取用户"""
    valid_statuses = ['none', 'pending', 'activated']
    if status not in valid_statuses:
        return jsonify({'success': False, 'message': f'不效的状态: {status}'}), 400
    
    users = db_manager.get_users_by_status(status)
    logger.debug(f'按状态得到用户: {status}, 共 {len(users)} 条')
    return jsonify({'success': True, 'status': status, 'users': users, 'count': len(users)})


@app.route('/api/users', methods=['POST'])
@require_login
def add_user():
    """添加用户"""
    data = request.get_json() or {}
    
    # 验证字段
    required_fields = ['openId', 'nickname']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'success': False, 'message': f'{field} 不能为空'}), 400
    
    # 检查openid是否已存在
    existing_user = db_manager.get_user_by_openid(data['openId'])
    if existing_user:
        return jsonify({'success': False, 'message': 'openId 已存在'}), 400
    
    # 添加新用户
    new_user = {
        'id': f"user-{int(get_current_time().timestamp() * 1000)}",
        'openId': data.get('openId'),
        'nickname': data.get('nickname'),
        'avatar': data.get('avatar', ''),
        'subscribeTime': get_current_time().isoformat(),
        'activationStatus': data.get('activationStatus', 'none'),
        'activationCode': data.get('activationCode'),
        'createdAt': get_current_time().isoformat()
    }
    
    result = db_manager.add_user(new_user)
    logger.info(f'添加新用户: {new_user["openId"]}')
    return jsonify({'success': True, 'user': result}), 201


@app.route('/api/users/<user_id>/activate', methods=['POST'])
@require_login
def activate_user(user_id):
    """激活用户"""
    data = request.get_json() or {}
    activation_code = data.get('activationCode', '').strip().upper()
    
    if not activation_code:
        return jsonify({'success': False, 'message': '激活码不能为空'}), 400
    
    result = db_manager.activate_user(user_id, activation_code)
    
    if result['success']:
        logger.info(f'激活用户: {user_id}, 激活码: {activation_code}')
        return jsonify(result)
    else:
        logger.warning(f'激活用户失败: {user_id}, 原因: {result.get("message")}')
        return jsonify(result), 400


@app.route('/api/users/<openid>/codes', methods=['GET'])
@require_login
def get_user_codes(openid):
    """获取用户关联的激活码列表"""
    try:
        codes = db_manager.get_codes()
        user_codes = [c for c in codes if c.get('openid') == openid]
        logger.debug(f'获取用户激活码: openid={openid}, 共 {len(user_codes)} 条')
        return jsonify({'success': True, 'codes': user_codes})
    except Exception as e:
        logger.error(f'获取用户激活码失败: {e}')
        return jsonify({'success': False, 'message': '获取失败'}), 500


@app.route('/api/users/batch-activate', methods=['POST'])
@require_login
def batch_activate_users():
    """批量激活用户"""
    data = request.get_json() or {}
    user_ids = data.get('userIds', [])
    
    if not user_ids or not isinstance(user_ids, list):
        return jsonify({'success': False, 'message': 'userIds 不能为空且必须是数组'}), 400
    
    result = db_manager.batch_activate_users(user_ids)
    logger.info(f'批量激活用户: 成功 {result["success"]} 个, 失败 {result["failed"]} 个')
    return jsonify({'success': True, 'result': result})


@app.route('/api/users/sync-wechat-info', methods=['POST'])
@require_login
def sync_wechat_info():
    """
    从微信服务器同步所有关注用户的头像和昵称信息
    这是一个后台同步操作，可能需要较长时间
    """
    try:
        logger.info('开始同步微信用户信息...')
        
        # 第一步：获取所有关注者的openid列表
        followers = get_wechat_followers()
        if not followers:
            return jsonify({
                'success': False,
                'message': '无法获取关注者列表，请检查微信配置'
            }), 500
        
        logger.info(f'获取到 {len(followers)} 个关注者')
        
        # 第二步：逐个获取用户详细信息并更新或创建用户
        updated_count = 0
        created_count = 0
        failed_count = 0
        
        for openid in followers:
            try:
                # 获取用户详细信息
                user_info = get_wechat_user_info(openid)
                if not user_info:
                    failed_count += 1
                    continue
                
                # 检查用户是否已存在
                existing_user = db_manager.get_user_by_openid(openid)
                
                if existing_user:
                    # 更新现有用户的头像、昵称
                    update_data = {
                        'nickname': user_info.get('nickname', existing_user.get('nickname')),
                        'avatar': user_info.get('headimgurl', existing_user.get('avatar', ''))
                    }
                    db_manager.update_user(existing_user['id'], update_data)
                    updated_count += 1
                    logger.debug(f'更新用户: {openid} - {user_info.get("nickname")}')
                else:
                    # 创建新用户
                    new_user = {
                        'id': f"user-{int(get_current_time().timestamp() * 1000)}",
                        'openId': openid,
                        'nickname': user_info.get('nickname', '微信用户'),
                        'avatar': user_info.get('headimgurl', ''),
                        'subscribeTime': datetime.fromtimestamp(
                            user_info.get('subscribe_time', int(get_current_time().timestamp())),
                            tz=pytz.timezone('Asia/Shanghai')
                        ).isoformat(),
                        'activationStatus': 'none',
                        'createdAt': get_current_time().isoformat()
                    }
                    db_manager.add_user(new_user)
                    created_count += 1
                    logger.debug(f'创建新用户: {openid} - {user_info.get("nickname")}')
                
                # 避免请求过于频繁，微信有访问频率限制
                import time
                time.sleep(0.1)
            
            except Exception as e:
                logger.error(f'同步用户 {openid} 失败: {e}')
                failed_count += 1
        
        result = {
            'success': True,
            'total': len(followers),
            'created': created_count,
            'updated': updated_count,
            'failed': failed_count,
            'message': f'同步完成！新建 {created_count} 个用户，更新 {updated_count} 个用户，失败 {failed_count} 个'
        }
        
        logger.info(f'✓ 微信用户信息同步完成: {result["message"]}')
        return jsonify(result)
    
    except Exception as e:
        logger.error(f'同步微信用户信息失败: {e}')
        return jsonify({
            'success': False,
            'message': f'同步失败: {str(e)}'
        }), 500


@app.route('/api/admin/avatar', methods=['POST'])
@require_login
def set_admin_avatar():
    """
    设置管理员的头像
    仅管理员可用
    请求体：{"avatar_type": "admin-gold"}  # 不提供仅默认改为logo.ico
    """
    try:
        username = session.get('user')
        
        # 验证是否是管理员
        if username != ADMIN_USERNAME:
            return jsonify({
                'success': False,
                'message': '仅管理员可以使用此功能'
            }), 403
        
        # 获取请求的头像类型
        data = request.get_json() or {}
        avatar_type = data.get('avatar_type', 'admin-logo')
        
        # 验证头像类型
        valid_admin_avatars = ['admin', 'admin-logo', 'admin-gold', 'admin-red', 'admin-green', 'admin-blue', 'admin-purple']
        if not avatar_type.startswith('admin'):
            avatar_type = 'admin-logo'
        
        # 保存设置到文件中
        admin_settings = {
            'avatar': f'avatar:{avatar_type}',
            'avatar_type': avatar_type,
            'updated_at': get_current_time().isoformat()
        }
        
        # 保存到配置文件
        config_file = 'data/admin_settings.json'
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(admin_settings, f, ensure_ascii=False, indent=2)
        
        logger.info(f'管理员 {username} 的头像已设置为 {avatar_type}')
        
        return jsonify({
            'success': True,
            'message': f'管理员头像已设置为 {avatar_type}',
            'avatar': f'avatar:{avatar_type}'
        })
    
    except Exception as e:
        logger.error(f'设置管理员头像失败: {e}')
        return jsonify({
            'success': False,
            'message': f'设置失败: {str(e)}'
        }), 500


@app.route('/api/admin/settings', methods=['GET'])
@require_login
def get_admin_settings():
    """
    获取管理员设置
    """
    try:
        config_file = 'data/admin_settings.json'
        
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                settings = json.load(f)
        else:
            settings = {'avatar': 'avatar:admin'}
        
        return jsonify({
            'success': True,
            'settings': settings
        })
    
    except Exception as e:
        logger.error(f'获取管理员设置失败: {e}')
        return jsonify({
            'success': False,
            'message': f'获取失败: {str(e)}'
        }), 500


@app.route('/api/users/<openid>/update-from-wechat', methods=['PUT'])
@require_login
def update_user_from_wechat(openid):
    """
    从微信服务器更新单个用户的信息（头像、昵称等）
    也支持直接通过JSON设置头像
    """
    try:
        data = request.get_json() or {}
        
        # 查找用户
        user = db_manager.get_user_by_openid(openid)
        if not user:
            return jsonify({
                'success': False,
                'message': '用户不存在'
            }), 404
        
        # 如果请求体中包含avatar字段，直接设置头像
        if 'avatar' in data:
            update_data = {'avatar': data.get('avatar')}
            updated_user = db_manager.update_user(user['id'], update_data)
            logger.info(f'设置用户头像 [{openid}]: {data.get("avatar")}')
            
            return jsonify({
                'success': True,
                'message': '用户头像已更新',
                'user': updated_user
            })
        
        # 否则从微信获取用户最新信息
        user_info = get_wechat_user_info(openid)
        if not user_info:
            return jsonify({
                'success': False,
                'message': '无法从微信获取用户信息，用户可能已取关'
            }), 400
        
        # 更新用户信息
        update_data = {
            'nickname': user_info.get('nickname', user.get('nickname')),
            'avatar': user_info.get('headimgurl', user.get('avatar', ''))
        }
        
        updated_user = db_manager.update_user(user['id'], update_data)
        logger.info(f'更新用户信息 [{openid}]: {update_data}')
        
        return jsonify({
            'success': True,
            'message': '用户信息已更新',
            'user': updated_user
        })
    
    except Exception as e:
        logger.error(f'更新用户信息失败: {e}')
        return jsonify({
            'success': False,
            'message': f'更新失败: {str(e)}'
        }), 500


# ===================== 迟访问记录 =====================

def get_user_ip():
    """获取用户客户端IP地址"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


@app.route('/api/record-visit', methods=['POST'])
def record_visit():
    """记录用户访问IP和次数"""
    try:
        data = request.get_json() or {}
        openid = data.get('openid', '').strip()
        
        if not openid:
            return jsonify({'success': False, 'message': 'openid 不能为空'}), 400
        
        # 获取客户端 IP
        client_ip = get_user_ip()
        
        # 查询用户是否存在
        user = db_manager.get_user_by_openid(openid)
        
        if user:
            # 更新用户 IP 和访问次数
            update_data = {
                'lastIp': client_ip,
                'visitCount': (user.get('visitCount', 0) or 0) + 1,
                'lastLoginTime': get_current_time().isoformat()
            }
            updated_user = db_manager.update_user(user['id'], update_data)
            logger.debug(f'记录用户访问: {openid}, IP: {client_ip}, 访问次数: {updated_user.get("visitCount")}')
            return jsonify({
                'success': True,
                'message': '访问记录已保存',
                'visitCount': updated_user.get('visitCount')
            })
        else:
            # 不存在执子的用户，不创建，只返回成功
            logger.debug(f'访问记录：用户 {openid} 不存在')
            return jsonify({
                'success': True,
                'message': '访问记录已保存'
            })
    
    except Exception as e:
        logger.error(f'记录访问失败: {e}')
        return jsonify({'success': False, 'message': f'记录失败: {str(e)}'}), 500



@app.route('/api/statistics', methods=['GET'])
@require_login
def get_statistics():
    """获取统计数据"""
    stats = db_manager.get_statistics()
    logger.debug('获取统计数据')
    response = jsonify(stats)
    response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/activities', methods=['GET'])
@require_login
def get_activities():
    """获取最近活动日志（仪表盘用）"""
    limit = request.args.get('limit', default=5, type=int)
    limit = min(limit, 50)  # 最多返回50条
    
    activities = []
    try:
        # 获取最近的激活码操作
        codes = db_manager.get_codes()
        code_activities = []
        
        for code in codes:
            # 检查激活码的最新操作
            if code.get('usedAt'):
                try:
                    used_dt = datetime.fromisoformat(code['usedAt'])
                    # 如果datetime不带时区信息，添加上海时区
                    if used_dt.tzinfo is None:
                        used_dt = used_dt.replace(tzinfo=pytz.timezone('Asia/Shanghai'))
                    code_activities.append({
                        'id': f"code_{code['id']}",
                        'user': code.get('usedBy', '未知用户'),
                        'type': '验证成功',
                        'detail': f"激活码 {code['code']} 已使用",
                        'timestamp': used_dt.timestamp(),
                        'time': used_dt,
                        'userColor': '#10b981',
                        'userIcon': 'fas fa-check'
                    })
                except:
                    pass
            elif code.get('createdAt'):
                try:
                    created_dt = datetime.fromisoformat(code['createdAt'])
                    # 如果datetime不带时区信息，添加上海时区
                    if created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=pytz.timezone('Asia/Shanghai'))
                    code_activities.append({
                        'id': f"code_{code['id']}",
                        'user': code.get('createdBy', '系统'),
                        'type': '生成激活码',
                        'detail': f"新生成激活码 {code['code']}",
                        'timestamp': created_dt.timestamp(),
                        'time': created_dt,
                        'userColor': '#3b82f6',
                        'userIcon': 'fas fa-plus'
                    })
                except:
                    pass
        
        # 获取最近的用户操作
        users = db_manager.get_users()
        user_activities = []
        
        for user in users:
            if user.get('createdAt'):
                try:
                    created_dt = datetime.fromisoformat(user['createdAt'])
                    # 如果datetime不带时区信息，添加上海时区
                    if created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=pytz.timezone('Asia/Shanghai'))
                    activity_type = '关注公众号' if user.get('activationStatus') == 'pending' else '激活成功'
                    activity_icon = 'fas fa-star' if user.get('activationStatus') == 'pending' else 'fas fa-check-circle'
                    activity_color = '#a855f7' if user.get('activationStatus') == 'pending' else '#10b981'
                    
                    user_activities.append({
                        'id': f"user_{user['id']}",
                        'user': user.get('username', '新用户'),
                        'type': activity_type,
                        'detail': f"用户 {user.get('username', '未知')} {activity_type}",
                        'timestamp': created_dt.timestamp(),
                        'time': created_dt,
                        'userColor': activity_color,
                        'userIcon': activity_icon
                    })
                except:
                    pass
        
        # 合并并按时间排序（最新的在前）
        activities = code_activities + user_activities
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        activities = activities[:limit]
        # 格式化时间显示
        now = get_current_time()
        for activity in activities:
            # 确保时间对象带有时区信息，便于计算时差
            activity_time = activity['time']
            if activity_time.tzinfo is None:
                activity_time = activity_time.replace(tzinfo=pytz.timezone('Asia/Shanghai'))
            
            # 计算时间差（基于激活码的实际时间）
            time_diff = now - activity_time
            total_seconds = time_diff.total_seconds()
            
            # 精确计算相对时间
            if total_seconds < 0:
                # 未来时间（不应该出现，但做防守）
                activity['time_display'] = '刚刚'
            elif total_seconds < 60:
                activity['time_display'] = '刚刚'
            elif total_seconds < 3600:
                minutes = int(total_seconds / 60)
                activity['time_display'] = f'{minutes}分钟前'
            elif total_seconds < 86400:
                hours = int(total_seconds / 3600)
                activity['time_display'] = f'{hours}小时前'
            elif total_seconds < 604800:  # 一周
                days = int(total_seconds / 86400)
                activity['time_display'] = f'{days}天前'
            else:
                # 超过一周，显示具体日期
                activity['time_display'] = activity_time.strftime('%m-%d %H:%M')
            
            # 确定活动类型颜色
            if activity['type'] == '验证成功':
                activity['typeClass'] = 'bg-green-100 text-green-800'
            elif activity['type'] == '生成激活码':
                activity['typeClass'] = 'bg-blue-100 text-blue-800'
            elif activity['type'] == '激活成功':
                activity['typeClass'] = 'bg-green-100 text-green-800'
            else:  # 关注公众号
                activity['typeClass'] = 'bg-purple-100 text-purple-800'
            
            # 保留timestamp用于前端实时计算，不要删除
            del activity['time']
            # 调试: 打印第一个活动的信息（检查timestamp是否存在）
            if activity == activities[0]:
                logger.debug(f'活动数据: timestamp={activity.get("timestamp")}, time_display={activity.get("time_display")}')
    
    except Exception as e:
        logger.error(f'获取活动日志失败: {e}')
    
    response = jsonify({'activities': activities})
    response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/system-info', methods=['GET'])
@require_login
def get_system_info():
    """获取系统信息"""
    import platform
    system_info = {
        'app_name': '激活码管理系统',
        'version': '1.0.0',
        'author': '开发团队',
        'storage_mode': 'SQLAlchemy数据库' if USE_DATABASE else 'JSON文件',
        'timezone': 'Asia/Shanghai',
        'python_version': platform.python_version(),
        'platform': platform.system(),
        'timestamp': get_current_time().isoformat()
    }
    logger.debug('获取系统信息')
    response = jsonify(system_info)
    response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/logs', methods=['GET'])
@require_login
def get_logs():
    """获取系统日志"""
    limit = request.args.get('limit', default=500, type=int)
    limit = min(limit, 1000)  # 最多返回1000条
    
    logs = []
    try:
        log_file = os.getenv('LOG_FILE', 'logs/app.log')
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # 取最后 limit 条
                lines = lines[-limit:]
                
                for line in lines:
                    try:
                        # 解析日志格式: 2025-01-01 12:00:00,000 - module - LEVEL - message
                        parts = line.strip().split(' - ', 3)
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            module = parts[1]
                            level = parts[2]
                            message = parts[3]
                            
                            # 确定日志级别样式
                            level_class = {
                                'DEBUG': 'bg-purple-100 text-purple-800',
                                'INFO': 'bg-blue-100 text-blue-800',
                                'WARNING': 'bg-yellow-100 text-yellow-800',
                                'ERROR': 'bg-red-100 text-red-800'
                            }.get(level, 'bg-gray-100 text-gray-800')
                            
                            logs.append({
                                'id': f"log_{len(logs)}",
                                'timestamp': timestamp,
                                'module': module,
                                'level': level,
                                'levelClass': level_class,
                                'message': message,
                                'details': None
                            })
                    except:
                        continue
        
        # 反向排序，最新的日志在前
        logs.reverse()
    
    except Exception as e:
        logger.error(f'读取日志文件失败: {e}')
    
    response = jsonify({'logs': logs})
    response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/logs', methods=['DELETE'])
@require_login
def clear_logs():
    """清空系统日志"""
    try:
        log_file = os.getenv('LOG_FILE', 'logs/app.log')
        if os.path.exists(log_file):
            open(log_file, 'w').close()  # 清空文件
            logger.info('系统日志已被清空')
            return jsonify({'success': True, 'message': '日志已清空'})
        else:
            return jsonify({'success': False, 'message': '日志文件不存在'}), 404
    except Exception as e:
        logger.error(f'清空日志失败: {e}')
        return jsonify({'success': False, 'message': f'清空失败: {str(e)}'}), 500


# ===================== 自定义回复接口 =====================

@app.route('/api/trigger-keywords', methods=['GET'])
@require_login
def get_trigger_keywords():
    """获取触发关键词配置"""
    try:
        config = db_manager.get_trigger_keywords()
        logger.debug(f'加载触发关键词: {config.get("keywords", [])}')
        response = jsonify(config)
        response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
        return response
    except Exception as e:
        logger.error(f'获取触发关键词配置失败: {e}')
        return jsonify({'error': '获取失败'}), 500


@app.route('/api/trigger-keywords', methods=['POST'])
@require_login
def save_trigger_keywords():
    """保存触发关键词配置"""
    try:
        data = request.get_json() or {}
        keywords = data.get('keywords', [])
        config = data.get('config', {})
        preview = data.get('preview', {})
        
        if not keywords:
            return jsonify({'success': False, 'message': '至少设置一个关键词'}), 400
        
        result = db_manager.save_trigger_keywords(keywords, config, preview)
        logger.info(f'触发关键词配置已保存: {keywords}')
        return jsonify(result)
    
    except Exception as e:
        logger.error(f'保存触发关键词配置失败: {e}')
        return jsonify({'success': False, 'message': f'保存失败: {str(e)}'}), 500


@app.route('/api/replies', methods=['GET'])
@require_login
def get_replies():
    """获取自定义回复列表"""
    try:
        # 使用数据库管理器获取回复（支持JSON和数据库两种模式）
        replies = db_manager.get_replies()
        logger.debug(f'获取自定义回复列表, 共 {len(replies)} 条')
        response = jsonify(replies)
        response.headers['Cache-Control'] = 'no-store, no-cache, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response
    except Exception as e:
        logger.error(f'获取回复列表失败: {e}')
        return jsonify({'error': '获取失败'}), 500


@app.route('/api/replies', methods=['POST'])
@require_login
def add_or_update_reply():
    """添加或更新自定义回复"""
    try:
        data = request.get_json()
        
        # 验证必需字段
        if not data.get('keyword') or not data.get('replyContent'):
            return jsonify({'success': False, 'message': '请填写关键词和回复内容'}), 400
        
        # 检查是否是编辑一个现有的
        reply_id = data.get('id')
        if reply_id:
            # 编辑
            reply_data = {
                'id': reply_id,
                'keyword': data.get('keyword'),
                'match_type': data.get('matchType', 'exact'),
                'reply_type': data.get('replyType', 'text'),
                'reply_content': data.get('replyContent'),
                'priority': data.get('priority', 50),
                'enabled': data.get('enabled', True)
            }
            result = db_manager.update_reply(reply_id, reply_data)
            if result:
                logger.info(f'更新回复规则: {reply_id}')
                return jsonify({'success': True, 'message': '保存成功'})
            else:
                return jsonify({'success': False, 'message': '指定的规则不存在'}), 404
        else:
            # 新增
            new_reply = {
                'id': f"reply-{int(get_current_time().timestamp() * 1000)}",
                'keyword': data.get('keyword'),
                'match_type': data.get('matchType', 'exact'),
                'reply_type': data.get('replyType', 'text'),
                'reply_content': data.get('replyContent'),
                'priority': data.get('priority', 50),
                'enabled': data.get('enabled', True)
            }
            db_manager.add_reply(new_reply)
            logger.info(f'新增回复规则: {new_reply["keyword"]}')
            return jsonify({'success': True, 'message': '保存成功'})
    except Exception as e:
        logger.error(f'保存回复规则失败: {e}')
        return jsonify({'success': False, 'message': f'保存失败: {str(e)}'}), 500


@app.route('/api/replies/<reply_id>', methods=['DELETE'])
@require_login
def delete_reply(reply_id):
    """删除自定义回复"""
    try:
        db_manager.delete_reply(reply_id)
        logger.info(f'删除回复规则: {reply_id}')
        return jsonify({'success': True, 'message': '删除成功'})
    except Exception as e:
        logger.error(f'删除回复规则失败: {e}')
        return jsonify({'success': False, 'message': f'删除失败: {str(e)}'}), 500


@app.route('/api/replies/<reply_id>/toggle', methods=['PUT'])
@require_login
def toggle_reply(reply_id):
    """切换回复规则是否启用"""
    try:
        # 获取现有的回复
        replies = db_manager.get_replies()
        reply = next((r for r in replies if r.get('id') == reply_id), None)
        
        if not reply:
            return jsonify({'success': False, 'message': '指定的规则不存在'}), 404
        
        # 切换启用状态
        new_enabled = not reply.get('enabled', True)
        reply['enabled'] = new_enabled
        
        # 更新到数据库
        db_manager.update_reply(reply_id, reply)
        
        logger.info(f'切换回复规则状态: {reply_id}, 启用={new_enabled}')
        return jsonify({'success': True, 'message': '更新成功'})
    except Exception as e:
        logger.error(f'切换回复规则失败: {e}')
        return jsonify({'success': False, 'message': f'更新失败: {str(e)}'}), 500


# ===================== 微信接口 =====================

def send_wechat_message_to_user(openid, message_content):
    """
    主动发送消息给用户
    需要获取access_token并使用微信API发送
    """
    try:
        access_token = get_wechat_access_token()
        if not access_token:
            logger.error('无法获取AccessToken，消息发送失败')
            return False
        
        # 微信消息发送API
        url = f'https://api.weixin.qq.com/cgi-bin/message/custom/send'
        
        headers = {'Content-Type': 'application/json'}
        
        payload = {
            'touser': openid,
            'msgtype': 'text',
            'text': {
                'content': message_content
            }
        }
        
        params = {'access_token': access_token}
        
        logger.debug(f'发送微信消息 - URL: {url}')
        logger.debug(f'发送微信消息 - openid: {openid}')
        logger.debug(f'发送微信消息 - 消息内容: {message_content[:50]}...')
        
        response = requests.post(
            url,
            params=params,
            json=payload,
            headers=headers,
            timeout=10
        )
        
        logger.debug(f'微信API响应状态码: {response.status_code}')
        logger.debug(f'微信API响应内容: {response.text}')
        
        result = response.json()
        
        if result.get('errcode') == 0:
            logger.info(f'✓ 消息发送成功给用户: {openid}')
            return True
        else:
            error_code = result.get('errcode', 'unknown')
            error_msg = result.get('errmsg', '未知错误')
            logger.error(f'✗ 消息发送失败 (错误码{error_code}): {error_msg}')
            
            # 记录完整的响应用于调试
            logger.error(f'完整响应: {result}')
            return False
    except Exception as e:
        logger.error(f'发送消息异常: {e}')
        import traceback
        logger.error(f'异常堆栈: {traceback.format_exc()}')
        return False



def verify_wechat_signature(signature, timestamp, nonce):
    """
    验证微信服务器签名
    根据微信开发者指南，需要验证请求来自微信服务器
    """
    WECHAT_TOKEN = os.getenv('WECHAT_TOKEN', 'change_me')
    # 按照微信规则：将token、timestamp、nonce三个参数进行字典序排序
    data = sorted([WECHAT_TOKEN, timestamp, nonce])
    # 将三个参数字符串拼接成一个字符串进行sha1加密
    code = ''.join(data)
    code = hashlib.sha1(code.encode()).hexdigest()
    # 生成的摘要与signature对比，相等则请求来自微信
    is_valid = code == signature
    
    # 详细日志，便于调试
    logger.debug(f'微信签名验证: token={WECHAT_TOKEN}, timestamp={timestamp}, nonce={nonce}')
    logger.debug(f'计算的签名: {code}')
    logger.debug(f'微信发来的签名: {signature}')
    logger.debug(f'验证结果: {"通过" if is_valid else "失败"}')
    
    return is_valid

def load_trigger_keywords():
    """
    加载触发关键词配置
    """
    try:
        config = db_manager.get_trigger_keywords()
        if config:
            return config
    except Exception as e:
        logger.error(f'加载触发关键词配置失败: {e}')
    return None

def should_trigger_code_generation(content, trigger_keywords):
    """
    检查消息是否应该触发自动生成激活码
    老版逻辑：检查消息是否包含任何一个关键词（OR 操作）
    """
    if not trigger_keywords or not trigger_keywords.get('keywords'):
        return False
    
    keywords = trigger_keywords.get('keywords', [])
    # 检查消息中是否包含任何一个关键词
    for keyword in keywords:
        if keyword in content:
            return True
    
    return False

def parse_wechat_message(data):
    """
    解析微信 XML 格式的消息
    """
    try:
        root = ET.fromstring(data)
        msg = {}
        for child in root:
            msg[child.tag] = child.text
        return msg
    except Exception as e:
        logger.error(f'解析微信消息失败: {e}')
        return None

def create_wechat_response(from_user, to_user, content, msg_type='text'):
    """
    创建微信 XML 格式的回复
    符合微信消息格式规范
    """
    create_time = int(get_current_time().timestamp())
    response = f'''<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[{msg_type}]]></MsgType>
<Content><![CDATA[{content}]]></Content>
</xml>'''
    return response

def create_wechat_news_response(from_user, to_user, news_items):
    """
    创建微信图文消息 XML 格式
    根据微信公众号开发者规范
    https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Service_Center_messages.html
    
    Args:
        from_user: 接收者(PublicAccount)
        to_user: 发送者(User)
        news_items: 图文项目列表
                    [
                        {
                            'title': '文章标题',
                            'description': '文章描述',
                            'picUrl': '图片URL',
                            'url': '链接URL'
                        }
                    ]
    """
    create_time = int(get_current_time().timestamp())
    items_xml = ''
    for item in news_items:
        items_xml += f'''<item>
<Title><![CDATA[{item.get('title', '')}]]></Title>
<Description><![CDATA[{item.get('description', '')}]]></Description>
<PicUrl><![CDATA[{item.get('picUrl', '')}]]></PicUrl>
<Url><![CDATA[{item.get('url', '')}]]></Url>
</item>
'''
    
    response = f'''<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[news]]></MsgType>
<ArticleCount>{len(news_items)}</ArticleCount>
<Articles>
{items_xml}</Articles>
</xml>'''
    return response

def match_custom_reply(user_message):
    """
    查找匹配的自定义回复（改进版）
    优先级：精确匹配 > 包含匹配 > 模糊匹配
    支持旧版的隐性匹配（在消息中找到关键词）
    返回整个回复对象，包含类型信息
    """
    try:
        # 使用改进的 get_reply_by_keyword 方法
        reply = db_manager.get_reply_by_keyword(user_message)
        return reply if reply else None
    except Exception as e:
        logger.error(f'查询自定义回复失败: {e}')
        return None

def handle_activation_code(user_message):
    """
    处理激活码验证（改进版）
    当用户发送激活码时自动验证
    支持 4-32 位激活码，返回详细的验证结果
    """
    # 检测用户消息是否可能是激活码
    # 激活码通常是 4-32 位的字母数字组合，可以包含横线或不含空格
    code = user_message.strip().upper()
    
    # 简单的激活码格式校验（可根据实际情况调整）
    if 4 <= len(code) <= 32 and code.replace('-', '').isalnum():
        try:
            # 调用激活码验证接口
            codes = db_manager.get_codes()
            for code_obj in codes:
                if code_obj.get('code', '').upper() == code:
                    status = code_obj.get('status')
                    if status == 'unused':
                        # 有效的激活码
                        expires_at = code_obj.get('expiresAt', '')
                        expires_display = ''
                        try:
                            if expires_at:
                                expires_dt = datetime.fromisoformat(expires_at)
                                expires_display = f"过期时间: {expires_dt.strftime('%Y-%m-%d %H:%M:%S')}"
                        except:
                            pass
                        return f'✓ 激活码有效！\n\n激活码: {code}\n状态: 未使用\n{expires_display}\n\n请妥善保管你的激活码。'
                    elif status == 'used':
                        # 已使用的激活码
                        used_at = code_obj.get('usedAt', '')
                        used_display = ''
                        try:
                            if used_at:
                                used_dt = datetime.fromisoformat(used_at)
                                used_display = f"使用时间: {used_dt.strftime('%Y-%m-%d %H:%M:%S')}"
                        except:
                            pass
                        return f'✗ 激活码已使用\n\n激活码: {code}\n{used_display}\n\n如需要新的激活码，请发送"生成激活码"申请。'
                    elif status == 'expired':
                        # 已过期的激活码
                        expires_at = code_obj.get('expiresAt', '')
                        expired_display = ''
                        try:
                            if expires_at:
                                expires_dt = datetime.fromisoformat(expires_at)
                                expired_display = f"过期时间: {expires_dt.strftime('%Y-%m-%d %H:%M:%S')}"
                        except:
                            pass
                        return f'✗ 激活码已过期\n\n激活码: {code}\n{expired_display}\n\n暂无法使用。请联系管理员申请新码。'
            
            # 激活码不存在
            return f'✗ 激活码不存在或无效\n\n激活码: {code}\n\n请检查输入是否正确。'
        except Exception as e:
            logger.error(f'验证激活码失败: {e}')
            return '验证失败，请稍后重试。'
    
    return None

def is_activation_code_format(content):
    """
    检查是否为激活码格式
    对应老版的is_activation_code_format函数
    """
    # 移除可能的分隔符
    normalized_content = content.replace('-', '').replace('_', '')
    
    # 检查长度和基本格式
    if not (6 <= len(normalized_content) <= 12 and normalized_content.isalnum()):
        return False
    
    # 检查是否只包含系统生成时使用的字符集（排除容易混淆的字符）
    # 系统生成的激活码不会包含 0, O, 1, I 这些容易混淆的字符
    forbidden_chars = {'0', 'O', '1', 'I'}
    if any(c in forbidden_chars for c in normalized_content):
        return False
    
    # 检查是否为常见英文单詞或命令词（排除特定关键词）
    common_words = {
        'CARPLAY', 'HELLO', 'WORLD', 'TEST', 'CODE', 'ADMIN', 'USER', 
        'HELP', 'MENU', 'ABOUT', 'KEY', '客服', '关于', '你好', '功能'
    }
    
    # 转换为大写以便比较
    content_upper = normalized_content.upper()
    
    # 如果是常见英文单詞或命令词，则不认为是激活码
    if content_upper in common_words:
        return False
    
    # 检查字符组合模式：更灵活的判断规则
    has_letters = any(c.isalpha() for c in normalized_content)
    has_digits = any(c.isdigit() for c in normalized_content)
    
    # 对于字母数字混合的激活码，确保不是常见的英文单詞模式
    if has_letters and has_digits:
        # 检查是否是驻峰命名或单詞组合（如CarPlay这种格式）
        camel_case_pattern = False
        for i in range(1, len(normalized_content) - 1):
            if (normalized_content[i-1].islower() and normalized_content[i].isupper() and 
                normalized_content[i+1].islower()):
                camel_case_pattern = True
                break
        
        # 如果是驻峰命名格式，很可能是普通英文单詞，不是激活码
        if camel_case_pattern:
            return False
    
    return True

def process_wechat_command(openid, content):
    try:
        content_lower = content.lower().strip()
        # 1. 优先检查自定义回复
        custom_reply = match_custom_reply(content)
        if custom_reply:
            logger.info(f'✓ 自定义回复匹配: {content}')
            # 返回下面是整个回复对象，包含类型信息
            return custom_reply
        
        # 1.5. 检查是否是"申请激活码"类型的请求
        if content_lower in ['申请激活码', '请求激活码', '我要激活码', '申请', '需要激活码', '生成激活码']:
            logger.info(f'检测到申请激活码请求, 自动生成激活码')
            generate_result = db_manager.generate_code_advanced(
                openid=openid,
                length=8,
                format_type='ALPHANUMERIC',
                is_vip=False
            )
            
            if generate_result['success']:
                code = generate_result['code']
                expires_at_display = generate_result.get('expires_at_display', '')
                message = f'🎉 稍等，您的激活码已生成\n\n🎯 激活码: {code}\n⏰ 有效期: {expires_at_display}\n\n✅ 激活码已为您生成，即可使用。'
                logger.info(f'🌟 成功为用户 {openid} 生成激活码: {code}')
                return message
            else:
                logger.warning(f'🚨 为用户 {openid} 生成激活码失败')
                return '🚨 激活码生成失败，请稍后重试'
        
        # 2. 检查激活码生成关键词
        trigger_keywords = load_trigger_keywords()
        if trigger_keywords and should_trigger_code_generation(content, trigger_keywords):
            logger.info(f'🆘 検测到触发关键词，详情: openid={openid}, content={content}')
            is_vip = trigger_keywords.get('config', {}).get('isVIP', False)
            logger.debug(f'传入generate_code_advanced的参数: openid={openid}, is_vip={is_vip}')
            generate_result = db_manager.generate_code_advanced(
                openid=openid,
                length=8,
                format_type='ALPHANUMERIC',
                is_vip=is_vip
            )
            
            if generate_result['success']:
                code = generate_result['code']
                expires_at_display = generate_result.get('expires_at_display', '')
                logger.info(f'✅ 激活码存储成功: code={code}, openid={openid}')
                
                # 使用自定义的预览模板
                preview = trigger_keywords.get('preview', {})
                chat_reply = preview.get('chatReply', '✓ 您的激活码已生成，详情请查看报文消息。')
                push_message = preview.get('pushMessage', f'🎉 您的激活码已生成\n\n🎯 激活码: {code}\n⏰ 有效期: {expires_at_display}\n\n✅ 激活码已为您生成，即可使用。')
                
                # 替换模板中的占位符
                push_message = push_message.replace('XXXXXXXX', code).replace('2025-11-14 17:00:21', expires_at_display)
                
                logger.info(f'✅ 激活码存储成功: code={code}, openid={openid}')
                logger.info(f'使用自定义模板回复用户: {code}')
                return push_message
            else:
                return '激活码生成失败，请稍后重试'
        
        # 3. 检查是否为激活码格式（使用激活码）
        if is_activation_code_format(content):
            logger.info(f'检测到激活码使用计划: {content}')
            code_response = handle_activation_code(content.upper())
            if code_response:
                return code_response
        
        # 4. 内置指令
        if content_lower in ['我的激活码', '激活码历史', '历史记录', '我的记录']:
            logger.info('用户查询激活码历史')
            user_codes = db_manager.get_codes()
            user_code_list = [c for c in user_codes if c.get('openid') == openid]
            if user_code_list:
                result = '📋 你的激活码历史\n\n'
                for code in user_code_list:
                    result += f"{code['code']} - {code['status']}\n"
                return result
            else:
                return '你还没有任何激活码'
        
        elif content_lower in ['激活码状态', '当前状态', '状态查询']:
            logger.info('用户查询激活码状态')
            user_codes = db_manager.get_codes()
            active_code = None
            for code in user_codes:
                if code.get('openid') == openid and code.get('status') == 'unused':
                    active_code = code
                    break
            
            if active_code:
                expires_at = active_code.get('expiresAt', '')
                created_at = active_code.get('createdAt', '')
                result = f'🟢 你当前有有效的激活码\n\n'
                result += f'激活码：{active_code["code"]}\n'
                if created_at:
                    result += f'创建时间：{created_at}\n'
                if expires_at:
                    result += f'过期时间：{expires_at}\n'
                result += f'状态：未使用\n\n⚠️ 请妥善保管你的激活码！'
                return result
            else:
                return '🔴 你没有有效的激活码。发送"激活码"获取新的激活码。'
        
        elif content_lower in ['帮助', 'help', '使用说明', '指令']:
            logger.info('用户请求帮助')
            return '''📋 你好,欢迎使用我们的激活码系统！

❔ 常见问题：
1. 如何获取激活码？
   发送"申请激活码"或"我要激活码"即可自动获取

2. 激活码有效期多长？
   一般是24小时，请及时使用

3. 激活码过期了怎办？
   请重新发送"申请激活码"获取新的

4. 如何确认激活码是否有效？
   直接发送激活码给我，我会立即验证

5. 如何查看我的激活码历史？
   发送"我的激活码"或"激活码历史"查看

💡 更多功能请发送"菜单"查看。'''
        
        elif content_lower in ['菜单', 'menu', '功能']:
            logger.info('用户请求菜单')
            return '''🏧 功能菜单

📱 激活码相关：
• 生成激活码 - 获取新的激活码
• 我的激活码 - 查看激活码历史记录
• 激活码状态 - 查看当前激活码状态
• [直接输入激活码] - 立即使用激活码

📋 常用功能：
• 帮助 - 查看完整功能使用说明
• 菜单 - 查看所有可用功能

💡 使用提示：
直接发送以上关键词即可使用对应功能！'''
        
        # 5. 默认回复
        logger.info('使用默认回复')
        return f'''❌ 抱歉,我未能理解您发送的内容：\"{content}\"

✨ 推荐使用这些功能哦：
📌 发送「生成激活码」→ 获取新激活码
📌 发送「菜单」→ 查看所有可用功能
📌 发送「帮助」→ 获取详细使用说明

💡 直接发送激活码，就能立即使用啦～

有任何疑问，发送「徐大兵」就能获取支持哦～'''
    
    except Exception as e:
        logger.error(f'处理消息异常: {e}')
        return '⚠️ 出错了,请稍后重试。'

@app.route('/wechat', methods=['GET', 'POST'])
def wechat_handler():
    """
    微信消息处理端点
    符合微信开发者指南的完整实现
    
    GET请求：用于微信公众号配置验证
    POST请求：用于接收和处理微信消息
    """
    # 检查Token配置
    WECHAT_TOKEN = os.getenv('WECHAT_TOKEN', '')
    if not WECHAT_TOKEN or WECHAT_TOKEN == 'change_me':
        error_msg = 'WeChat Token未配置。请在.env文件中设置WECHAT_TOKEN'
        logger.error(error_msg)
        if request.method == 'GET':
            return error_msg, 400
        else:
            return ''
    
    if request.method == 'GET':
        # 微信服务器验证（GET 请求）
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        
        logger.info(f'收到微信验证请求: signature={signature}, timestamp={timestamp}, nonce={nonce}')
        
        # 验证签名
        if verify_wechat_signature(signature, timestamp, nonce):
            logger.info('✓ 微信服务器验证成功')
            return echostr
        else:
            logger.warning('✗ 微信服务器验证失败 - 签名不匹配')
            return 'invalid signature', 403
    
    else:
        # 处理微信消息（POST 请求）
        try:
            # 首先验证POST请求的签名
            signature = request.args.get('signature', '')
            timestamp = request.args.get('timestamp', '')
            nonce = request.args.get('nonce', '')
            
            if not verify_wechat_signature(signature, timestamp, nonce):
                logger.warning('✗ POST请求签名验证失败')
                return ''
            
            # 解析微信消息
            data = request.get_data(as_text=True)
            logger.debug(f'收到微信消息数据: {data[:200]}...')
            
            msg = parse_wechat_message(data)
            
            if not msg:
                logger.error('微信消息解析失败')
                return ''
            
            # 提取消息信息
            from_user = msg.get('FromUserName', '')
            to_user = msg.get('ToUserName', '')
            msg_type = msg.get('MsgType', '')
            msg_id = msg.get('MsgId', '')
            content = msg.get('Content', '').strip()
            
            logger.info(f'✓ 收到微信消息 [ID={msg_id}]: 来自={from_user}, 类型={msg_type}, 内容={content}')
            
            # 记录用户信息（用于后期主动发送消息）
            # 使用 get_user_by_openid 更加可靠，避免重复记录
            existing_user = db_manager.get_user_by_openid(from_user)
            if not existing_user:
                new_user = {
                    'id': f'user-{int(get_current_time().timestamp() * 1000)}',
                    'openId': from_user,
                    'nickname': msg.get('FromUserName', '未知用户'),
                    'subscribeTime': get_current_time().isoformat(),
                    'activationStatus': 'none',
                    'createdAt': get_current_time().isoformat()
                }
                db_manager.add_user(new_user)
                logger.info(f'✓ 记录新用户: {from_user}')
            else:
                logger.debug(f'用户已存在: {from_user}')
            
            # 默认回复内容
            reply_content =(
               "✨感谢关注！\n"
               "\n"
               "→ 回复 【菜单】  解锁全部内容\n"
               "→ 回复 【徐大兵】  联系博主进群\n"
            ) 
            reply_type = 'text'
            
            # 处理文本消息
            if msg_type == 'text':
                # 使用新的统一消息处理逻辑
                reply_result = process_wechat_command(from_user, content)
                
                # 检查是否是自定义回复对象（包含类型信息）
                if isinstance(reply_result, dict) and 'reply_type' in reply_result:
                    reply_type = reply_result.get('reply_type', 'text')
                    if reply_type == 'news':
                        # 图文消息，将JSON解析
                        try:
                            news_data = json.loads(reply_result.get('reply_content', '{}'))
                            # 将单个图文包装成列表
                            news_items = [news_data] if isinstance(news_data, dict) else news_data
                            logger.info(f'✓ 回复图文消息: {news_data.get("title", "")}')
                            response = create_wechat_news_response(to_user, from_user, news_items)
                            logger.debug(f'返回微信图文回复: {response[:200]}...')
                            return response
                        except Exception as e:
                            logger.error(f'图文消息格式化失败: {e}')
                            reply_content = '图文消息格式错误'
                    else:
                        # 正常回复（文本、图片、语音）
                        reply_content = reply_result.get('reply_content', '')
                else:
                    # 不是自定义回复，简单的字符串结果
                    reply_content = reply_result if reply_result else '感谢您的消息，稍后回复您。'
                logger.info(f'✓ 处理用户消息完成，准备回复')
            else:
                logger.info(f'暂不支持处理 {msg_type} 类型消息')
            
            # 创建微信格式的回复
            response = create_wechat_response(to_user, from_user, reply_content, 'text')
            logger.debug(f'返回微信回复: {response[:100]}...')
            
            return response
        
        except Exception as e:
            logger.error(f'微信消息处理错误: {e}', exc_info=True)
            # 返回空回复（微信会显示"该公众号暂时无法提供服务"）
            return ''


@app.route('/verify', methods=['GET'])
def verify():
    """系统状态验证"""
    return jsonify({
        'status': 'ok',
        'version': '1.0.0',
        'timestamp': get_current_time().isoformat()
    })


@app.route('/api/wechat/access-token', methods=['GET'])
@require_login
def api_get_wechat_access_token():
    """
    获取微信 AccessToken
    仅在後台使用
    """
    try:
        access_token = get_wechat_access_token()
        if access_token:
            return jsonify({
                'success': True,
                'access_token': access_token,
                'timestamp': get_current_time().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'message': '无效的 AppID 或 AppSecret'
            }), 400
    except Exception as e:
        logger.error(f'获取 AccessToken 错误: {e}')
        return jsonify({
            'success': False,
            'message': '\u670d務器错误'
        }), 500





@app.route('/api/wechat/message/decrypt', methods=['POST'])
@require_login
def api_decrypt_wechat_message():
    """
    解密微信安全模式的消息
    
    请求体:
    {
        "msg_signature": "...",
        "timestamp": "123456",
        "nonce": "abc123",
        "data": "...encrypted data..."
    }
    """
    try:
        data = request.get_json() or {}
        msg_signature = data.get('msg_signature', '')
        timestamp = data.get('timestamp', '')
        nonce = data.get('nonce', '')
        encrypt_data = data.get('data', '')
        
        decrypted = decrypt_wechat_message('aes', msg_signature, timestamp, nonce, encrypt_data)
        
        if decrypted:
            return jsonify({
                'success': True,
                'content': decrypted
            })
        else:
            return jsonify({
                'success': False,
                'message': '\u6d88息解密失败'
            }), 400
    except Exception as e:
        logger.error(f'\u6d88息解密错误: {e}')
        return jsonify({
            'success': False,
            'message': '\u670d務器错误'
        }), 500


@app.route('/api/wechat/message/encrypt', methods=['POST'])
@require_login
def api_encrypt_wechat_message():
    """
    加密微信安全模式的回复消息
    
    请求体:
    {
        "content": "\u56de复内容",
        "timestamp": "123456",
        "nonce": "abc123"
    }
    """
    try:
        data = request.get_json() or {}
        content = data.get('content', '')
        timestamp = data.get('timestamp', '')
        nonce = data.get('nonce', '')
        
        result = encrypt_wechat_message(content, timestamp, nonce)
        
        if result:
            return jsonify({
                'success': True,
                'encrypt': result['encrypt'],
                'msg_signature': result['msg_signature']
            })
        else:
            return jsonify({
                'success': False,
                'message': '\u6d88息加密失败'
            }), 400
    except Exception as e:
        logger.error(f'\u6d88息加密错误: {e}')
        return jsonify({
            'success': False,
            'message': '\u670d務器错误'
        }), 500


@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    logger.warning(f'404错误: {request.url}')
    return jsonify({'error': '页面未找到'}), 404


@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    logger.error(f'500错误: {str(error)}')
    return jsonify({'error': '服务器错误'}), 500


# ===================== 数据初始化 =====================
def init_sample_data():
    """初始化示例数据"""
    codes = db_manager.get_codes()
    if not codes:
        logger.info('初始化示例激活码数据...')
        for i in range(20):
            code_data = {
                'id': f'code-{i+1}',
                'code': generate_code(),
                'created_at': get_current_time() - timedelta(days=random.randint(0, 30)),
                'expires_at': get_current_time() + timedelta(days=7),
                'status': random.choice(['unused', 'used', 'expired']),
                'is_vip': False
            }
            db_manager.add_code(code_data)
    
    users = db_manager.get_users()
    if not users:
        logger.info('初始化示例用户数据...')
        for i in range(15):
            user_data = {
                'id': f'user-{i+1}',
                'open_id': f'openid_{i+1}',
                'nickname': f'用户{i+1}',
                'avatar': 'https://via.placeholder.com/100',
                'subscribe_time': get_current_time() - timedelta(days=random.randint(0, 60)),
                'activation_status': random.choice(['none', 'pending', 'activated']),
                'activation_code': generate_code() if random.random() > 0.3 else None
            }
            db_manager.add_user(user_data)


def init_trigger_keywords():
    """初始化触发关键词配置"""
    config = db_manager.get_trigger_keywords()
    # 检查数据库是否已经有该配置
    if config and config.get('keywords'):
        # 已有配置，不需要初始化
        logger.info(f'触发关键词已存在: {config.get("keywords", [])}')
        return
    
    # 不存在，保存默认配置
    default_keywords = ['生成']
    default_config = {
        'sendMessage': True,
        'sendReply': True,
        'isVIP': False
    }
    db_manager.save_trigger_keywords(default_keywords, default_config)
    logger.info(f'已创建默认触发关键词: {default_keywords}')


# ===================== 应用启动 =====================
if __name__ == '__main__':
    logger.info('=' * 60)
    logger.info('API服务中心启动')
    logger.info(f'存储模式: {"SQLAlchemy数据库" if USE_DATABASE else "JSON文件"}')
    logger.info(f'调试模式: {app.debug}')
    
    # 初始化触发关键词配置
    with app.app_context():
        init_trigger_keywords()
    
    # 初始化示例数据（已禁用）
    # with app.app_context():
    #     init_sample_data()
    
    logger.info('服务启动完成，监听 http://0.0.0.0:5000')
    logger.info('=' * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
