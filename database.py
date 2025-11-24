#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
WeChat Activation Manager - 数据库模型和管理
支持SQLite和PostgreSQL
"""

from datetime import datetime, timedelta
import json
import random
import string
import secrets
import sqlite3
from pathlib import Path
import pytz
from typing import Optional, Dict, Any

# ===================== 时区配置 =====================
CHINA_TZ = pytz.timezone('Asia/Shanghai')

def get_current_time():
    """获取当前中国时间"""
    return datetime.now(CHINA_TZ)

def get_utc_time():
    """获取UTC时间用于数据库存储"""
    return get_current_time().astimezone(pytz.utc)

# ===================== JSON存储方案 =====================

class JSONStorage:
    """基于JSON文件的存储方案"""
    
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.codes_file = self.data_dir / "codes.json"
        self.users_file = self.data_dir / "users.json"
        self.replies_file = self.data_dir / "replies.json"

        self.wechat_file = self.data_dir / "wechat.json"
    
    def load_json(self, file_path, default=None):
        """加载JSON文件"""
        if default is None:
            default = []
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return default
        return default
    
    def save_json(self, file_path, data):
        """保存JSON文件"""
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    # 激活码操作
    def get_codes(self):
        return self.load_json(self.codes_file, [])
    
    def save_codes(self, codes):
        self.save_json(self.codes_file, codes)
    
    def add_code(self, code_data):
        codes = self.get_codes()
        codes.append(code_data)
        self.save_codes(codes)
        return code_data
    
    def update_code(self, code_id, updates):
        codes = self.get_codes()
        for i, code in enumerate(codes):
            if code['id'] == code_id:
                codes[i].update(updates)
                self.save_codes(codes)
                return codes[i]
        return None
    
    def delete_code(self, code_id):
        codes = self.get_codes()
        codes = [c for c in codes if c['id'] != code_id]
        self.save_codes(codes)
    
    # 用户操作
    def get_users(self):
        return self.load_json(self.users_file, [])
    
    def save_users(self, users):
        self.save_json(self.users_file, users)
    
    def add_user(self, user_data):
        users = self.get_users()
        users.append(user_data)
        self.save_users(users)
        return user_data
    
    # 自定义回复操作
    def get_replies(self):
        return self.load_json(self.replies_file, [])
    
    def save_replies(self, replies):
        self.save_json(self.replies_file, replies)
    
    def add_reply(self, reply_data):
        replies = self.get_replies()
        replies.append(reply_data)
        self.save_replies(replies)
        return reply_data
    

    
    # 微信配置操作
    def get_wechat_config(self):
        return self.load_json(self.wechat_file, {})
    
    def save_wechat_config(self, config):
        self.save_json(self.wechat_file, config)


# ===================== SQLAlchemy数据库方案 =====================

try:
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
    
    db = SQLAlchemy()
    
    class ActivationCode(db.Model):
        """激活码模型"""
        __tablename__ = 'activation_codes'
        
        id = Column(String(50), primary_key=True)
        code = Column(String(20), unique=True, nullable=False)
        user_id = Column(String(50))
        user_name = Column(String(100))
        created_at = Column(DateTime, default=get_current_time)
        expires_at = Column(DateTime, nullable=False)
        used_at = Column(DateTime)
        status = Column(String(20), default='unused')  # unused, used, expired
        is_vip = Column(Boolean, default=False)
        vip_level = Column(Integer)
        features = Column(Text)  # JSON格式
        
        def to_dict(self):
            return {
                'id': self.id,
                'code': self.code,
                'openid': self.user_id,
                'userId': self.user_id,
                'userName': self.user_name,
                'createdAt': self.created_at.isoformat() if isinstance(self.created_at, datetime) else None,
                'expiresAt': self.expires_at.isoformat() if isinstance(self.expires_at, datetime) else None,
                'usedAt': self.used_at.isoformat() if isinstance(self.used_at, datetime) else None,
                'status': self.status,
                'isVIP': self.is_vip,
                'vipLevel': self.vip_level,
                'features': json.loads(self.features) if isinstance(self.features, str) and len(self.features) > 0 else []
            }
    
    class User(db.Model):
        """用户模型"""
        __tablename__ = 'users'
        
        id = Column(String(50), primary_key=True)
        open_id = Column(String(100), unique=True, nullable=False)
        nickname = Column(String(100), nullable=False)
        avatar = Column(String(255))
        subscribe_time = Column(DateTime, default=get_current_time)
        activation_status = Column(String(20), default='none')  # none, pending, activated
        activation_code = Column(String(20))
        last_login_time = Column(DateTime)
        created_at = Column(DateTime, default=get_current_time)
        city = Column(String(100))  # 城市信息
        last_ip = Column(String(50))  # 最后访问IP
        visit_count = Column(Integer, default=0)  # 访问次数
        
        def to_dict(self):
            return {
                'id': self.id,
                'openId': self.open_id,
                'nickname': self.nickname,
                'avatar': self.avatar,
                'subscribeTime': self.subscribe_time.isoformat() if isinstance(self.subscribe_time, datetime) else None,
                'activationStatus': self.activation_status,
                'activationCode': self.activation_code,
                'lastLoginTime': self.last_login_time.isoformat() if isinstance(self.last_login_time, datetime) else None,
                'city': self.city,
                'lastIp': self.last_ip,
                'visitCount': self.visit_count
            }
    
    class CustomReply(db.Model):
        """自定义回复模型"""
        __tablename__ = 'custom_replies'
        
        id = Column(String(50), primary_key=True)
        keyword = Column(String(100), nullable=False)
        reply_content = Column(Text, nullable=False)
        reply_type = Column(String(20), default='text')  # text, image, voice, video, news
        match_type = Column(String(20), default='exact')  # exact, contains
        priority = Column(Integer, default=50)  # 优先级，数字越大优先级越高
        enabled = Column(Boolean, default=True)
        created_at = Column(DateTime, default=get_current_time)
        updated_at = Column(DateTime, default=get_current_time, onupdate=get_current_time)
        
        def to_dict(self):
            return {
                'id': self.id,
                'keyword': self.keyword,
                'reply_content': self.reply_content,
                'replyContent': self.reply_content,
                'reply_type': self.reply_type,
                'replyType': self.reply_type,
                'match_type': self.match_type,
                'matchType': self.match_type,
                'priority': getattr(self, 'priority', 50),
                'enabled': self.enabled,
                'createdAt': self.created_at.isoformat() if isinstance(self.created_at, datetime) else None,
                'updatedAt': self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else None
            }
    
    class WechatConfig(db.Model):
        """微信配置模型"""
        __tablename__ = 'wechat_config'
        
        id = Column(String(50), primary_key=True, default='default')
        app_id = Column(String(100))
        app_secret = Column(String(100))
        token = Column(String(100))
        encryption_key = Column(String(100))
        server_url = Column(String(255))
        api_version = Column(String(20), default='v1.0.0')
        created_at = Column(DateTime, default=get_current_time)
        updated_at = Column(DateTime, default=get_current_time, onupdate=get_current_time)
        
        def to_dict(self):
            return {
                'appId': self.app_id,
                'appSecret': self.app_secret,
                'token': self.token,
                'encryptionKey': self.encryption_key,
                'serverUrl': self.server_url,
                'apiVersion': self.api_version
            }
    
    class TriggerKeyword(db.Model):
        """触发关键词配置模型"""
        __tablename__ = 'trigger_keywords'
        
        id = Column(String(50), primary_key=True, default='default')
        keywords = Column(Text, nullable=False)  # JSON数组
        config = Column(Text)  # JSON格式的配置
        preview = Column(Text)  # JSON格式的预览内容
        created_at = Column(DateTime, default=get_current_time)
        updated_at = Column(DateTime, default=get_current_time, onupdate=get_current_time)
        
        def to_dict(self):
            try:
                keywords_list = json.loads(self.keywords)
            except:
                keywords_list = []
            try:
                config_data = json.loads(self.config) if self.config else {}
            except:
                config_data = {}
            try:
                preview_data = json.loads(self.preview) if self.preview else {}
            except:
                preview_data = {}
            return {
                'keywords': keywords_list,
                'config': config_data,
                'preview': preview_data,
                'createdAt': self.created_at.isoformat() if isinstance(self.created_at, datetime) else None,
                'updatedAt': self.updated_at.isoformat() if isinstance(self.updated_at, datetime) else None
            }
    
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    db = None


# ===================== 数据库工厂 =====================

class DatabaseManager:
    """数据库管理器 - 支持JSON和SQLAlchemy切换"""
    
    def __init__(self, use_db: bool = False, db_instance: Optional[Any] = None):
        """
        初始化数据库管理器
        :param use_db: 是否使用数据库
        :param db_instance: SQLAlchemy实例
        """
        self.use_db = use_db and DB_AVAILABLE
        self.db: Optional[Any] = db_instance if self.use_db else None
        
        if not self.use_db:
            self.storage = JSONStorage()
    
    # ===================== 新版本激活码逻辑 =====================
    
    def generate_code_advanced(self, openid: str = '', length: int = 8, format_type: str = 'ALPHANUMERIC', is_vip: bool = False) -> dict:
        """
        高级激活码生成逻辑（来自旧版本）
        支持多种格式和防重复检测
        
        Args:
            openid: 用户openid
            length: 激活码长度
            format_type: 激活码格式 (ALPHANUMERIC, NUMERIC, ALPHA)
            is_vip: 是否为VIP码
        
        Returns:
            包含激活码和元数据的字典
        """
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f'[激活码生成] 开始: openid={openid}, is_vip={is_vip}')
        
        max_attempts = 100  # 防止无限循环
        code = None
        
        # 生成激活码
        for _ in range(max_attempts):
            if format_type == 'NUMERIC':
                code = ''.join(secrets.choice(string.digits) for _ in range(length))
            elif format_type == 'ALPHA':
                code = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(length))
            else:  # ALPHANUMERIC (default)
                chars = string.ascii_uppercase + string.digits
                # 排除容易混淆的字符
                chars = chars.replace('0', '').replace('O', '').replace('1', '').replace('I', '')
                code = ''.join(secrets.choice(chars) for _ in range(length))
            
            # 检查是否重复
            if not self._code_exists(code):
                break
        
        if not code:
            return {'success': False, 'message': '激活码生成失败，请稍后重试'}
        
        # 获取过期时间（使用UTC时间存储）
        expiry_hours = 24  # 默认24小时
        expires_at = get_utc_time() + timedelta(hours=expiry_hours)
        
        # 构造完整的激活码对象
        new_code = {
            'id': f"code-{int(get_current_time().timestamp() * 1000)}",
            'code': code,
            'openid': openid,
            'createdAt': get_current_time().isoformat(),
            'expiresAt': expires_at.isoformat(),
            'status': 'unused',
            'isVIP': is_vip,
            'metadata': {
                'format_type': format_type,
                'length': length,
                'generation_method': 'advanced' if openid else 'admin'
            }
        }
        
        # 日志记录激活码对象
        logger.debug(f'[激活码生成] 激活码对象: {new_code}')
        
        # 保存到数据库
        result = self.add_code(new_code)
        logger.info(f'[激活码生成] 保存结果: code={result.get("code")}, openid={result.get("openid")}')
        
        # 转换为中国时间显示
        expires_at_china = expires_at.replace(tzinfo=pytz.UTC).astimezone(CHINA_TZ)
        
        return {
            'success': True,
            'code': code,
            'expires_at': expires_at.isoformat(),
            'expires_at_display': expires_at_china.strftime("%Y-%m-%d %H:%M:%S"),
            'message': f'激活码生成成功！\n\n🎯 您的激活码：{code}\n⏰ 有效期：{expiry_hours}小时\n📅 过期时间：{expires_at_china.strftime("%Y-%m-%d %H:%M:%S")} (北京时间)\n\n请妥善保管您的激活码！',
            'details': result
        }
    
    def use_code_advanced(self, code: str) -> dict:
        """
        高级激活码验证和使用逻辑（来自旧版本）
        支持状态验证、过期检查和事务处理
        
        Args:
            code: 要使用的激活码
        
        Returns:
            包含验证结果的字典
        """
        if self.use_db:
            # 数据库模式
            code_obj = ActivationCode.query.filter_by(code=code.upper()).first()
            
            if not code_obj:
                return {'success': False, 'message': '激活码不存在'}
            
            # 检查是否已使用
            if code_obj.status == 'used':
                return {'success': False, 'message': '激活码已被使用'}
            
            # 检查是否过期
            try:
                expires_at = code_obj.expires_at
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                # 使用北京时间比较
                now = get_current_time()
                
                if expires_at < now:
                    # 标记为过期
                    code_obj.status = 'expired'
                    self.db.session.commit()
                    return {'success': False, 'message': '激活码已过期'}
            except:
                pass
            
            # 标记为已使用
            code_obj.status = 'used'
            code_obj.used_at = get_current_time()
            self.db.session.commit()
            
            # 同步更新对应用户的激活状态
            if code_obj.user_id:
                # 根据user_id查找用户（user_id可能是openid或user_id）
                user = User.query.filter_by(open_id=code_obj.user_id).first()
                if not user:
                    # 尝试用id查找
                    user = User.query.filter_by(id=code_obj.user_id).first()
                
                if user:
                    user.activation_status = 'activated'
                    user.activation_code = code.upper()
                    user.last_login_time = get_current_time()
                    self.db.session.commit()
            
            return {'success': True, 'message': '激活码使用成功'}
        else:
            # JSON 存储模式
            # 获取所有激活码
            codes = self.get_codes()
            
            # 查找激活码
            activation_code = None
            code_index = -1
            for i, c in enumerate(codes):
                if c.get('code') == code.upper():
                    activation_code = c
                    code_index = i
                    break
            
            if not activation_code:
                return {'success': False, 'message': '激活码不存在'}
            
            # 检查是否已使用
            if activation_code.get('status') == 'used':
                return {'success': False, 'message': '激活码已被使用'}
            
            # 检查是否过期
            try:
                expires_at = datetime.fromisoformat(activation_code['expiresAt'])
                # 使用北京时间比较
                now = get_current_time()
                
                if expires_at < now:
                    # 标记为过期
                    codes[code_index]['status'] = 'expired'
                    self.storage.save_codes(codes)
                    return {'success': False, 'message': '激活码已过期'}
            except:
                pass
            
            # 标记为已使用
            codes[code_index]['status'] = 'used'
            codes[code_index]['usedAt'] = get_current_time().isoformat()
            self.storage.save_codes(codes)
            
            return {'success': True, 'message': '激活码使用成功'}
    
    def _code_exists(self, code: str) -> bool:
        """检查激活码是否存在"""
        codes = self.get_codes()
        for c in codes:
            if c.get('code') == code.upper():
                return True
        return False
    
    # ===================== 原有的激活码逻辑 =====================
    def get_codes(self):
        if self.use_db:
            return [code.to_dict() for code in ActivationCode.query.all()]
        return self.storage.get_codes()
    
    def add_code(self, code_data):
        if self.use_db:
            # 转换字段名：驼峰式 -> 蛇形式
            db_data = {}
            field_mapping = {
                'id': 'id',
                'code': 'code',
                'openid': 'user_id',
                'userId': 'user_id',
                'userName': 'user_name',
                'createdAt': 'created_at',
                'expiresAt': 'expires_at',
                'usedAt': 'used_at',
                'status': 'status',
                'isVIP': 'is_vip',
                'vipLevel': 'vip_level',
                'features': 'features'
            }
            
            # 处理字段映射
            for key, value in code_data.items():
                if key == 'metadata':
                    continue  # 跳过metadata字段
                db_key = field_mapping.get(key)
                if db_key:
                    # features字段需要转换为JSON字符串
                    if db_key == 'features':
                        if isinstance(value, list):
                            db_data[db_key] = json.dumps(value) if value else ''
                        elif isinstance(value, str):
                            db_data[db_key] = value
                        else:
                            db_data[db_key] = json.dumps(value) if value else ''
                    else:
                        db_data[db_key] = value
            
            # 确保 user_id 有值（从 openid 或 userId）
            if not db_data.get('user_id'):
                # 如果 user_id 为 None 或不存在，从 openid 或 userId 获取
                db_data['user_id'] = code_data.get('openid') or code_data.get('userId')
            
            # 如果还没有created_at，使用当前时间
            if 'created_at' not in db_data:
                db_data['created_at'] = get_current_time()
            
            # 如果没有expires_at，使用默认值（24小时后）
            if 'expires_at' not in db_data:
                db_data['expires_at'] = get_current_time() + timedelta(hours=24)
            
            # 调试日志
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f'[激活码存储] 输入数据: {code_data}')
            logger.debug(f'[激活码存储] 数据库字段映射前: user_id={db_data.get("user_id")} (from {list(code_data.keys())})')
            logger.debug(f'[激活码存储] 最终数据库字段: {db_data}')
            
            code = ActivationCode(**db_data)
            self.db.session.add(code)
            self.db.session.commit()
            
            result = code.to_dict()
            logger.info(f'[激活码存储] 成功保存: code={result.get("code")}, user_id={result.get("openid") or result.get("userId")}, 映射后: {code.user_id}')
            return result
        return self.storage.add_code(code_data)
    
    def update_code(self, code_id, updates):
        if self.use_db:
            code = ActivationCode.query.get(code_id)
            if code:
                for key, value in updates.items():
                    setattr(code, key, value)
                self.db.session.commit()
                return code.to_dict()
            return None
        return self.storage.update_code(code_id, updates)
    
    def delete_code(self, code_id):
        if self.use_db:
            code = ActivationCode.query.get(code_id)
            if code:
                self.db.session.delete(code)
                self.db.session.commit()
        else:
            self.storage.delete_code(code_id)
    
    # 用户相关
    def get_users(self):
        if self.use_db:
            return [user.to_dict() for user in User.query.all()]
        return self.storage.get_users()
    
    def get_user_by_openid(self, openid: str):
        """根据openid获取用户"""
        if self.use_db:
            user = User.query.filter_by(open_id=openid).first()
            return user.to_dict() if user else None
        users = self.storage.get_users()
        for u in users:
            if u.get('openId') == openid:
                return u
        return None
    
    def get_user(self, user_id: str):
        """根据ID获取单个用户"""
        if self.use_db:
            user = User.query.get(user_id)
            return user.to_dict() if user else None
        users = self.storage.get_users()
        for u in users:
            if u.get('id') == user_id:
                return u
        return None
    
    def add_user(self, user_data):
        """添加用户"""
        if self.use_db:
            # 不转换字段名
            db_data = {}
            field_mapping = {
                'id': 'id',
                'openId': 'open_id',
                'open_id': 'open_id',
                'nickname': 'nickname',
                'avatar': 'avatar',
                'subscribeTime': 'subscribe_time',
                'subscribe_time': 'subscribe_time',
                'activationStatus': 'activation_status',
                'activation_status': 'activation_status',
                'activationCode': 'activation_code',
                'activation_code': 'activation_code',
                'lastLoginTime': 'last_login_time',
                'last_login_time': 'last_login_time',
                'createdAt': 'created_at',
                'created_at': 'created_at',
                'city': 'city',
                'lastIp': 'last_ip',
                'last_ip': 'last_ip',
                'visitCount': 'visit_count',
                'visit_count': 'visit_count'
            }
            for key, value in user_data.items():
                db_key = field_mapping.get(key, key)
                if db_key in ['id', 'open_id', 'nickname', 'avatar', 'subscribe_time', 'activation_status', 'activation_code', 'last_login_time', 'created_at', 'city', 'last_ip', 'visit_count']:
                    db_data[db_key] = value
            
            user = User(**db_data)
            self.db.session.add(user)
            self.db.session.commit()
            return user.to_dict()
        return self.storage.add_user(user_data)
    
    def update_user(self, user_id: str, updates: dict):
        """更新用户信息"""
        if self.use_db:
            user = User.query.get(user_id)
            if user:
                # 转换字段名
                field_mapping = {
                    'openId': 'open_id',
                    'activationStatus': 'activation_status',
                    'activationCode': 'activation_code',
                    'lastLoginTime': 'last_login_time',
                    'createdAt': 'created_at',
                    'subscribeTime': 'subscribe_time',
                    'lastIp': 'last_ip',
                    'visitCount': 'visit_count',
                    'city': 'city'
                }
                for key, value in updates.items():
                    db_key = field_mapping.get(key, key)
                    if hasattr(user, db_key):
                        setattr(user, db_key, value)
                self.db.session.commit()
                return user.to_dict()
            return None
        else:
            users = self.storage.get_users()
            for i, u in enumerate(users):
                if u['id'] == user_id:
                    users[i].update(updates)
                    self.storage.save_users(users)
                    return users[i]
            return None
    
    def delete_user(self, user_id):
        """删除用户"""
        if self.use_db:
            user = User.query.get(user_id)
            if user:
                self.db.session.delete(user)
                self.db.session.commit()
        else:
            users = self.storage.get_users()
            users = [u for u in users if u['id'] != user_id]
            self.storage.save_users(users)
    
    def search_users(self, keyword: str):
        """搜索用户（按昵称或openid）"""
        keyword_lower = keyword.lower().strip()
        users = self.get_users()
        results = []
        for u in users:
            if keyword_lower in u.get('nickname', '').lower() or keyword_lower in u.get('openId', '').lower():
                results.append(u)
        return results
    
    def get_users_by_status(self, status: str):
        """按激活状态获取用户列表"""
        users = self.get_users()
        return [u for u in users if u.get('activationStatus') == status]
    
    def activate_user(self, user_id: str, activation_code: str) -> dict:
        """激活用户（使用激活码）
        类似于 use_code_advanced
        """
        user = self.get_user(user_id)
        if not user:
            return {'success': False, 'message': '用户不存在'}
        
        # 检查激活码是否有效
        code_result = self.use_code_advanced(activation_code)
        if not code_result['success']:
            return code_result
        
        # 更新用户状态
        update_result = self.update_user(user_id, {
            'activationStatus': 'activated',
            'activationCode': activation_code,
            'lastLoginTime': get_current_time().isoformat()
        })
        
        return {
            'success': True,
            'message': '用户激活成功',
            'user': update_result
        }
    
    def batch_activate_users(self, user_ids: list) -> dict:
        """批量激活用户"""
        results = {'success': 0, 'failed': 0, 'details': []}
        
        for user_id in user_ids:
            user = self.get_user(user_id)
            if user:
                update_result = self.update_user(user_id, {
                    'activationStatus': 'activated',
                    'lastLoginTime': get_current_time().isoformat()
                })
                results['success'] += 1
                results['details'].append({
                    'user_id': user_id,
                    'status': 'success',
                    'user': update_result
                })
            else:
                results['failed'] += 1
                results['details'].append({
                    'user_id': user_id,
                    'status': 'failed',
                    'message': '用户不存在'
                })
        
        return results
    
    # ===================== 触发关键词管理 =====================
    
    def get_trigger_keywords(self):
        """获取触发关键词配置"""
        if self.use_db:
            tk = TriggerKeyword.query.filter_by(id='default').first()
            if tk:
                return tk.to_dict()
            # 返回默认配置
            return {
                'keywords': ['生成'],
                'config': {
                    'sendMessage': True,
                    'sendReply': True,
                    'isVIP': False
                },
                'preview': {},
                'createdAt': None,
                'updatedAt': None
            }
        return self.storage.get_trigger_keywords() if hasattr(self.storage, 'get_trigger_keywords') else {}
    
    def save_trigger_keywords(self, keywords: list, config: dict = None, preview: dict = None):
        """保存触发关键词配置"""
        if self.use_db:
            tk = TriggerKeyword.query.filter_by(id='default').first()
            keywords_json = json.dumps(keywords, ensure_ascii=False)
            config_json = json.dumps(config or {}, ensure_ascii=False)
            preview_json = json.dumps(preview or {}, ensure_ascii=False)
            
            if tk:
                tk.keywords = keywords_json
                tk.config = config_json
                tk.preview = preview_json
                tk.updated_at = get_current_time()
            else:
                tk = TriggerKeyword(id='default', keywords=keywords_json, config=config_json, preview=preview_json)
                self.db.session.add(tk)
            
            self.db.session.commit()
            return {'success': True, 'keywords': keywords, 'config': config, 'preview': preview}
        else:
            if hasattr(self.storage, 'save_trigger_keywords'):
                return self.storage.save_trigger_keywords(keywords, config)
            return {'success': True}
    
    # ===================== 自定义回复相关 =====================
    def get_replies(self):
        if self.use_db:
            return [reply.to_dict() for reply in CustomReply.query.filter_by(enabled=True).all()]
        return self.storage.get_replies()
    
    def add_reply(self, reply_data):
        if self.use_db:
            # 转换字段名：驼峰式 -> 蛇形式
            db_data = {}
            field_mapping = {
                'id': 'id',
                'keyword': 'keyword',
                'replyContent': 'reply_content',
                'reply_content': 'reply_content',
                'replyType': 'reply_type',
                'reply_type': 'reply_type',
                'matchType': 'match_type',
                'match_type': 'match_type',
                'priority': 'priority',
                'enabled': 'enabled'
            }
            for key, value in reply_data.items():
                db_key = field_mapping.get(key, key)
                if db_key in ['id', 'keyword', 'reply_content', 'reply_type', 'match_type', 'priority', 'enabled']:
                    db_data[db_key] = value
            
            reply = CustomReply(**db_data)
            self.db.session.add(reply)
            self.db.session.commit()
            return reply.to_dict()
        return self.storage.add_reply(reply_data)
    
    def update_reply(self, reply_id: str, reply_data: dict):
        """更新自定义回复"""
        if self.use_db:
            reply = CustomReply.query.get(reply_id)
            if reply:
                # 转换字段名
                field_mapping = {
                    'keyword': 'keyword',
                    'replyContent': 'reply_content',
                    'reply_content': 'reply_content',
                    'replyType': 'reply_type',
                    'reply_type': 'reply_type',
                    'matchType': 'match_type',
                    'match_type': 'match_type',
                    'priority': 'priority',
                    'enabled': 'enabled'
                }
                for key, value in reply_data.items():
                    db_key = field_mapping.get(key, key)
                    if hasattr(reply, db_key):
                        setattr(reply, db_key, value)
                self.db.session.commit()
                return reply.to_dict()
            return None
        else:
            # JSON 模式
            replies = self.storage.get_replies()
            for i, r in enumerate(replies):
                if r['id'] == reply_id:
                    replies[i].update(reply_data)
                    self.storage.save_replies(replies)
                    return replies[i]
            return None
    
    def delete_reply(self, reply_id: str):
        """删除自定义回复"""
        if self.use_db:
            reply = CustomReply.query.get(reply_id)
            if reply:
                self.db.session.delete(reply)
                self.db.session.commit()
        else:
            replies = self.storage.get_replies()
            replies = [r for r in replies if r['id'] != reply_id]
            self.storage.save_replies(replies)
    
    def get_reply_by_keyword(self, keyword: str) -> dict:
        """
        根据关键词查找自定义回复（改进版）
        支持精确匹配和模糊匹配，优先级逻辑：
        1. 精确匹配 (exact) - 完全相同
        2. 包含匹配 (contains) - 包含关键词
        3. 模糊匹配 - 关键词出现在消息中
        """
        replies = self.get_replies()
        keyword_lower = keyword.lower().strip()
        
        # 第一步：精确匹配（优先级最高）
        for reply in replies:
            # 检查是否启用
            if not reply.get('enabled', True):
                continue
            if reply.get('match_type') == 'exact':
                if reply.get('keyword', '').lower().strip() == keyword_lower:
                    return reply
        
        # 第二步：包含匹配
        for reply in replies:
            # 检查是否启用
            if not reply.get('enabled', True):
                continue
            if reply.get('match_type') == 'contains':
                if reply.get('keyword', '').lower().strip() in keyword_lower:
                    return reply
        
        # 第三步：模糊匹配 - 关键词在消息中（用于旧版兼容）
        best_match = None
        best_match_len = 0
        
        for reply in replies:
            # 检查是否启用
            if not reply.get('enabled', True):
                continue
            keyword_str = reply.get('keyword', '').lower().strip()
            if keyword_str and keyword_str in keyword_lower:
                # 选择最长的匹配（更精确）
                if len(keyword_str) > best_match_len:
                    best_match = reply
                    best_match_len = len(keyword_str)
        
        return best_match
    
    # 统计相关
    def get_statistics(self):
        """获取统计数据"""
        codes = self.get_codes()
        users = self.get_users()
        
        return {
            'total_codes': len(codes),
            'unused_codes': len([c for c in codes if c['status'] == 'unused']),
            'used_codes': len([c for c in codes if c['status'] == 'used']),
            'expired_codes': len([c for c in codes if c['status'] == 'expired']),
            'total_users': len(users),
            'activated_users': len([u for u in users if u['activationStatus'] == 'activated']),
            'pending_users': len([u for u in users if u['activationStatus'] == 'pending'])
        }
    
    # ===================== 清除数据相关 =====================
    def clear_all_data(self):
        """清除所有数据"""
        if self.use_db:
            # 数据库模式
            try:
                ActivationCode.query.delete()
                User.query.delete()
                CustomReply.query.delete()
                self.db.session.commit()
                return {'success': True, 'message': '所有数据已清除'}
            except Exception as e:
                self.db.session.rollback()
                return {'success': False, 'message': f'清除数据失败: {str(e)}'}
        else:
            # JSON 模式
            try:
                self.storage.save_codes([])
                self.storage.save_users([])
                self.storage.save_replies([])
                return {'success': True, 'message': '所有数据已清除'}
            except Exception as e:
                return {'success': False, 'message': f'清除数据失败: {str(e)}'}


# ===================== 初始化函数 =====================

def init_database(app, use_db=False):
    """初始化数据库"""
    if use_db and DB_AVAILABLE:
        db.init_app(app)
        with app.app_context():
            db.create_all()
            # 验证表格是否实际创建了
            import sqlalchemy as sa
            inspector = sa.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f'[数据库成功初始化] 已创建表格: {tables}')
        return DatabaseManager(use_db=True, db_instance=db)
    else:
        return DatabaseManager(use_db=False)
