import hashlib
import uuid
import random
import string
from datetime import datetime, timedelta
from src.models.db import db, User, PasswordResetToken


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, hashed):
    return hash_password(password) == hashed


def create_user(username, password, email=None, role='user'):
    if User.query.filter_by(username=username).first():
        return {'success': False, 'message': '用户名已存在'}
    user = User(
        username=username,
        password_hash=hash_password(password),
        email=email,
        role=role,
        is_active=True
    )
    db.session.add(user)
    db.session.commit()
    return {'success': True, 'user': user.to_dict()}


def get_user(username):
    return User.query.filter_by(username=username).first()


def get_user_by_id(user_id):
    return User.query.get(user_id)


def get_all_users():
    return User.query.all()


def update_user(user_id, data):
    user = User.query.get_or_404(user_id)
    if 'username' in data:
        existing = User.query.filter(User.username == data['username'], User.id != user_id).first()
        if existing:
            return {'success': False, 'message': '用户名已存在'}
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    if 'role' in data:
        user.role = data['role']
    if 'is_active' in data:
        user.is_active = data['is_active']
    db.session.commit()
    return {'success': True, 'user': user.to_dict()}


def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin' and User.query.filter_by(role='admin').count() <= 1:
        return {'success': False, 'message': '至少保留一个管理员账号'}
    db.session.delete(user)
    db.session.commit()
    return {'success': True}


def change_password(user_id, old_password, new_password):
    user = User.query.get_or_404(user_id)
    if not verify_password(old_password, user.password_hash):
        return {'success': False, 'message': '旧密码不正确'}
    user.password_hash = hash_password(new_password)
    db.session.commit()
    return {'success': True}


def generate_reset_code():
    return ''.join(random.choices(string.digits, k=6))


def create_reset_token(user_id):
    token = str(uuid.uuid4())
    code = generate_reset_code()
    expires_at = datetime.now() + timedelta(minutes=30)
    old_tokens = PasswordResetToken.query.filter_by(user_id=user_id).all()
    for t in old_tokens:
        db.session.delete(t)
    reset_token = PasswordResetToken(
        user_id=user_id,
        token=token,
        code=code,
        expires_at=expires_at
    )
    db.session.add(reset_token)
    db.session.commit()
    return {'token': token, 'code': code}


def verify_reset_token(token, code):
    reset_token = PasswordResetToken.query.filter_by(token=token, code=code).first()
    if not reset_token:
        return None
    if datetime.now() > reset_token.expires_at:
        return None
    return reset_token.user


def reset_password(token, code, new_password):
    user = verify_reset_token(token, code)
    if not user:
        return {'success': False, 'message': '验证码无效或已过期'}
    user.password_hash = hash_password(new_password)
    old_tokens = PasswordResetToken.query.filter_by(user_id=user.id).all()
    for t in old_tokens:
        db.session.delete(t)
    db.session.commit()
    return {'success': True}


def init_admin():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        create_user('admin', 'admin', role='admin')