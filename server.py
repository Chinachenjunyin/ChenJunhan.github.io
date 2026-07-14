import json
import os
import time
import uuid
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
TZ = timezone(timedelta(hours=8))


def now():
    return datetime.now(TZ).isoformat()
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
JWT_SECRET = 'blog-secret-2024'
DATA_DIR = os.path.join(BASE_DIR, 'data')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
ARTICLES_FILE = os.path.join(DATA_DIR, 'articles.json')
COMMENTS_FILE = os.path.join(DATA_DIR, 'comments.json')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
OWNER_EMAIL = '3615744342@qq.com'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'mov', 'avi'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def read_json(filepath):
    try:
        if not os.path.exists(filepath):
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def write_json(filepath, data):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def init_data():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        owner = {
            'id': 'u1',
            'email': OWNER_EMAIL,
            'username': '站长',
            'password': bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode(),
            'role': 'admin',
            'avatar': '',
            'createdAt': now()
        }
        write_json(USERS_FILE, [owner])
    if not os.path.exists(ARTICLES_FILE):
        write_json(ARTICLES_FILE, [])
    if not os.path.exists(COMMENTS_FILE):
        write_json(COMMENTS_FILE, [])


def get_user_by_id(uid):
    users = read_json(USERS_FILE)
    for u in users:
        if u['id'] == uid:
            return u
    return None


def require_auth():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None, jsonify({'error': '请先登录'}), 401
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=['HS256'])
        return payload, None, None
    except Exception:
        return None, jsonify({'error': '登录已过期，请重新登录'}), 401


def is_owner(user_dict):
    return user_dict and user_dict.get('email') == OWNER_EMAIL


def require_admin():
    user, err_resp, status = require_auth()
    if err_resp:
        return user, err_resp, status
    if user.get('role') != 'admin':
        return None, jsonify({'error': '仅管理员可操作'}), 403
    return user, None, None


def require_owner():
    user, err_resp, status = require_auth()
    if err_resp:
        return user, err_resp, status
    if not is_owner(user):
        return None, jsonify({'error': '仅站长可操作'}), 403
    return user, None, None


def user_public(u):
    return {
        'id': u['id'], 'email': u['email'], 'username': u['username'],
        'role': u['role'], 'avatar': u.get('avatar', ''),
        'createdAt': u.get('createdAt', '')
    }


def enrich_article(a):
    author = get_user_by_id(a.get('authorId'))
    return {
        **a,
        'authorName': author['username'] if author else '未知',
        'authorAvatar': author.get('avatar', '') if author else '',
        'isOwner': author['email'] == OWNER_EMAIL if author else False
    }


init_data()
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route('/api/upload', methods=['POST'])
def upload_file():
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    if 'file' not in request.files:
        return jsonify({'error': '没有文件'}), 400
    f = request.files['file']
    if f.filename == '' or not f.filename:
        return jsonify({'error': '文件名为空'}), 400
    if not allowed_file(f.filename):
        return jsonify({'error': '不支持的文件类型，支持：' + ', '.join(ALLOWED_EXTENSIONS)}), 400
    ext = f.filename.rsplit('.', 1)[1].lower()
    filename = str(uuid.uuid4())[:10] + '.' + ext
    filepath = os.path.join(UPLOAD_DIR, filename)
    f.save(filepath)
    file_url = '/uploads/' + filename
    media_type = 'video' if ext in {'mp4', 'webm', 'mov', 'avi'} else 'image'
    return jsonify({'url': file_url, 'type': media_type, 'name': filename})


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not email or not username or not password:
        return jsonify({'error': '请填写完整信息'}), 400
    if len(password) < 6:
        return jsonify({'error': '密码至少6位'}), 400
    users = read_json(USERS_FILE)
    if any(u['email'] == email for u in users):
        return jsonify({'error': '该邮箱已注册'}), 400
    user = {
        'id': 'u' + str(int(time.time() * 1000)),
        'email': email,
        'username': username,
        'password': bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        'role': 'user',
        'avatar': '',
        'createdAt': now()
    }
    users.append(user)
    write_json(USERS_FILE, users)
    token = jwt.encode({
        'id': user['id'], 'email': user['email'],
        'role': user['role'], 'username': user['username'],
        'avatar': user.get('avatar', ''),
        'exp': datetime.utcnow() + timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({
        'token': token,
        'user': {**user_public(user), 'isOwner': is_owner(user)}
    })


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '').strip()
    users = read_json(USERS_FILE)
    user = next((u for u in users if u['email'] == email), None)
    if not user or not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': '邮箱或密码错误'}), 401
    token = jwt.encode({
        'id': user['id'], 'email': user['email'],
        'role': user['role'], 'username': user['username'],
        'avatar': user.get('avatar', ''),
        'exp': datetime.utcnow() + timedelta(days=7)
    }, JWT_SECRET, algorithm='HS256')
    return jsonify({
        'token': token,
        'user': {**user_public(user), 'isOwner': is_owner(user)}
    })


@app.route('/api/me', methods=['GET'])
def get_me():
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    u = get_user_by_id(user['id'])
    if not u:
        return jsonify({'error': '用户不存在'}), 404
    result = user_public(u)
    result['isOwner'] = is_owner(u)
    return jsonify(result)


@app.route('/api/articles', methods=['GET'])
def list_articles():
    articles = read_json(ARTICLES_FILE)
    result = [enrich_article(a) for a in articles]
    result.sort(key=lambda a: a.get('createdAt', ''), reverse=True)
    return jsonify(result)


@app.route('/api/articles/<article_id>', methods=['GET'])
def get_article(article_id):
    articles = read_json(ARTICLES_FILE)
    article = next((a for a in articles if a['id'] == article_id), None)
    if not article:
        return jsonify({'error': '文章不存在'}), 404
    return jsonify(enrich_article(article))


@app.route('/api/articles', methods=['POST'])
def create_article():
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()
    tags = data.get('tags', [])
    if not title or not content:
        return jsonify({'error': '标题和内容不能为空'}), 400
    articles = read_json(ARTICLES_FILE)
    article = {
        'id': 'a' + str(int(time.time() * 1000)),
        'title': title,
        'content': content,
        'tags': tags,
        'authorId': user['id'],
        'createdAt': now(),
        'updatedAt': now()
    }
    articles.append(article)
    write_json(ARTICLES_FILE, articles)
    return jsonify(enrich_article(article))


@app.route('/api/articles/<article_id>', methods=['PUT'])
def update_article(article_id):
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    articles = read_json(ARTICLES_FILE)
    idx = next((i for i, a in enumerate(articles) if a['id'] == article_id), None)
    if idx is None:
        return jsonify({'error': '文章不存在'}), 404
    article = articles[idx]
    if article['authorId'] != user['id'] and not is_owner(user):
        return jsonify({'error': '无权修改此文章'}), 403
    data = request.get_json() or {}
    if 'title' in data:
        article['title'] = data['title'].strip()
    if 'content' in data:
        article['content'] = data['content'].strip()
    if 'tags' in data:
        article['tags'] = data['tags']
    article['updatedAt'] = now()
    write_json(ARTICLES_FILE, articles)
    return jsonify(enrich_article(article))


@app.route('/api/articles/<article_id>', methods=['DELETE'])
def delete_article(article_id):
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    articles = read_json(ARTICLES_FILE)
    idx = next((i for i, a in enumerate(articles) if a['id'] == article_id), None)
    if idx is None:
        return jsonify({'error': '文章不存在'}), 404
    article = articles[idx]
    if article['authorId'] != user['id'] and not is_owner(user):
        return jsonify({'error': '无权删除此文章'}), 403
    articles.pop(idx)
    write_json(ARTICLES_FILE, articles)
    return jsonify({'success': True})


@app.route('/api/articles/<article_id>/comments', methods=['GET'])
def get_comments(article_id):
    comments = read_json(COMMENTS_FILE)
    article_comments = [c for c in comments if c['articleId'] == article_id]
    article_comments.sort(key=lambda c: c.get('createdAt', ''))
    return jsonify(article_comments)


@app.route('/api/articles/<article_id>/comments', methods=['POST'])
def create_comment(article_id):
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    data = request.get_json() or {}
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': '评论内容不能为空'}), 400
    if len(content) > 500:
        return jsonify({'error': '评论最多500字'}), 400
    author = get_user_by_id(user['id'])
    parentId = data.get('parentId', '')
    replyTo = ''
    if parentId:
        all_cmts = read_json(COMMENTS_FILE)
        parent = next((c for c in all_cmts if c['id'] == parentId), None)
        if parent:
            replyTo = parent.get('username', '')
    comment = {
        'id': 'c' + str(int(time.time() * 1000)),
        'articleId': article_id,
        'authorId': user['id'],
        'username': author['username'] if author else user.get('username', ''),
        'avatar': author.get('avatar', '') if author else '',
        'content': content,
        'parentId': parentId,
        'replyTo': replyTo,
        'createdAt': now()
    }
    comments = read_json(COMMENTS_FILE)
    comments.append(comment)
    write_json(COMMENTS_FILE, comments)
    return jsonify(comment)


@app.route('/api/articles/<article_id>/comments/<comment_id>', methods=['DELETE'])
def delete_comment(article_id, comment_id):
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    comments = read_json(COMMENTS_FILE)
    idx = next((i for i, c in enumerate(comments) if c['id'] == comment_id and c['articleId'] == article_id), None)
    if idx is None:
        return jsonify({'error': '评论不存在'}), 404
    c = comments[idx]
    if c['authorId'] != user['id'] and not is_owner(user):
        return jsonify({'error': '无权删除此评论'}), 403
    comments.pop(idx)
    # also remove replies to this comment
    comments = [c for c in comments if not (c.get('parentId') == comment_id)]
    write_json(COMMENTS_FILE, comments)
    return jsonify({'success': True})


@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    user, err_resp, status = require_admin()
    if err_resp:
        return err_resp, status
    users = read_json(USERS_FILE)
    articles = read_json(ARTICLES_FILE)
    result = []
    for u in users:
        result.append({
            'id': u['id'],
            'email': u['email'],
            'username': u['username'],
            'role': u['role'],
            'avatar': u.get('avatar', ''),
            'createdAt': u['createdAt'],
            'articleCount': sum(1 for a in articles if a.get('authorId') == u['id'])
        })
    return jsonify(result)


@app.route('/api/admin/articles', methods=['GET'])
def admin_articles():
    user, err_resp, status = require_admin()
    if err_resp:
        return err_resp, status
    articles = read_json(ARTICLES_FILE)
    result = [enrich_article(a) for a in articles]
    result.sort(key=lambda a: a.get('createdAt', ''), reverse=True)
    return jsonify(result)


@app.route('/api/admin/users/<user_id>', methods=['PUT'])
def update_user_role(user_id):
    user, err_resp, status = require_owner()
    if err_resp:
        return err_resp, status
    users = read_json(USERS_FILE)
    idx = next((i for i, u in enumerate(users) if u['id'] == user_id), None)
    if idx is None:
        return jsonify({'error': '用户不存在'}), 404
    target = users[idx]
    data = request.get_json() or {}
    if 'role' in data:
        if data['role'] not in ('user', 'admin'):
            return jsonify({'error': '无效的角色'}), 400
        if target['id'] == user['id']:
            return jsonify({'error': '不能修改自己的角色'}), 400
        target['role'] = data['role']
    if 'avatar' in data:
        target['avatar'] = data['avatar']
    write_json(USERS_FILE, users)
    return jsonify(user_public(target))


@app.route('/api/me/avatar', methods=['PUT'])
def update_avatar():
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    data = request.get_json() or {}
    avatar = data.get('avatar', '').strip()
    users = read_json(USERS_FILE)
    idx = next((i for i, u in enumerate(users) if u['id'] == user['id']), None)
    if idx is None:
        return jsonify({'error': '用户不存在'}), 404
    users[idx]['avatar'] = avatar
    write_json(USERS_FILE, users)
    return jsonify(user_public(users[idx]))


@app.route('/api/me/password', methods=['PUT'])
def change_password():
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    data = request.get_json() or {}
    current_password = data.get('currentPassword', '')
    new_password = data.get('newPassword', '').strip()
    if not current_password or not new_password:
        return jsonify({'error': '请填写当前密码和新密码'}), 400
    if len(new_password) < 6:
        return jsonify({'error': '新密码至少6位'}), 400
    users = read_json(USERS_FILE)
    idx = next((i for i, u in enumerate(users) if u['id'] == user['id']), None)
    if idx is None:
        return jsonify({'error': '用户不存在'}), 404
    if not bcrypt.checkpw(current_password.encode(), users[idx]['password'].encode()):
        return jsonify({'error': '当前密码错误'}), 403
    users[idx]['password'] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    write_json(USERS_FILE, users)
    return jsonify({'success': True})


@app.route('/api/me', methods=['PUT'])
def update_me():
    user, err_resp, status = require_auth()
    if err_resp:
        return err_resp, status
    data = request.get_json() or {}
    users = read_json(USERS_FILE)
    idx = next((i for i, u in enumerate(users) if u['id'] == user['id']), None)
    if idx is None:
        return jsonify({'error': '用户不存在'}), 404
    if 'username' in data:
        users[idx]['username'] = data['username'].strip()
    if 'avatar' in data:
        users[idx]['avatar'] = data['avatar'].strip()
    write_json(USERS_FILE, users)
    return jsonify(user_public(users[idx]))


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3001, debug=False)
