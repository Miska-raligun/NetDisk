from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash,jsonify,abort,send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv  # ✅ 新增
import os,json
import io
import zipfile

load_dotenv()

app = Flask(__name__)
app.secret_key = 'super-secret-key'

UPLOAD_FOLDER = 'uploads'
USER_FILE = 'users.json'
META_FILE = 'filemeta.json'
UPLOAD_LOG_FILE = 'upload_log.json'
DOWNLOAD_LOG_FILE = 'download_log.json'
USER_QUOTA = 500 * 1024 * 1024 * 1024  
TOTAL_QUOTA = 3 * 1024 * 1024 * 1024 * 1024

SUPER_ADMIN = {
    'username': os.getenv('ADMIN_USERNAME', 'admin'),
    'password': os.getenv('ADMIN_PASSWORD', 'admin123')
}

def ensure_initial_files():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    for file in [USER_FILE, META_FILE, UPLOAD_LOG_FILE, DOWNLOAD_LOG_FILE]:
        if not os.path.exists(file):
            with open(file, 'w') as f:
                json.dump({} if 'log' not in file else [], f)  # 日志文件为 []，其他为 {}

    # ✅ 确保超级管理员用户被视为已注册用户（可选）
    users = {}
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r') as f:
            try:
                users = json.load(f)
            except:
                pass
    if SUPER_ADMIN['username'] not in users:
        users[SUPER_ADMIN['username']] = {
            'password': generate_password_hash(SUPER_ADMIN['password']),
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        with open(USER_FILE, 'w') as f:
            json.dump(users, f, indent=2)

def get_total_used_space():
    total = 0
    for root, _, files in os.walk(UPLOAD_FOLDER):
        for f in files:
            fp = os.path.join(root, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total

def get_total_user_used_space(user_name):
    total = 0
    user_root = os.path.join(UPLOAD_FOLDER, user_name)
    if not os.path.exists(user_root):
        return 0

    for root, _, files in os.walk(user_root):
        for f in files:
            fp = os.path.join(root, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total

def format_size(size_bytes):
    if size_bytes >= 1024 ** 4:
        return f"{size_bytes / (1024 ** 4):.2f} TB"
    elif size_bytes >= 1024 ** 3:
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= 1024 ** 2:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / (1024 ** 1):.1f} KB"
    else:
        return f"{size_bytes} B"

# 注册为过滤器
app.jinja_env.filters['format_size'] = format_size
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE) as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_metadata():
    if not os.path.exists(META_FILE):
        return {}
    
    with open(META_FILE, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if not content:
            return {}  # 空文件，返回空字典
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            print("⚠️ 警告：filesmeta.json 内容解析失败，返回空元数据")
            return {}

def save_metadata(meta):
    with open(META_FILE, 'w') as f:
        json.dump(meta, f, indent=2)

def save_log(entry, file):
    logs = []
    if os.path.exists(file):
        with open(file) as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    logs.append(entry)
    with open(file, 'w') as f:
        json.dump(logs, f, indent=2)

def is_admin():
    return session.get('user') == SUPER_ADMIN['username']

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == SUPER_ADMIN['username'] and password == SUPER_ADMIN['password']:
            session['user'] = username
            return redirect(url_for('dashboard'))

        users = load_users()
        if username in users and check_password_hash(users[username]['password'], password):
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    users = load_users()
    username = request.form['username']
    password = request.form['password']

    if username in users or username == SUPER_ADMIN['username']:
        flash('用户名已存在')
        return redirect(url_for('login'))

    users[username] = {
        'password': generate_password_hash(password),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    save_users(users)

    # ✅ 注册成功后自动登录
    session['user'] = username
    flash('✅ 注册成功，欢迎！')
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    is_admin_user = is_admin()

    # 获取当前访问的文件夹与所属用户
    folder = request.args.get('folder', 'default').strip()
    target_user = request.args.get('user', username).strip()

    # 收集所有可访问的文件夹（当前用户 + 公开 + 管理员全可见）
    visible_folders = []
    for user_dir in os.listdir(UPLOAD_FOLDER):
        user_path = os.path.join(UPLOAD_FOLDER, user_dir)
        if not os.path.isdir(user_path):
            continue

        # 加载 folder_meta.json
        meta_path = os.path.join(user_path, 'folder_meta.json')
        folder_meta = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    folder_meta = json.load(f)
            except:
                pass

        # 添加用户的已有文件夹
        for folder_name, info in folder_meta.items():
            permission = info.get("permission", "private")
            if user_dir == username or is_admin_user or permission == "public":
                visible_folders.append({
                    "owner": user_dir,
                    "folder": folder_name,
                    "permission": permission,
                    "description": info.get("description", "")
                })

        # ✅ 始终检查 default 文件夹是否存在并可见
        default_path = os.path.join(user_path, 'default')
        already_included = any(f["owner"] == user_dir and f["folder"] == "default" for f in visible_folders)
        if os.path.exists(default_path) and not already_included:
            if user_dir == username or is_admin_user:
                visible_folders.append({
                    "owner": user_dir,
                    "folder": "default",
                    "permission": "private",
                    "description": "(默认文件夹)"
                })

    # 加载当前正在访问的文件夹内容
    target_root = os.path.join(UPLOAD_FOLDER, target_user)
    folder_path = os.path.join(target_root, folder)

    # 若访问的是当前用户，default 不存在时自动创建
    if not os.path.exists(folder_path):
        if target_user == username:
            os.makedirs(folder_path, exist_ok=True)
        else:
            flash("❌ 文件夹不存在")
            return redirect(url_for('dashboard', folder='default', user=username))

    # 检查访问权限
    folder_permission = 'private'
    folder_meta_path = os.path.join(target_root, 'folder_meta.json')
    if os.path.exists(folder_meta_path):
        with open(folder_meta_path) as f:
            folder_meta = json.load(f)
            if folder in folder_meta:
                folder_permission = folder_meta[folder].get('permission', 'private')

    if folder_permission == 'private' and target_user != username and not is_admin_user:
        flash("❌ 无权限访问该文件夹")
        return redirect(url_for('dashboard', folder='default', user=username))

    # 加载文件及元数据
    meta = load_metadata()
    files = []

    for fname in os.listdir(folder_path):
        fpath = os.path.join(folder_path, fname)
        if not os.path.isfile(fpath):
            continue

        meta_key = f"{target_user}/{folder}/{fname}"
        file_info = meta.get(meta_key, {})

        files.append({
            "name": fname,
            "size": os.path.getsize(fpath),
            "time": datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%Y-%m-%d %H:%M:%S'),
            "owner": file_info.get("owner", target_user),  # ✅ 正确显示上传者
            "downloads": file_info.get("download_count", 0),
            "description": file_info.get("description", ""),
            "meta_key": meta_key,
            "folder": folder,
            "folder_permission": folder_permission,  # ✅ 加这一行
        })

    files.sort(key=lambda x: x["time"], reverse=True)

    used_space=get_total_user_used_space(username)

    return render_template("dashboard.html",
        username=username,
        #used_space=sum(f["size"] for f in files),
        used_space=used_space,
        total_space=USER_QUOTA,
        total_quota_mb=USER_QUOTA / 1024 / 1024,
        files=files,
        folder=folder,
        folder_owner=target_user,
        folders=visible_folders,
        deleted_users=set()
    )




@app.route('/change_password', methods=['POST'])
def change_password():
    users = load_users()
    username = request.form['username']
    new_pass = request.form['new_password']
    old_pass = request.form.get('old_password')

    # 管理员从后台修改他人密码
    if is_admin():
        if username in users:
            users[username]['password'] = generate_password_hash(new_pass)
            save_users(users)
            flash(f"管理员已修改 {username} 的密码")
        else:
            flash("用户不存在")
        return redirect(url_for('admin_users'))

    # 普通用户必须只能改自己
    current_user = session.get('user')
    if not current_user or username != current_user:
        flash("只能修改自己的密码")
        return redirect(url_for('dashboard'))

    # 检查原密码
    if username not in users or not check_password_hash(users[username]['password'], old_pass):
        flash("原密码错误，修改失败")
        return redirect(url_for('dashboard'))

    users[username]['password'] = generate_password_hash(new_pass)
    save_users(users)
    flash("密码修改成功")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/download/<path:encoded>')
def download(encoded):
    if 'user' not in session:
        return redirect(url_for('login'))

    meta = load_metadata()
    username = session['user']
    is_admin_user = is_admin()

    # encoded: user/folder/filename
    meta_key = encoded
    parts = encoded.split('/')
    if len(parts) != 3:
        flash("❌ 无效文件路径")
        return redirect(url_for('dashboard'))

    file_owner, folder, filename = parts

    if meta_key not in meta:
        flash("❌ 文件不存在")
        return redirect(url_for('dashboard'))

    file_info = meta[meta_key]
    permission = file_info.get("permission", "private")
    folder_owner = file_info.get("folder_owner", file_owner)

    # ✅ 权限判断
    if permission == "private" and username != folder_owner and not is_admin_user:
        flash("❌ 没有权限下载该文件")
        return redirect(url_for('dashboard'))

    # ✅ 记录下载次数 + 写日志
    file_info["download_count"] = file_info.get("download_count", 0) + 1
    save_metadata(meta)
    save_log({'user': username, 'filename': meta_key, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, DOWNLOAD_LOG_FILE)

    file_full_path = os.path.join(UPLOAD_FOLDER, file_owner, folder, filename)
    if not os.path.exists(file_full_path):
        flash("❌ 文件实际路径不存在")
        return redirect(url_for('dashboard'))

    # ✅ 权限检查通过后，重定向到 Nginx 静态路径
    print(f"✅ 权限校验通过，重定向至 Nginx：/secure-download/{file_owner}/{folder}/{filename}")
    return redirect(f"/secure-download/{file_owner}/{folder}/{filename}")


@app.route('/api/download_url/<path:encoded>')
def api_download_url(encoded):
    if 'user' not in session:
        return jsonify({'error': '未登录'}), 403

    meta = load_metadata()
    username = session['user']
    is_admin_user = is_admin()

    meta_key = encoded
    parts = encoded.split('/')
    if len(parts) != 3:
        return jsonify({'error': '无效文件路径'}), 400

    file_owner, folder, filename = parts

    if meta_key not in meta:
        return jsonify({'error': '文件元信息不存在'}), 404

    file_info = meta[meta_key]
    permission = file_info.get("permission", "private")
    folder_owner = file_info.get("folder_owner", file_owner)

    if permission == "private" and username != folder_owner and not is_admin_user:
        return jsonify({'error': '没有权限下载该文件'}), 403

    # 记录下载次数 + 写日志
    file_info["download_count"] = file_info.get("download_count", 0) + 1
    save_metadata(meta)
    save_log({'user': username, 'filename': meta_key, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, DOWNLOAD_LOG_FILE)

    file_full_path = os.path.join(UPLOAD_FOLDER, file_owner, folder, filename)
    if not os.path.exists(file_full_path):
        return jsonify({'error': '文件不存在或已被删除'}), 404

    # 返回 Nginx 代理路径
    url = f"/secure-download/{file_owner}/{folder}/{filename}"
    return jsonify({'url': url})


@app.route('/api/download/<path:encoded>', methods=['POST'])
def api_download(encoded):
    if 'user' not in session:
        return "未登录", 403
    return url_for('download_single', encoded=encoded)

@app.route('/download_single/<path:encoded>')
def download_single(encoded):
    if 'user' not in session:
        return redirect(url_for('login'))

    meta = load_metadata()
    username = session['user']
    is_admin_user = is_admin()

    # encoded: user/folder/filename
    meta_key = encoded
    parts = encoded.split('/')
    if len(parts) != 3:
        flash("❌ 无效文件路径")
        return redirect(url_for('dashboard'))

    file_owner, folder, filename = parts

    if meta_key not in meta:
        flash("❌ 文件不存在")
        return redirect(url_for('dashboard'))

    file_info = meta[meta_key]
    permission = file_info.get("permission", "private")
    folder_owner = file_info.get("folder_owner", file_owner)

    # ✅ 权限判断
    if permission == "private" and username != folder_owner and not is_admin_user:
        flash("❌ 没有权限下载该文件")
        return redirect(url_for('dashboard'))

    # ✅ 记录下载次数 + 写日志
    file_info["download_count"] = file_info.get("download_count", 0) + 1
    save_metadata(meta)
    save_log({'user': username, 'filename': meta_key, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, DOWNLOAD_LOG_FILE)

    file_full_path = os.path.join(UPLOAD_FOLDER, file_owner, folder)
    if not os.path.exists(file_full_path):
        flash("❌ 文件实际路径不存在")
        return redirect(url_for('dashboard'))

    return send_from_directory(file_full_path,filename, as_attachment=True)

@app.route('/delete/<path:encoded>')
def delete_file(encoded):
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    is_admin_user = is_admin()

    parts = encoded.split('/')
    if len(parts) != 3:
        flash("❌ 无效文件路径")
        return redirect(url_for('dashboard'))

    file_owner, folder, filename = parts
    meta_key = f"{file_owner}/{folder}/{filename}"

    meta = load_metadata()
    if meta_key not in meta:
        flash("⚠️ 文件不存在")
        return redirect(url_for('dashboard', folder=folder, user=file_owner))

    file_info = meta[meta_key]
    upload_owner = file_info.get('owner', '')
    folder_owner = file_info.get('folder_owner', file_owner)

    if username != upload_owner and username != folder_owner and not is_admin_user:
        flash("❌ 无权删除该文件")
        return redirect(url_for('dashboard', folder=folder, user=folder_owner))

    try:
        os.remove(os.path.join(UPLOAD_FOLDER, folder_owner, folder, filename))
        meta.pop(meta_key)
        save_metadata(meta)
        flash(f"✅ 已删除文件：{filename}")
    except Exception as e:
        flash("❌ 删除失败：" + str(e))

    return redirect(url_for('dashboard', folder=folder, user=folder_owner))

@app.route('/delete_many', methods=['POST'])
def delete_many():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    is_admin_user = is_admin()
    meta = load_metadata()
    to_delete = request.form.getlist('files')
    deleted = []

    for meta_key in to_delete:
        parts = meta_key.split('/')
        if len(parts) != 3:
            continue
        file_owner, folder, filename = parts
        if meta_key not in meta:
            continue

        file_info = meta[meta_key]
        upload_owner = file_info.get('owner', '')
        folder_owner = file_info.get('folder_owner', file_owner)

        if username != upload_owner and username != folder_owner and not is_admin_user:
            continue

        try:
            os.remove(os.path.join(UPLOAD_FOLDER, folder_owner, folder, filename))
            meta.pop(meta_key)
            deleted.append(filename)
        except:
            continue

    save_metadata(meta)
    flash(f"✅ 已删除：{', '.join(deleted)}")

    # ✅ 保持当前视图跳转
    folder = request.form.get('folder', 'default')
    owner = request.form.get('user', session['user'])
    return redirect(url_for('dashboard', folder=folder, user=owner))

@app.route('/admin/users')
def admin_users():
    if not is_admin():
        flash("无权限访问")
        return redirect(url_for('dashboard'))

    users = load_users()
    meta = load_metadata()
    deleted_users = {info['owner'] for info in meta.values() if info['owner'] not in users and info['owner'] != SUPER_ADMIN['username']}

    user_stats = []
    users_number=0
    for uname in users:
        users_number += 1
        #if uname == SUPER_ADMIN['username']:
            #continue
        used = sum(info['size'] for info in meta.values() if info['owner'] == uname)
        percent = (used / TOTAL_QUOTA) * 100
        user_stats.append({
            'username': uname,
            'created_at': users[uname].get('created_at', '未知'),
            'used': used,
            'percent': percent
        })
    used_space_total = get_total_used_space()
    #total_quota_all_users = TOTAL_QUOTA * users_number
    return render_template('admin_user.html', 
                           users=user_stats, 
                           username=session['user'], 
                           deleted_users=deleted_users,
                           used_space_total=used_space_total,
                           total_quota_all_users=TOTAL_QUOTA,
                           )

import shutil
@app.route('/admin/delete_users', methods=['POST'])
def admin_delete_users():
    if not is_admin():
        return redirect(url_for('dashboard'))

    to_delete = request.form.getlist('delete_users')
    users = load_users()
    deleted = []

    for uname in to_delete:
        if uname != SUPER_ADMIN['username'] and uname in users:
            users.pop(uname)
            deleted.append(uname)

            # ✅ 删除该用户 uploads/<uname> 文件夹
            user_dir = os.path.join(UPLOAD_FOLDER, uname)
            if os.path.exists(user_dir):
                try:
                    shutil.rmtree(user_dir)
                    print(f"✅ 已删除用户 {uname} 的文件夹数据")
                except Exception as e:
                    print(f"⚠️ 删除用户文件夹失败（{uname}）：{e}")

            # ✅ 删除该用户相关的元数据
            with meta_lock:
                meta = load_metadata()
                keys_to_delete = [k for k in meta if k.startswith(f"{uname}/")]
                for k in keys_to_delete:
                    meta.pop(k)
                save_metadata(meta)

    save_users(users)
    flash(f"✅ 已删除用户：{', '.join(deleted)}")
    return redirect(url_for('admin_users'))

@app.route('/admin/change_password', methods=['POST'])
def admin_change_password():
    return change_password()

@app.route('/admin/logs')
def admin_logs():
    if not is_admin():
        return redirect(url_for('dashboard'))

    logs = []
    if os.path.exists(DOWNLOAD_LOG_FILE):
        with open(DOWNLOAD_LOG_FILE) as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    logs.sort(key=lambda x: x['time'], reverse=True)

    users = load_users()
    deleted_users = {log['user'] for log in logs if log['user'] not in users and log['user'] != SUPER_ADMIN['username']}

    return render_template('admin_logs.html', logs=logs, username=session['user'], deleted_users=deleted_users)

@app.route('/admin/uploads')
def admin_uploads():
    if not is_admin():
        return redirect(url_for('dashboard'))

    logs = []
    if os.path.exists(UPLOAD_LOG_FILE):
        with open(UPLOAD_LOG_FILE) as f:
            try:
                logs = json.load(f)
            except:
                logs = []

    logs.sort(key=lambda x: x['time'], reverse=True)

    users = load_users()
    deleted_users = {log['user'] for log in logs if log['user'] not in users and log['user'] != SUPER_ADMIN['username']}

    return render_template('admin_uploads.html', logs=logs, username=session['user'], deleted_users=deleted_users)

@app.route('/admin/clear_logs', methods=['POST'])
def clear_logs():
    if not is_admin():
        return redirect(url_for('dashboard'))
    open(DOWNLOAD_LOG_FILE, 'w').write("[]")
    flash("已清空下载日志")
    return redirect(url_for('admin_logs'))

@app.route('/admin/clear_uploads', methods=['POST'])
def clear_uploads():
    if not is_admin():
        return redirect(url_for('dashboard'))
    open(UPLOAD_LOG_FILE, 'w').write("[]")
    flash("已清空上传日志")
    return redirect(url_for('admin_uploads'))

@app.route('/verify_password', methods=['POST'])
def verify_password():
    users = load_users()
    username = request.form['username']
    old_password = request.form['old_password']

    if username in users and check_password_hash(users[username]['password'], old_password):
        return 'ok'
    return 'fail', 403



import threading
meta_lock = threading.Lock()  # 全局锁，确保多线程写入安全

@app.route('/upload_one', methods=['POST'])
def upload_one():
    if 'user' not in session:
        return '未登录', 403

    username = session['user']
    target_user = request.form.get('user', username).strip()
    folder = request.form.get('folder', 'default').strip()
    description = request.form.get('description', '')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    user_dir = os.path.join(UPLOAD_FOLDER, target_user)
    folder_path = os.path.join(user_dir, folder)
    os.makedirs(folder_path, exist_ok=True)

    permission = 'private'
    folder_meta_path = os.path.join(user_dir, 'folder_meta.json')
    if os.path.exists(folder_meta_path):
        try:
            with open(folder_meta_path) as f:
                folder_meta = json.load(f)
                if folder in folder_meta:
                    permission = folder_meta[folder].get('permission', 'private')
        except:
            pass

    # 权限校验
    is_self_upload = (username == target_user)
    if not is_self_upload and not is_admin():
        if permission != 'public':
            return '❌ 无权限上传到私密文件夹', 403
        
    uploaded_file = request.files.get('file')
    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        save_path = os.path.join(folder_path, filename)
        file_size = len(uploaded_file.read())
        uploaded_file.stream.seek(0)  # 回到文件开头再保存

        # ✅ 管理员不做空间检查
        if not is_admin():
            used = get_total_user_used_space(target_user)
            if used + file_size > USER_QUOTA:
                return "❌ 当前用户存储空间不足，上传失败", 403
        
        uploaded_file.save(save_path)
        size = os.path.getsize(save_path)
        meta_key = f"{target_user}/{folder}/{filename}"

        with meta_lock:
            meta = load_metadata()
            meta[meta_key] = {
                "owner": username,  # ✅ 正确记录上传者
                "folder_owner": target_user,  # ✅ 存储文件夹所属者（可选）
                "size": size,
                "upload_time": now,
                "download_count": 0,
                "description": description,
                "folder": folder,
                "permission": permission
            }
            save_metadata(meta)

        save_log({'user': username, 'filename': meta_key, 'time': now}, UPLOAD_LOG_FILE)
        return 'OK'

    return '❌ 未选择有效文件', 400

@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    if 'user' not in session:
        return '未登录', 403

    chunk = request.files.get('file')
    filename = request.form['filename']
    chunk_index = int(request.form['chunk_index'])
    user = request.form['user'].strip()
    folder = request.form['folder'].strip()

    folder_path = os.path.join(UPLOAD_FOLDER, user, folder, 'chunks_' + filename)
    os.makedirs(folder_path, exist_ok=True)

    chunk.save(os.path.join(folder_path, f'{chunk_index}.part'))
    return 'OK'

@app.route('/merge_chunks', methods=['POST'])
def merge_chunks():
    if 'user' not in session:
        return '未登录', 403

    data = request.get_json()
    filename = data['filename']
    folder = data['folder'].strip()
    user = data['user'].strip()
    desc = data.get('description', '')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    folder_path = os.path.join(UPLOAD_FOLDER, user, folder)
    chunk_dir = os.path.join(folder_path, 'chunks_' + filename)
    final_path = os.path.join(folder_path, filename)

    # 计算新文件的分片总大小
    chunk_size_total = sum(
        os.path.getsize(os.path.join(chunk_dir, f)) for f in os.listdir(chunk_dir)
        if os.path.isfile(os.path.join(chunk_dir, f))
    )

    if not is_admin():
        used_space = get_total_user_used_space(user)

        # ✅ 判断是否超出配额（对每个用户同用 TOTAL_QUOTA）
        if used_space + chunk_size_total > USER_QUOTA:
            shutil.rmtree(chunk_dir)  # 删除用户上传的 chunk 分片
            return "❌ 当前用户存储空间不足，上传失败，分片已清除", 403

    # 合并写入
    with open(final_path, 'wb') as f:
        parts = sorted(os.listdir(chunk_dir), key=lambda x: int(x.split('.')[0]))
        for part in parts:
            with open(os.path.join(chunk_dir, part), 'rb') as pf:
                f.write(pf.read())

    shutil.rmtree(chunk_dir)  # 清理临时目录

    # 写 metadata
    size = os.path.getsize(final_path)
    meta_key = f"{user}/{folder}/{filename}"
    permission = 'private'

    folder_meta_path = os.path.join(UPLOAD_FOLDER, user, 'folder_meta.json')
    if os.path.exists(folder_meta_path):
        try:
            with open(folder_meta_path) as f:
                folder_meta = json.load(f)
                if folder in folder_meta:
                    permission = folder_meta[folder].get('permission', 'private')
        except:
            pass

    with meta_lock:
        meta = load_metadata()
        meta[meta_key] = {
            "owner": session['user'],
            "folder_owner": user,
            "size": size,
            "upload_time": now,
            "download_count": 0,
            "description": desc,
            "folder": folder,
            "permission": permission
        }
        save_metadata(meta)

    save_log({'user': session['user'], 'filename': meta_key, 'time': now}, UPLOAD_LOG_FILE)
    return '合并完成'

@app.route('/create_folder', methods=['POST'])
def create_folder():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    folder_name = request.form.get('folder_name', '').strip()
    description = request.form.get('description', '').strip()
    permission = request.form.get('permission', 'private')

    # 校验合法性
    if not folder_name or '/' in folder_name or '\\' in folder_name:
        flash("❌ 文件夹名称非法")
        return redirect(url_for('dashboard'))

    user_folder_root = os.path.join(UPLOAD_FOLDER, username)
    folder_path = os.path.join(user_folder_root, folder_name)

    # 创建文件夹目录
    os.makedirs(folder_path, exist_ok=True)

    # 保存文件夹元信息（保存在 folder.meta.json 中）
    meta_file = os.path.join(user_folder_root, 'folder_meta.json')
    folder_meta = {}
    if os.path.exists(meta_file):
        try:
            with open(meta_file) as f:
                folder_meta = json.load(f)
        except:
            pass

    folder_meta[folder_name] = {
        "owner": username,
        "description": description,
        "permission": permission,
        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    with open(meta_file, 'w') as f:
        json.dump(folder_meta, f, indent=2)

    flash(f"✅ 已创建文件夹 {folder_name}，权限：{permission}")
    return redirect(url_for('dashboard', folder=folder_name, user=username))

@app.route('/delete_folder', methods=['POST'])
def delete_folder():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    is_admin_user = is_admin()

    folder = request.form.get('folder', '').strip()
    target_user = request.form.get('user', '').strip()

    if not folder or not target_user:
        flash("❌ 参数缺失")
        return redirect(url_for('dashboard'))

    if folder == 'default':
        flash("❌ 无法删除默认文件夹")
        return redirect(url_for('dashboard', folder=folder, user=target_user))

    if username != target_user and not is_admin_user:
        flash("❌ 无权限删除其他用户的文件夹")
        return redirect(url_for('dashboard', folder=folder, user=target_user))

    folder_path = os.path.join(UPLOAD_FOLDER, target_user, folder)
    if os.path.exists(folder_path):
        try:
            shutil.rmtree(folder_path)
            # 清除 folder_meta.json 中的条目
            meta_path = os.path.join(UPLOAD_FOLDER, target_user, 'folder_meta.json')
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    folder_meta = json.load(f)
                if folder in folder_meta:
                    folder_meta.pop(folder)
                    with open(meta_path, 'w') as f:
                        json.dump(folder_meta, f, indent=2)
            # 删除 metadata 中该文件夹下的文件项
            with meta_lock:
                meta = load_metadata()
                keys_to_delete = [k for k in meta if k.startswith(f"{target_user}/{folder}/")]
                for k in keys_to_delete:
                    meta.pop(k)
                save_metadata(meta)

            flash(f"✅ 已删除文件夹：{folder}")
        except Exception as e:
            flash("❌ 删除失败：" + str(e))
    else:
        flash("⚠️ 文件夹不存在")

    return redirect(url_for('dashboard'))

@app.route('/delete_folders', methods=['POST'])
def delete_folders():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    is_admin_user = is_admin()
    folders_to_delete = request.form.getlist('folders')
    deleted = []

    for item in folders_to_delete:
        try:
            owner, folder = item.split('/', 1)
        except:
            continue
        if folder == 'default':
            continue
        if owner != username and not is_admin_user:
            continue

        folder_path = os.path.join(UPLOAD_FOLDER, owner, folder)
        if os.path.exists(folder_path):
            try:
                shutil.rmtree(folder_path)
                # 清理 folder_meta.json
                meta_path = os.path.join(UPLOAD_FOLDER, owner, 'folder_meta.json')
                if os.path.exists(meta_path):
                    with open(meta_path, 'r') as f:
                        folder_meta = json.load(f)
                    if folder in folder_meta:
                        folder_meta.pop(folder)
                        with open(meta_path, 'w') as f:
                            json.dump(folder_meta, f, indent=2)

                # 删除文件 metadata
                with meta_lock:
                    meta = load_metadata()
                    keys_to_delete = [k for k in meta if k.startswith(f"{owner}/{folder}/")]
                    for k in keys_to_delete:
                        meta.pop(k)
                    save_metadata(meta)

                deleted.append(f"{owner}/{folder}")
            except:
                continue

    flash(f"✅ 已批量删除文件夹：{', '.join(deleted)}" if deleted else "⚠️ 无文件夹被删除")
    return redirect(url_for('dashboard'))


@app.route('/record_download', methods=['POST'])
def record_download():
    data = request.get_json()
    meta_key = data.get('meta_key')

    if not meta_key:
        return jsonify({'status': 'error', 'message': 'Missing meta_key'}), 400

    print(f"[record_download] Request received for: {meta_key}")

    meta = load_metadata()
    if meta_key not in meta:
        return jsonify({'status': 'error', 'message': 'File not found in metadata'}), 404

    meta[meta_key]['download_count'] = meta[meta_key].get('download_count', 0) + 1
    save_metadata(meta)

    return jsonify({'status': 'success'})


def is_folder_visible_to_user(folder_name, username):
    try:
        folder_owner, folder = folder_name.split('/', 1)
    except ValueError:
        return False  # 不是合法的 "owner/folder" 格式

    metadata = load_metadata()
    key_prefix = f"{folder_owner}/{folder}/"

    # 检查是否有文件在这个文件夹下
    for meta_key, info in metadata.items():
        if meta_key.startswith(key_prefix):
            if info.get("permission") == "public":
                return True
            if folder_owner == username or username == 'admin':
                return True
            return False
    return False

from flask import abort, send_file, session, jsonify

@app.route('/download_folder/<path:folder_name>')
def download_folder(folder_name):
    username = session['user']
    #print("当前登录用户:", username)  # Debug用
    if not username:
        abort(403)  # 避免跳转，明确禁止访问

    folder_path = os.path.join('uploads', folder_name)
    folder_owner = folder_name.split('/')[0]

    if not os.path.exists(folder_path):
        return abort(404)

    if username != folder_owner and not is_admin() and not is_folder_visible_to_user(folder_name, username):
        return abort(403)

    zip_stream = io.BytesIO()
    with zipfile.ZipFile(zip_stream, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zf.write(file_path, arcname)

    zip_stream.seek(0)
    return send_file(zip_stream, mimetype='application/zip', as_attachment=True, download_name=f"{folder_name.split('/')[-1]}.zip")

@app.route('/preview/<path:encoded>')
def preview_file(encoded):
    if 'user' not in session:
        return redirect(url_for('login'))

    meta = load_metadata()
    username = session['user']
    is_admin_user = is_admin()

    parts = encoded.split('/')
    if len(parts) != 3:
        flash("❌ 无效文件路径")
        return redirect(url_for('dashboard'))

    file_owner, folder, filename = parts
    meta_key = encoded

    if meta_key not in meta:
        flash("❌ 文件不存在")
        return redirect(url_for('dashboard'))

    file_info = meta[meta_key]
    permission = file_info.get("permission", "private")
    folder_owner = file_info.get("folder_owner", file_owner)

    # ✅ 权限检查
    if permission == "private" and username != folder_owner and not is_admin_user:
        flash("❌ 无权限预览该文件")
        return redirect(url_for('dashboard'))

    file_full_path = os.path.join(UPLOAD_FOLDER, file_owner, folder, filename)
    if not os.path.exists(file_full_path):
        flash("❌ 文件实际不存在")
        return redirect(url_for('dashboard'))

    # ✅ 直接返回文件内容用于预览（不作为附件下载）
    return send_file(file_full_path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)





