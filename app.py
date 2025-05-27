from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv  # ✅ 新增
import os,json

load_dotenv()

app = Flask(__name__)
app.secret_key = 'super-secret-key'

UPLOAD_FOLDER = 'uploads'
USER_FILE = 'users.json'
META_FILE = 'filemeta.json'
UPLOAD_LOG_FILE = 'upload_log.json'
DOWNLOAD_LOG_FILE = 'download_log.json'
TOTAL_QUOTA = 10 * 1024 * 1024 * 1024  # 100 MB

SUPER_ADMIN = {
    'username': os.getenv('ADMIN_USERNAME', 'admin'),
    'password': os.getenv('ADMIN_PASSWORD', 'admin123')
}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE) as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_metadata():
    if os.path.exists(META_FILE):
        with open(META_FILE) as f:
            return json.load(f)
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
    flash('注册成功，请登录')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    users = load_users()
    meta = load_metadata()

    # 标记删除用户
    deleted_users = {info['owner'] for info in meta.values()
                     if info['owner'] not in users and info['owner'] != SUPER_ADMIN['username']}

    used = sum(info['size'] for info in meta.values())
    total = TOTAL_QUOTA

    if request.method == 'POST':
        files = request.files.getlist('file')
        description = request.form.get('description', '')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for uploaded_file in files:
            if uploaded_file and uploaded_file.filename:
                filename = uploaded_file.filename
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                uploaded_file.save(save_path)
                size = os.path.getsize(save_path)
                meta[filename] = {
                    "owner": session['user'],
                    "size": size,
                    "upload_time": now,
                    "download_count": 0,
                    "description": description
                }
                save_log({'user': session['user'], 'filename': filename, 'time': now}, UPLOAD_LOG_FILE)
        save_metadata(meta)
        flash("上传成功")
        return redirect(url_for('dashboard'))

    files = [
        {
            "name": name,
            "size": info["size"],
            "time": info["upload_time"],
            "owner": info["owner"],
            "downloads": info.get("download_count", 0),
            "description": info.get("description", "")
        }
        for name, info in meta.items()
    ]

    files.sort(key=lambda x: x["time"], reverse=True)

    return render_template('dashboard.html',
        files=files,
        username=session['user'],
        used_space=used,
        total_space=total,
        total_quota_mb=total / 1024 / 1024,
        deleted_users=deleted_users
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

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    meta = load_metadata()
    safe = os.path.basename(filename)

    if safe in meta:
        meta[safe]["download_count"] = meta[safe].get("download_count", 0) + 1
        save_metadata(meta)

    save_log({'user': session['user'], 'filename': filename, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, DOWNLOAD_LOG_FILE)
    return send_from_directory(UPLOAD_FOLDER, safe, as_attachment=True)

@app.route('/api/download/<filename>', methods=['POST'])
def api_download(filename):
    if 'user' not in session:
        return "未登录", 403
    return url_for('download', filename=filename)

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    meta = load_metadata()
    safe = os.path.basename(filename)

    if safe in meta:
        if meta[safe]['owner'] == session['user'] or is_admin():
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, safe))
                meta.pop(safe)
                save_metadata(meta)
                flash(f"已删除：{safe}")
            except:
                flash("删除失败")
        else:
            flash("无权限删除该文件")
    return redirect(url_for('dashboard'))

@app.route('/delete_many', methods=['POST'])
def delete_many():
    if 'user' not in session:
        return redirect(url_for('login'))

    meta = load_metadata()
    to_delete = request.form.getlist('files')
    deleted = []

    for fname in to_delete:
        safe = os.path.basename(fname)
        if safe in meta:
            if meta[safe]['owner'] == session['user'] or is_admin():
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, safe))
                    meta.pop(safe)
                    deleted.append(safe)
                except:
                    pass
    save_metadata(meta)
    flash(f"已删除：{', '.join(deleted)}")
    return redirect(url_for('dashboard'))

@app.route('/admin/users')
def admin_users():
    if not is_admin():
        flash("无权限访问")
        return redirect(url_for('dashboard'))

    users = load_users()
    meta = load_metadata()
    deleted_users = {info['owner'] for info in meta.values() if info['owner'] not in users and info['owner'] != SUPER_ADMIN['username']}

    user_stats = []
    for uname in users:
        if uname == SUPER_ADMIN['username']:
            continue
        used = sum(info['size'] for info in meta.values() if info['owner'] == uname)
        percent = (used / TOTAL_QUOTA) * 100
        user_stats.append({
            'username': uname,
            'created_at': users[uname].get('created_at', '未知'),
            'used': used,
            'percent': percent
        })

    return render_template('admin_user.html', users=user_stats, username=session['user'], deleted_users=deleted_users)

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

    save_users(users)
    flash(f"已删除用户：{', '.join(deleted)}")
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

    uploaded_file = request.files.get('file')
    description = request.form.get('description', '')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        uploaded_file.save(save_path)
        size = os.path.getsize(save_path)

        with meta_lock:
            meta = load_metadata()
            meta[filename] = {
                "owner": session['user'],
                "size": size,
                "upload_time": now,
                "download_count": 0,
                "description": description
            }
            save_metadata(meta)

        save_log({'user': session['user'], 'filename': filename, 'time': now}, UPLOAD_LOG_FILE)
        return 'OK'

    return '失败', 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)





