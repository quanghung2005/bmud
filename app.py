import sqlite3
import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import hashlib

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_demo'
DB_FILE = 'forum_v4.db' # Dùng DB mới để tránh lỗi khóa file (file lock) đang chạy

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Bảng Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT,
            student_id TEXT,
            role TEXT,
            email TEXT,
            phone TEXT,
            bank_account TEXT,
            private_notes TEXT
        )
    ''')
    
    # 2. Bảng Bài viết (Topics)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')

    # 3. Bảng Bình luận (Comments) - Nơi chứa XSS
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            author_id INTEGER,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts (id),
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')

    # 4. Bảng Log Tấn Công (Attack Logs) - Chống giả mạo bằng Blockchain-like Hash
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            prev_hash TEXT,
            hash TEXT
        )
    ''')

    # Chỉ thêm dữ liệu mẫu nếu bảng users trống
    cursor.execute("SELECT COUNT(*) as count FROM sqlite_master WHERE type='table' AND name='users'")
    has_users_table = cursor.fetchone()['count'] > 0
    
    if has_users_table:
        cursor.execute("SELECT COUNT(*) as count FROM users")
        if cursor.fetchone()['count'] == 0:
            # Thêm dữ liệu mẫu cực kỳ nhạy cảm
            cursor.execute("INSERT INTO users (username, password, full_name, student_id, role, email, phone, bank_account, private_notes) VALUES ('admin', 'admin123', 'Giám Thị Nguyễn Văn A', 'ADMIN001', 'admin', 'admin@truong.edu.vn', '0988.888.888', 'VCB: 101010101010 (Số dư: 2.5 Tỷ VNĐ)', 'Mã két sắt phòng giáo vụ: 886622. Pass server backup: admin_!@#')")
            cursor.execute("INSERT INTO users (username, password, full_name, student_id, role, email, phone, bank_account, private_notes) VALUES ('sinhvien1', '123456', 'Trần Thị B', 'SV2021001', 'student', 'sv1@truong.edu.vn', '0912.345.678', 'MBBank: 999999999', 'Sinh viên ưu tú')")
            cursor.execute("INSERT INTO users (username, password, full_name, student_id, role, email, phone, bank_account, private_notes) VALUES ('sinhvien2', 'password', 'Lê Văn C', 'SV2021002', 'student', 'sv2@truong.edu.vn', '0909.090.090', 'ACB: 88888888', 'Chưa đóng học phí')")
            
            cursor.execute("INSERT INTO posts (author_id, title, content) VALUES (1, 'Thông báo lịch thi học kỳ', 'Chào mừng các em sinh viên đến với diễn đàn năm học mới. Lịch thi sẽ được cập nhật sớm nhất.')")
            cursor.execute("INSERT INTO posts (author_id, title, content) VALUES (2, 'Hỏi về môn Bảo mật ứng dụng', 'Cho em hỏi lịch thi môn Bảo mật ứng dụng là ngày nào ạ? Em lo môn này quá.')")
            
            cursor.execute("INSERT INTO comments (post_id, author_id, content) VALUES (2, 3, 'Mình nghe nói là tuần sau thi đó bạn.')")

    conn.commit()
    conn.close()

# Hàm hỗ trợ ghi log tấn công (Tamper-Resistant WAF)
def log_attack(attack_type, details):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Lấy hash của bản ghi trước đó
    cursor.execute("SELECT hash FROM attack_logs ORDER BY id DESC LIMIT 1")
    last_log = cursor.fetchone()
    prev_hash = last_log['hash'] if last_log and last_log['hash'] else "0" * 64
    
    # Tạo nội dung để băm (hash)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content_to_hash = f"{attack_type}|{details}|{timestamp}|{prev_hash}"
    current_hash = hashlib.sha256(content_to_hash.encode()).hexdigest()
    
    cursor.execute("INSERT INTO attack_logs (attack_type, details, timestamp, prev_hash, hash) VALUES (?, ?, ?, ?, ?)", 
                   (attack_type, details, timestamp, prev_hash, current_hash))
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('forum'))
    return redirect(url_for('login'))

# --- VULNERABILITY 1: SQL INJECTION ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # WAF LOGIC: Phát hiện dấu hiệu SQLi
        if "'" in username or "--" in username or "OR" in username.upper():
            log_attack('SQL Injection', f"Phát hiện payload SQLi ở trường Username: {username}")

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # LỖ HỔNG (VULNERABLE)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print("Executing Query:", query)
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('forum'))
            else:
                flash('Sai tên đăng nhập hoặc mật khẩu!', 'error')

        except sqlite3.Error as e:
            flash(f'Lỗi cơ sở dữ liệu: {e}', 'error')
            log_attack('Database Error', f"Lỗi thực thi SQL do payload: {username}")
        finally:
            conn.close()
    return render_template('login.html')

# --- VULNERABILITY 4: INSECURE PASSWORD RESET ---
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['password']
        # LỖ HỔNG (VULNERABLE): Đổi mật khẩu mà không cần OTP, Email, hay mật khẩu cũ.
        # Chỉ cần biết username là có thể tự do đặt lại mật khẩu!
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Kiểm tra xem user có tồn tại không
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
    
        if user:
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
            conn.commit()
            log_attack('Insecure Password Reset', f"Mật khẩu của tài khoản '{username}' đã bị thay đổi trái phép thành '{new_password}'!")
            flash(f'Đã đổi mật khẩu cho tài khoản {username} thành công!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Tài khoản không tồn tại!', 'error')
            
        conn.close()
        
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/reset')
def reset():
    session.clear()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DROP TABLE IF EXISTS attack_logs")
        cursor.execute("DROP TABLE IF EXISTS comments")
        cursor.execute("DROP TABLE IF EXISTS posts")
        cursor.execute("DROP TABLE IF EXISTS users")
        conn.commit()
    except Exception as e:
        pass
    finally:
        conn.close()
    init_db()
    flash('Hệ thống đã được reset về trạng thái ban đầu!', 'success')
    return redirect(url_for('login'))

@app.route('/forum', methods=['GET', 'POST'])
def forum():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        author_id = session['user_id']
        cursor.execute("INSERT INTO posts (author_id, title, content) VALUES (?, ?, ?)", (author_id, title, content))
        conn.commit()
        flash('Đăng chủ đề thành công!', 'success')
        return redirect(url_for('forum'))
        
    cursor.execute('''
        SELECT posts.*, users.full_name, users.role, 
               (SELECT COUNT(*) FROM comments WHERE post_id = posts.id) as comment_count
        FROM posts 
        JOIN users ON posts.author_id = users.id 
        ORDER BY posts.created_at DESC
    ''')
    posts = cursor.fetchall()
    conn.close()
    
    return render_template('forum.html', posts=posts)

# --- VULNERABILITY 2: STORED XSS ---
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Xử lý khi đăng bình luận mới
    if request.method == 'POST':
        content = request.form['content']
        author_id = session['user_id']
        
        # WAF LOGIC: Phát hiện dấu hiệu XSS
        if "<script>" in content.lower() or "javascript:" in content.lower() or "onerror=" in content.lower():
            log_attack('Cross-Site Scripting (XSS)', f"User ID {author_id} cố gắng chèn mã độc vào bài viết #{post_id}. Payload: {content}")
        
        cursor.execute("INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)", (post_id, author_id, content))
        conn.commit()
        flash('Đã gửi bình luận!', 'success')
        return redirect(url_for('view_post', post_id=post_id))

    # Lấy thông tin bài đăng
    cursor.execute('''
        SELECT posts.*, users.full_name, users.role 
        FROM posts 
        JOIN users ON posts.author_id = users.id 
        WHERE posts.id = ?
    ''', (post_id,))
    post = cursor.fetchone()
    
    if not post:
        return "Không tìm thấy bài viết", 404
        
    # Lấy danh sách bình luận (NƠI HIỂN THỊ XSS)
    cursor.execute('''
        SELECT comments.*, users.full_name, users.role 
        FROM comments 
        JOIN users ON comments.author_id = users.id 
        WHERE comments.post_id = ?
        ORDER BY comments.created_at ASC
    ''', (post_id,))
    comments = cursor.fetchall()
    conn.close()
    
    return render_template('post.html', post=post, comments=comments)

# --- VULNERABILITY 3: BROKEN ACCESS CONTROL (IDOR) ---
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    requested_id = request.args.get('id')
    
    if not requested_id:
        requested_id = session['user_id']
        
    # WAF LOGIC: Phát hiện IDOR
    if str(requested_id) != str(session['user_id']) and session.get('role') != 'admin':
        log_attack('IDOR (Broken Access Control)', f"User ID {session['user_id']} cố gắng truy cập trái phép hồ sơ của User ID {requested_id}")
    # LỖ HỔNG (VULNERABLE): Vẫn cho phép query database mà không chặn lại
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (requested_id,))
    user_profile = cursor.fetchone()
    conn.close()
    
    if user_profile:
        return render_template('profile.html', user=user_profile)
    else:
        return "Không tìm thấy người dùng", 404

# --- WAF: Kiểm tra tính toàn vẹn của Log ---
def verify_logs_integrity(logs):
    verified_logs = []
    expected_prev = "0" * 64
    
    for log in logs:
        log_dict = dict(log)
        
        # Băm lại dữ liệu hiện tại
        content_to_hash = f"{log['attack_type']}|{log['details']}|{log['timestamp']}|{log['prev_hash']}"
        recalculated_hash = hashlib.sha256(content_to_hash.encode()).hexdigest()
        
        # Kiểm tra tính toàn vẹn
        if recalculated_hash == log['hash'] and log['prev_hash'] == expected_prev:
            log_dict['is_valid'] = True
        else:
            log_dict['is_valid'] = False
            
        expected_prev = log['hash']
        verified_logs.append(log_dict)
        
    return verified_logs



# --- ADMIN DASHBOARD ---
@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        log_attack('Unauthorized Access', f"User {session.get('user_id', 'Guest')} cố gắng truy cập trang Admin")
        flash('Bạn không có quyền truy cập trang này.', 'error')
        return redirect(url_for('forum'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    cursor.execute("SELECT * FROM attack_logs ORDER BY id ASC") # Phải lấy tăng dần để kiểm tra hash chain
    logs = cursor.fetchall()
    
    conn.close()
    
    # Kiểm tra toàn vẹn
    verified_logs = verify_logs_integrity(logs)
    verified_logs.reverse() # Đảo lại để hiển thị mới nhất lên đầu
    
    return render_template('admin.html', 
                         users=users, 
                         logs=verified_logs, 
                         total_users=len(users), 
                         total_logs=len(logs))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('role') != 'admin':
        return "Forbidden", 403
        
    if user_id == 1:
        flash("Không thể xóa Admin chính!", "error")
        return redirect(url_for('admin_dashboard'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    log_attack('Data Deletion', f"Admin đã xóa người dùng ID: {user_id}")
    flash("Xóa người dùng thành công", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/toggle_role/<int:user_id>', methods=['POST'])
def toggle_role(user_id):
    if session.get('role') != 'admin':
        return "Forbidden", 403
        
    if user_id == 1:
        flash("Không thể đổi quyền Admin chính!", "error")
        return redirect(url_for('admin_dashboard'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    new_role = 'admin' if user['role'] == 'student' else 'student'
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    
    log_attack('Role Changed', f"Admin đã đổi quyền user ID: {user_id} thành {new_role}")
    flash(f"Đã cập nhật quyền thành {new_role}", "success")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    print("Starting Student Forum at http://127.0.0.1:5000")
    app.run(debug=True)
