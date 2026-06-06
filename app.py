import sqlite3
import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_demo'
DB_FILE = 'forum_v3.db' # Dùng DB mới để tránh lỗi khóa file (file lock) đang chạy

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

    # 4. Bảng Log Tấn Công (Attack Logs)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

# Hàm hỗ trợ ghi log tấn công (WAF Mô phỏng)
def log_attack(attack_type, details):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO attack_logs (attack_type, details) VALUES (?, ?)", (attack_type, details))
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

# --- ADMIN DASHBOARD ---
@app.route('/admin')
def admin_dashboard():
    # CHỈ CÓ ADMIN MỚI ĐƯỢC VÀO TRANG NÀY
    if 'user_id' not in session or session.get('role') != 'admin':
        log_attack('Unauthorized Access', f"User ID {session.get('user_id', 'Guest')} cố gắng truy cập trang Quản trị Admin.")
        flash('Bạn không có quyền truy cập trang này!', 'error')
        return redirect(url_for('forum'))
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Lấy thống kê
    cursor.execute("SELECT COUNT(*) as count FROM users")
    total_users = cursor.fetchone()['count']
    cursor.execute("SELECT COUNT(*) as count FROM attack_logs")
    total_logs = cursor.fetchone()['count']
    
    # Lấy danh sách users (Dữ liệu nhạy cảm)
    cursor.execute("SELECT * FROM users")
    all_users = cursor.fetchall()
    
    # Lấy logs tấn công
    cursor.execute("SELECT * FROM attack_logs ORDER BY timestamp DESC LIMIT 20")
    attack_logs = cursor.fetchall()
    
    conn.close()
    
    return render_template('admin.html', total_users=total_users, total_logs=total_logs, users=all_users, logs=attack_logs)

if __name__ == '__main__':
    print("Starting Student Forum at http://127.0.0.1:5000")
    app.run(debug=True)
