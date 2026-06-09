# Phân tích Chuyên sâu các Lỗ hổng Bảo mật trong Hệ thống

Tài liệu này giải thích chi tiết về 4 lỗ hổng bảo mật được cài cắm trong ứng dụng: Đoạn code nào bị lỗi, Hacker lợi dụng nó ra sao, và Tại sao cách vá lỗi (Defense) lại có tác dụng.

---

## 1. Lỗ hổng SQL Injection (SQLi) - Chiếm quyền Đăng nhập

### Đoạn code bị lỗi
 Nằm trong hàm `@app.route('/login')` (file `app.py`):
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

### Tại sao lại bị lợi dụng?
Lỗi xảy ra do ứng dụng dùng phương pháp **Nối chuỗi (String Concatenation)** bằng cú pháp `f-string` của Python. Máy chủ sẽ lấy trực tiếp bất cứ thứ gì người dùng gõ trên giao diện và ghép thẳng vào câu truy vấn SQL.
- Nếu Hacker nhập username là: `' OR '1'='1' -- `
- Câu SQL gửi xuống Database sẽ biến thành: 
  `SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = '...'`
- Ký hiệu `--` là chú thích (comment) trong SQL, làm cho đoạn kiểm tra password phía sau vô giá trị. Điều kiện `1=1` luôn đúng, giúp Hacker lấy được dòng dữ liệu đầu tiên trong Database (thường là Admin) mà không cần mật khẩu.

### Cách giải quyết và Tại sao lại hoạt động?
**Cách vá lỗi:**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))
```
**Tại sao cách này lại hiệu quả?**
Đây là phương pháp **Parameterized Queries (Truy vấn có tham số)**. Thay vì nối chuỗi trực tiếp, chúng ta dùng dấu `?` làm "chỗ trống" (placeholder). Thư viện `sqlite3` sẽ tự động xử lý tách bạch phần **Lệnh SQL (Command)** và phần **Dữ liệu (Data)**. Nếu hacker nhập `' OR '1'='1' -- `, thư viện sẽ hiểu đó chỉ là một chuỗi ký tự (Data) của tên đăng nhập thông thường, chứ không phải một câu lệnh logic để thực thi. Do đó, mã độc hoàn toàn bị vô hiệu hóa.

---

## 2. Lỗ hổng Stored Cross-Site Scripting (XSS) - Chèn mã độc hiển thị

### Đoạn code bị lỗi
 Nằm trong template hiển thị bài viết `templates/post.html`:
```html
<div class="post-content comment-text">
    {{ comment.content | safe }}
</div>
```

### Tại sao lại bị lợi dụng?
Jinja2 (engine render HTML của Flask) mặc định rất an toàn vì nó tự động mã hóa (escape) các thẻ HTML (ví dụ `<` biến thành `&lt;`). 
Tuy nhiên, lập trình viên đã cố tình dùng filter **`| safe`**. Lệnh `safe` nói với hệ thống rằng: "Đừng kiểm duyệt nội dung này, hãy in nó ra dưới dạng HTML gốc".
Hacker có thể lợi dụng điều này bằng cách bình luận một đoạn mã `<script>alert('Bị hack')</script>`. Đoạn mã độc này được lưu xuống Database (Stored), và mỗi khi có ai vào xem bài viết, trình duyệt của họ sẽ chạy ngay đoạn script đó vì nó được tin tưởng hoàn toàn.

### Cách giải quyết và Tại sao lại hoạt động?
**Cách vá lỗi:**
Xóa bỏ chữ `| safe`:
```html
{{ comment.content }}
```
**Tại sao cách này lại hiệu quả?**
Khi bỏ `| safe`, Jinja2 sẽ kích hoạt lại cơ chế **Auto-Escaping**. Bất cứ đoạn mã độc nào hacker nhập vào đều bị chuyển hóa thành văn bản thuần túy (Plaintext). Trình duyệt sẽ chỉ hiển thị nguyên văn đoạn code `<script>...</script>` lên màn hình cho người dùng đọc bằng mắt, chứ tuyệt đối không thực thi (execute) đoạn script đó ở dưới nền.

---

## 3. Lỗ hổng IDOR (Insecure Direct Object Reference) - Rò rỉ dữ liệu trái phép

### Đoạn code bị lỗi
 Nằm trong hàm `@app.route('/profile')` (file `app.py`):
```python
requested_id = request.args.get('id')
# THIẾU BƯỚC KIỂM TRA QUYỀN TRUY CẬP (AUTHORIZATION) Ở ĐÂY
cursor.execute("SELECT * FROM users WHERE id = ?", (requested_id,))
```

### Tại sao lại bị lợi dụng?
IDOR xảy ra khi ứng dụng sử dụng trực tiếp một con số định danh (như `id=1` trên thanh URL) để truy vấn đối tượng trong cơ sở dữ liệu. 
Hacker (đang đóng vai Sinh viên) nhận ra rằng URL của mình là `/profile?id=2`. Bằng cách thay số 2 thành số 1 (`/profile?id=1`), ứng dụng sẽ ngoan ngoãn lấy thông tin của User ID = 1 (Giám thị) ra và hiển thị. Ứng dụng đã hoàn toàn tin tưởng người dùng mà quên mất phải đặt câu hỏi: *"Anh có phải là chủ nhân của cái ID này không?"*

### Cách giải quyết và Tại sao lại hoạt động?
**Cách vá lỗi:**
```python
if str(requested_id) != str(session['user_id']) and session.get('role') != 'admin':
    return "Forbidden: Bạn không có quyền xem thông tin này!", 403
```
**Tại sao cách này lại hiệu quả?**
Đây là cơ chế **Kiểm soát Truy cập dựa trên Vai trò (Role-Based Access Control) & Quyền sở hữu (Ownership)**. Hệ thống sẽ đem cái `requested_id` mà hacker yêu cầu so sánh với `session['user_id']` (chính là ID thật của người đang đăng nhập được lưu an toàn trên Server). Nếu 2 ID này không khớp nhau, và người đăng nhập cũng không mang role `admin`, hệ thống sẽ chặn đứng và báo lỗi 403 (Forbidden). 

---

## 4. Broken Authentication - Lỗ hổng Khôi phục mật khẩu (Insecure Password Reset)

### Đoạn code bị lỗi
 Nằm trong hàm `@app.route('/reset_password')` (file `app.py`):
```python
# Chỉ cần biết username là ứng dụng tự động cập nhật mật khẩu mới
cursor.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
```

### Tại sao lại bị lợi dụng?
Quá trình Xác thực (Authentication) bị "vỡ" hoàn toàn do thiết kế luồng Khôi phục tài khoản quá lỏng lẻo. Lập trình viên thiết kế tính năng này dựa trên giả định sai lầm rằng: "Chỉ có chủ tài khoản mới biết tên đăng nhập của họ". Nhưng thực tế, `username` luôn là thông tin công khai.
Kẻ tấn công truy cập vào chức năng Reset Password, nhập `admin` và một mật khẩu mới do hắn nghĩ ra. Vì hệ thống không hề yêu cầu phải nhập Mã OTP hay bấm xác nhận qua Email, câu lệnh `UPDATE` ở trên tự động chạy thẳng xuống Database. Hậu quả là mật khẩu thật của Giám thị đã bị đè lên bởi mật khẩu của hacker.

### Cách giải quyết và Tại sao lại hoạt động?
**Cách vá lỗi:**
Yêu cầu mã định danh một lần (OTP) sinh ngẫu nhiên và gửi qua phương thức sở hữu của nạn nhân (Email/SMS). Lưu mã OTP vào Session của server để kiểm chứng:
```python
# Route sinh mã OTP ngẫu nhiên
@app.route('/send_otp', methods=['POST'])
def send_otp():
    session['reset_otp'] = str(random.randint(100000, 999999))
    return "Đã gửi OTP"

# Trong hàm đổi mật khẩu
otp_input = request.form.get('otp', '')
saved_otp = session.get('reset_otp')

# Đối chiếu mã OTP người dùng nhập vào với mã OTP đã lưu trong Session
if not saved_otp or otp_input != saved_otp:
    flash('Mã OTP không hợp lệ!', 'error')
    return render_template('reset_password.html')
```
**Tại sao cách này lại hiệu quả?**
Giải pháp này tuân theo nguyên tắc **Xác thực Đa yếu tố (MFA / 2FA)** kết hợp **Mã thông báo dùng 1 lần (Dynamic Token)**. Thay vì chỉ kiểm tra "Bạn biết cái gì" (Tên đăng nhập), hệ thống đòi hỏi "Bạn có cái gì" (Thiết bị/Email để nhận OTP ngẫu nhiên). Mã OTP được sinh động (Dynamic) và lưu trên RAM của máy chủ (Session) nên hacker không thể đoán trước (`123456`) cũng như không thể đánh cắp từ Client. Quá trình kiểm chứng thất bại sẽ khiến lệnh `UPDATE` không bao giờ được chạy.
