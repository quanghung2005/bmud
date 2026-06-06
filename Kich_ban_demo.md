# Hướng dẫn Demo: Diễn đàn Sinh viên (Phiên bản V3 Nâng cấp)

Đây là tài liệu hướng dẫn chi tiết cách chạy ứng dụng phiên bản V3 (đã bổ sung Trang Admin và hệ thống Ghi log tấn công - WAF), thực hiện các kịch bản tấn công (Attack) và cách sửa code trực tiếp (Defense).

## 🚀 Cách chạy ứng dụng

1. Vì chúng ta vừa cập nhật code, hãy **Tắt server cũ** (Nhấn `Ctrl + C` ở cửa sổ Terminal).
2. Chạy lại lệnh: `python app.py`. Hệ thống sẽ tự động khởi tạo cơ sở dữ liệu mới (`forum_v3.db`).
3. Mở trình duyệt và truy cập: [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## 1. SQL Injection (Trang Đăng nhập) & Hệ thống Log WAF

**Tình huống:** Hacker bypass màn hình đăng nhập để chiếm quyền Admin. Lúc này Hacker có thể vào thẳng trang quản trị (Dashboard) để xem toàn bộ thông tin sinh viên (mật khẩu rõ).

- **Kịch bản Tấn công (Attack):**
  1. Truy cập trang đăng nhập.
  2. Tại ô **Tên đăng nhập**, nhập: `' OR '1'='1' -- ` (lưu ý có dấu cách sau hai dấu gạch ngang)
  3. Tại ô **Mật khẩu**, nhập bất kỳ.
  4. Bấm Đăng nhập -> Thành công đăng nhập vào tài khoản Admin.
  5. Trên thanh Menu (Navbar) sẽ hiện thêm nút màu đỏ **[Admin]**. Bấm vào đó.
  6. **Cực kỳ nguy hiểm:** Bạn có thể nhìn thấy danh sách tất cả user kèm theo **mật khẩu plaintext** (chữ không mã hóa). Đồng thời bạn cũng nhìn thấy "Nhật ký tấn công" ghi nhận lại nỗ lực SQLi vừa nãy của chính bạn!

- **Kịch bản Vá lỗi trực tiếp (Defense):**
  1. Mở file [app.py](file:///c:/Users/trieu/Downloads/bảo mật ứng dụng/vulnerable-student-forum/app.py).
  2. Tìm đến hàm `@app.route('/login')` (khoảng dòng 108).
  3. Xóa đoạn code: `query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"` và `cursor.execute(query)`.
  4. Thay bằng: 
     ```python
     query = "SELECT * FROM users WHERE username = ? AND password = ?"
     cursor.execute(query, (username, password))
     ```
  5. Khởi động lại server và thử lại payload.

---

## 2. Cross-Site Scripting - XSS (Phần Bình luận)

**Tình huống:** Hacker chèn mã độc JavaScript vào bình luận của một bài viết.

- **Kịch bản Tấn công (Attack):**
  1. Đăng nhập bằng tài khoản SV (User: `sinhvien1`, Pass: `123456`).
  2. Bấm vào một bài viết bất kỳ trong Diễn đàn.
  3. Tại ô **Viết bình luận**, copy và dán nguyên đoạn mã HTML/JS gợi ý bên dưới ô nhập (Đoạn mã có chứa thẻ `<div>` che toàn màn hình, kèm theo đoạn script di chuyển modal ra ngoài lớp `body` để tránh bị giới hạn kích thước bởi `.glass-panel` có `backdrop-filter`).
  4. Bấm Gửi bình luận -> Ngay lập tức, trang web bị che phủ bởi một giao diện "Lừa đảo" y như thật, căn giữa hoàn chỉnh và hiển thị đầy đủ nút **Xác nhận** (không bị chìm mất ở phía dưới). Bất kỳ ai vào đọc bài viết này cũng sẽ bị khóa màn hình bởi giao diện giả mạo này!
  5. **Log WAF:** Nếu Admin vào trang Quản trị, họ sẽ thấy hệ thống đã ghi log cảnh báo việc bạn chèn thẻ HTML lạ.

- **Kịch bản Vá lỗi trực tiếp (Defense):**
  1. Mở file [post.html](file:///c:/Users/trieu/Downloads/bảo mật ứng dụng/vulnerable-student-forum/templates/post.html).
  2. Tìm đến dòng hiển thị nội dung bình luận (khoảng dòng 41):
     ```html
     {{ comment.content | safe }}
     ```
  3. Xóa bỏ chữ `| safe`:
     ```html
     {{ comment.content }}
     ```
  4. Save file, tải lại trang web. Script sẽ trở thành text vô hại.

---

## 3. Broken Access Control - IDOR (Trang Hồ sơ)

**Tình huống:** User tự thay đổi ID trên URL để xem hồ sơ người khác.

- **Kịch bản Tấn công (Attack):**
  1. Đang đăng nhập bằng `sinhvien1`. Bấm vào **Hồ sơ**.
  2. Đổi URL thành `http://127.0.0.1:5000/profile?id=1` (ID của Admin).
  3. Xem được toàn bộ "DỮ LIỆU BẢO MẬT" của quản trị viên.
  4. **Log WAF:** Hệ thống sẽ âm thầm ghi lại một cảnh báo IDOR vào cơ sở dữ liệu. Admin có thể xem được trong trang Quản trị.

- **Kịch bản Vá lỗi trực tiếp (Defense):**
  1. Mở file [app.py](file:///c:/Users/trieu/Downloads/bảo mật ứng dụng/vulnerable-student-forum/app.py).
  2. Tìm đến hàm `@app.route('/profile')` (khoảng dòng 227).
  3. Thêm lệnh `return` ngay dưới dòng `log_attack(...)` để chặn truy cập:
     ```python
     if str(requested_id) != str(session['user_id']) and session.get('role') != 'admin':
         log_attack(...)
         return "Forbidden: Bạn không có quyền xem thông tin này!", 403
     ```
  4. Save file, khởi động lại server và kiểm tra.
