# Realtime IDS - Hệ thống Phát hiện Xâm nhập Thời gian thực
Realtime IDS là một hệ thống phát hiện xâm nhập thời gian thực, sử dụng học máy để phân tích luồng mạng và phát hiện các hành vi bất thường hoặc tấn công. Hệ thống cung cấp giao diện web thân thiện, giám sát liên tục và khả năng cảnh báo qua email và Telegram.
Tính năng
Phân tích mạng thời gian thực: Bắt và phân tích các gói tin mạng, nhóm thành luồng và trích xuất đặc trưng
Phát hiện tấn công bằng học máy: Sử dụng mô hình học sâu được huấn luyện trên tập dữ liệu NSL-KDD
Giao diện web thân thiện: Bảng điều khiển trực quan hiển thị thống kê và cảnh báo
Xem log thời gian thực: Theo dõi và lọc log tấn công trực tiếp từ giao diện
Thông báo đa kênh: Gửi cảnh báo qua email và Telegram khi phát hiện tấn công
Cấu hình linh hoạt: Điều chỉnh tất cả tham số qua giao diện web hoặc file cấu hình
Hỗ trợ whitelist/blacklist: Lọc IP và tên miền tin cậy hoặc nguy hiểm
Phát hiện Port scan: Tự động phát hiện hoạt động quét cổng
## Yêu cầu hệ thống
Python 3.10 hoặc cao hơn
Quyền root/sudo (cần thiết cho việc bắt gói tin mạng)
Thư viện pcap (libpcap-dev trên Linux)
Các thư viện Python được liệt kê trong requirements.txt
## Cài đặt
1. Clone repository
```bash
git clone https://github.com/yourusername/realtime-ids.git
cd realtime-ids
```
2. Cài đặt các phụ thuộc
```bash
# Cài môi trường venv trước khi cài thư viện (Linux/ Windows có thể bỏ qua và tới bước cài đặt thư viện)
python3 -m venv venv

#Kích hoạt môi trường sau
source venv/bin/active

# Cài đặt thư viện trong môi trường venv sau khi kích hoạt
pip install -r requirements.txt
```
3. Cấu hình hệ thống
Chỉnh sửa file cấu hình theo nhu cầu:
- Tên lớp mạng bắt gói tin
- Tên mô hình AI
- Cấu hình thông báo cho Gmail và Telegram,....
```bash
nano config.ini
```
## Sử dụng
Khởi động hệ thống
```bash
sudo python app.py
```
Hoặc nếu dụng với môi trường venv:
```bash
sudo venv/bin/python app.py
```

## Truy cập giao diện web

Mở trình duyệt và truy cập:
http://localhost:5000

Đăng nhập với thông tin trong file cấu hình (mặc định: admin/admin123)

## Cấu hình chi tiết File config.ini

[Network]
interface = eth0        # Giao diện mạng cần giám sát
window = 5              # Cửa sổ thời gian phân tích (giây)
min_packets = 3         # Số lượng gói tin tối thiểu để phân tích luồng
min_bytes = 100         # Kích thước tối thiểu (bytes) để phân tích luồng

[Model]
model_path = models/best_model_dl_smote.h5    # Đường dẫn đến mô hình
preprocess_path = models/preprocess_pipeline.pkl # Đường dẫn đến pipeline
threshold = 0.7         # Ngưỡng xác suất cảnh báo

[Filtering]
whitelist_file = data/whitelist.txt  # Danh sách IP/domain tin cậy
blacklist_file = data/blacklist.txt  # Danh sách IP/domain nguy hiểm

[Notification]
enable_email = false    # Bật/tắt thông báo email
email_sender = your_email@gmail.com     # Email gửi thông báo
email_password = your_app_password      # Mật khẩu ứng dụng Gmail
email_recipient = recipient@example.com # Email nhận thông báo
email_interval = 300    # Thời gian tối thiểu giữa các email (giây)

enable_telegram = false # Bật/tắt thông báo Telegram
telegram_token = your_telegram_bot_token  # Token bot Telegram
telegram_chat_id = your_telegram_chat_id  # ID chat Telegram
telegram_interval = 60  # Thời gian tối thiểu giữa các thông báo (giây)

[WebUI]
port = 5000             # Cổng máy chủ web
username = admin        # Tên đăng nhập giao diện web
password = admin123     # Mật khẩu đăng nhập


## Thiết lập thông báo
Email (Gmail)
Tạo App Password cho tài khoản Gmail của bạn
Cập nhật các tùy chọn email_* trong file cấu hình
Telegram
Tạo bot mới thông qua @BotFather và lấy token
Gửi tin nhắn đến bot của bạn và truy cập URL: https://api.telegram.org/bot<YourBOTToken>/getUpdates để lấy chat_id
Cập nhật các tùy chọn telegram_* trong file cấu hình

## Giao diện người dùng
### Dashboard
Trang chính hiển thị:

Trạng thái hệ thống (đang chạy/dừng)
Thống kê mạng (gói tin, luồng, cảnh báo)
Cảnh báo gần đây

### Logs
Hiển thị log tấn công với các tính năng:

Lọc theo từ khóa
Theo dõi theo thời gian thực
Xem lịch sử log

### Settings
Trang cấu hình cho phép chỉnh sửa:

Cài đặt mạng
Tham số mô hình
Cấu hình thông báo

## Phương pháp phát hiện
Realtime IDS sử dụng cách tiếp cận kết hợp:

### Phân tích dựa trên luồng:

Gom nhóm gói tin thành các luồng 5-tuple (src IP, src port, dst IP, dst port, protocol)
Trích xuất đặc trưng từ mỗi luồng (thời lượng, byte, gói tin, flag TCP, v.v.)

### Phát hiện học máy:

Sử dụng mô hình học sâu được huấn luyện trên tập NSL-KDD
Áp dụng tiền xử lý (scaling, one-hot encoding) cho đặc trưng

### Hậu xử lý thông minh:

Lọc cảnh báo dương tính giả bằng heuristics
Áp dụng ngưỡng thích ứng cho các loại lưu lượng khác nhau

### Phát hiện đặc biệt:

Quét cổng (phát hiện SYN flood hoặc quét cổng tuần tự)
Kiểm tra blacklist/whitelist
Phân tích tốc độ truyền cho DoS

## Hiệu suất và Điều chỉnh

### Tối ưu hóa hiệu suất
Điều chỉnh kích thước cửa sổ: Tăng window để giảm tải CPU hoặc giảm để cảnh báo nhanh hơn
Lọc luồng: Điều chỉnh min_packets và min_bytes để lọc luồng nhỏ và giảm phân tích không cần thiết
Ngưỡng cảnh báo: Điều chỉnh threshold để cân bằng giữa dương tính giả và âm tính giả

### Giảm dương tính giả
Thêm domain/IP tin cậy vào whitelist
Tăng threshold cho các dịch vụ cụ thể (HTTPS, DNS)
Điều chỉnh logic hậu xử lý trong ids_engine.py

## Xử lý sự cố
### Vấn đề thường gặp và giải pháp
Vấn đề	Giải pháp
Không bắt được gói tin	Kiểm tra quyền sudo/root và tên giao diện mạng
Quá nhiều cảnh báo giả	Tăng ngưỡng, bổ sung whitelist, tăng min_packets
Lỗi mô hình	Kiểm tra đường dẫn mô hình và preprocess trong config.ini
Email không gửi được	Kiểm tra App Password và cài đặt bảo mật Gmail
Telegram không hoạt động	Kiểm tra token bot và chat_id
### Log và gỡ lỗi
Các tệp log quan trọng:

logs/attack.log: Log tấn công được phát hiện
Đầu ra console: Thông tin khởi động và lỗi hệ thống
