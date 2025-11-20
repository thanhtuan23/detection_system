# Theo dõi và lưu trữ trạng thái của từng flow (luồng kết nối) mạng.
import time
from collections import defaultdict
from ids_utils import tcp_flag_to_nslkdd

class FlowState:
    __slots__ = ("first_ts","last_ts","src_bytes","dst_bytes","pkt_src","pkt_dst",
                "proto","service","flag_counts","is_https","rate_src","rate_dst")
    def __init__(self, proto:str, service:str):
        now = time.time()
        self.first_ts = now
        self.last_ts  = now
        self.src_bytes = 0    # bytes từ src->dst
        self.dst_bytes = 0    # bytes từ dst->src
        self.pkt_src = 0
        self.pkt_dst = 0
        self.proto = proto
        self.service = service
        self.flag_counts = defaultdict(int)  # đếm các loại flag
        self.is_https = service == "http_443"
        # Thêm chỉ số tốc độ truyền dữ liệu
        self.rate_src = 0.0  # bytes/sec từ src->dst
        self.rate_dst = 0.0  # bytes/sec từ dst->src

    def update(self, pkt, direction_src_to_dst: bool):
        ln = int(len(bytes(pkt)))
        now = time.time()
        if direction_src_to_dst:
            self.src_bytes += ln
            self.pkt_src   += 1
        else:
            self.dst_bytes += ln
            self.pkt_dst   += 1
        self.last_ts = now
        self.flag_counts[tcp_flag_to_nslkdd(pkt)] += 1
        
        # Cập nhật tốc độ truyền dữ liệu
        duration = max(0.001, now - self.first_ts)  # Tránh chia cho 0
        self.rate_src = self.src_bytes / duration
        self.rate_dst = self.dst_bytes / duration

    def to_feature_row(self, key_tuple, host_counts_window) -> dict:
        """
        Sinh 1 hàng đặc trưng CHÍNH XÁC theo NSL-KDD để khớp với pipeline training.
        CRITICAL: Tên cột PHẢI khớp 100% với notebook training để mô hình hoạt động!
        """
        (sip, sport, dip, dport, proto) = key_tuple
        duration = max(0.0, self.last_ts - self.first_ts)
        
        # Tính các chỉ số window-based QUAN TRỌNG cho DoS detection
        count = host_counts_window.get(("dst", dip), 0)
        srv_count = host_counts_window.get(("dst_srv", (dip, dport)), 0)
        dst_host_count = count
        dst_host_srv_count = srv_count
        
        # 🔍 DEBUG: Log features quan trọng cho flows lớn (nghi ngờ DoS)
        if count > 20 or (self.pkt_src + self.pkt_dst) > 50:
            print(f"🔍 FEATURES {sip}→{dip}:{dport} pkts={self.pkt_src+self.pkt_dst} duration={duration:.2f}s count={count} srv_count={srv_count}")
        
        # Tính các RATE quan trọng (KHÔNG ĐỂ = 0 nữa!)
        # same_srv_rate: tỷ lệ kết nối cùng service trong window (TOP #1 feature - 9.85% importance)
        same_srv_rate = float(srv_count) / max(1, count) if count > 0 else 0.0
        # diff_srv_rate: tỷ lệ kết nối khác service
        diff_srv_rate = 1.0 - same_srv_rate if count > 0 else 0.0
        
        # srv_diff_host_rate: tỷ lệ host khác nhau cho cùng service
        srv_diff_host_rate = 0.0  # Cần thêm tracking nếu muốn chính xác 100%
        
        # dst_host rates (TOP features cho DoS)
        dst_host_same_srv_rate = same_srv_rate  # TOP #3 feature (7.72%)
        dst_host_diff_srv_rate = diff_srv_rate
        dst_host_same_src_port_rate = 0.0  # Cần tracking chi tiết src_port
        dst_host_srv_diff_host_rate = 0.0
        
        # ERROR RATES: tính từ flag_counts (QUAN TRỌNG cho DoS/Probe detection)
        total_flags = sum(self.flag_counts.values())
        if total_flags > 0:
            # serror: SYN errors (S0=half-open, REJ=rejected, RSTR/RSTO=reset)
            serror_count = self.flag_counts.get("S0", 0) + self.flag_counts.get("REJ", 0)
            serror_rate = float(serror_count) / total_flags
            # rerror: REJ errors (connection refused)
            rerror_count = self.flag_counts.get("REJ", 0)
            rerror_rate = float(rerror_count) / total_flags
        else:
            serror_rate = 0.0
            rerror_rate = 0.0
        
        # srv & dst_host error rates (TOP #5 feature: dst_host_srv_serror_rate - 5.99%)
        srv_serror_rate = serror_rate
        srv_rerror_rate = rerror_rate  # TOP #8 feature (4.30%)
        dst_host_serror_rate = serror_rate
        dst_host_srv_serror_rate = serror_rate  # TOP #5 (5.99%)
        dst_host_rerror_rate = rerror_rate
        dst_host_srv_rerror_rate = rerror_rate
        
        # logged_in: TOP #4 feature (7.71%) - ước lượng dựa trên service
        logged_in = 1 if self.service in ['ssh', 'telnet', 'ftp', 'pop_3', 'imap4'] else 0
        
        # is_guest_login: TOP #16 feature (2.42%)
        is_guest_login = 0  # Thường = 0 trừ khi có evidence cụ thể
        
        # 🔍 DEBUG: Log key rates cho flows nghi ngờ
        if count > 20 or (self.pkt_src + self.pkt_dst) > 50:
            print(f"   same_srv_rate={same_srv_rate:.3f} serror_rate={serror_rate:.3f} logged_in={logged_in}")

        # NSL-KDD core columns - TÊN PHẢI KHỚP CHÍNH XÁC VỚI TRAINING!
        row = {
            "duration": duration,  # TOP #15 feature (2.52%)
            "protocol_type": self.proto,  # ✅ CRITICAL: phải là protocol_type KHÔNG phải proto!
            "service": self.service,
            "flag": max(self.flag_counts, key=self.flag_counts.get) if self.flag_counts else "SF",
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "land": int(sip == dip and sport == dport),  # TOP #24 feature
            "wrong_fragment": 0,  # TOP #12 feature (3.38%)
            "urgent": 0,
            "hot": 0,  # TOP #21 feature
            "num_failed_logins": 0,
            "logged_in": logged_in,  # ✅ TOP #4 (7.71%) - tính toán thay vì = 0
            "num_compromised": 0,
            "root_shell": 0,  # TOP #20 feature
            "su_attempted": 0,  # TOP #18 feature
            "num_root": 0,  # TOP #22 feature
            "num_file_creations": 0,  # TOP #19 feature
            "num_shells": 0,  # TOP #23 feature
            "num_access_files": 0,  # TOP #17 feature
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": is_guest_login,  # ✅ TOP #16 (2.42%)
            
            # Window-based features (CỰC KỲ QUAN TRỌNG cho DoS/Probe!)
            "count": count,  # ✅ TOP #6 (5.45%)
            "srv_count": srv_count,
            
            # Rate features (KHÔNG ĐỂ = 0 nữa - đây là lý do mô hình không hoạt động!)
            "serror_rate": serror_rate,  # ✅ Tính toán thực
            "srv_serror_rate": srv_serror_rate,  # ✅ Tính toán thực
            "rerror_rate": rerror_rate,  # ✅ Tính toán thực
            "srv_rerror_rate": srv_rerror_rate,  # ✅ TOP #8 (4.30%)
            "same_srv_rate": same_srv_rate,  # ✅ TOP #1 (9.85%) - QUAN TRỌNG NHẤT!
            "diff_srv_rate": diff_srv_rate,  # ✅ TOP #10 (3.61%)
            "srv_diff_host_rate": srv_diff_host_rate,  # ✅ TOP #11 (3.38%)
            
            # dst_host features (QUAN TRỌNG cho phát hiện scan/DoS phân tán)
            "dst_host_count": dst_host_count,  # ✅ TOP #7 (4.98%)
            "dst_host_srv_count": dst_host_srv_count,  # ✅ TOP #2 (8.34%)
            "dst_host_same_srv_rate": dst_host_same_srv_rate,  # ✅ TOP #3 (7.72%)
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,  # ✅ TOP #9 (4.30%)
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,  # ✅ TOP #13 (3.22%)
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,  # ✅ TOP #14 (2.67%)
            "dst_host_serror_rate": dst_host_serror_rate,  # ✅ Tính toán
            "dst_host_srv_serror_rate": dst_host_srv_serror_rate,  # ✅ TOP #5 (5.99%)
            "dst_host_rerror_rate": dst_host_rerror_rate,  # ✅ Tính toán
            "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,  # ✅ Tính toán
        }
        return row
