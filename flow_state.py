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
        Sinh 1 hàng đặc trưng gần với NSL-KDD (tập con cốt lõi).
        """
        (sip, sport, dip, dport, proto) = key_tuple
        duration = max(0.0, self.last_ts - self.first_ts)

        # NSL-KDD core columns
        row = {
            "duration": duration,
            "protocol_type": self.proto,
            "service": self.service,
            "flag": max(self.flag_counts, key=self.flag_counts.get) if self.flag_counts else "SF",
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "land": int(sip == dip and sport == dport),
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            # Các chỉ số dựa cửa sổ (xấp xỉ count/srv_count):
            "count": host_counts_window.get(("dst", dip), 0),
            "srv_count": host_counts_window.get(("dst_srv", (dip, dport)), 0),
            # Các tỷ lệ lỗi/serror… tạm 0 (phụ thuộc trace TCP chi tiết)
            "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
            "same_srv_rate": 0.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
            "dst_host_count": host_counts_window.get(("dst", dip), 0),
            "dst_host_srv_count": host_counts_window.get(("dst_srv", (dip, dport)), 0),
            "dst_host_same_srv_rate": 0.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0,
            "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0,
            "dst_host_srv_rerror_rate": 0.0,
            # Các đặc trưng bổ sung
            "rate_src": self.rate_src,
            "rate_dst": self.rate_dst,
            "is_https": int(self.is_https),
        }
        return row
