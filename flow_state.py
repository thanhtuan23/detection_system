# Theo dõi và lưu trữ trạng thái của từng flow (luồng kết nối) mạng.
import time
from collections import defaultdict
from ids_utils import tcp_flag_to_nslkdd

class FlowState:
    __slots__ = ("first_ts","last_ts","src_bytes","dst_bytes","pkt_src","pkt_dst",
                "proto","service","flag_counts")
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

    def to_feature_row(self, key_tuple, host_counts_window) -> dict:
        """
        Sinh 1 hàng đặc trưng CHÍNH XÁC theo NSL-KDD để khớp với pipeline training.
        """
        (sip, sport, dip, dport, proto) = key_tuple
        duration = max(0.0, self.last_ts - self.first_ts)
        
        # Tính các chỉ số window-based cho DoS detection
        count = host_counts_window.get(("dst", dip), 0)
        srv_count = host_counts_window.get(("dst_srv", (dip, dport)), 0)
        dst_host_count = count
        dst_host_srv_count = srv_count
        
        # Same/diff service rates
        same_srv_rate = float(srv_count) / max(1, count) if count > 0 else 0.0
        diff_srv_rate = 1.0 - same_srv_rate if count > 0 else 0.0
        srv_diff_host_rate = 0.0
        
        # dst_host rates
        dst_host_same_srv_rate = same_srv_rate
        dst_host_diff_srv_rate = diff_srv_rate
        dst_host_same_src_port_rate = 0.0
        dst_host_srv_diff_host_rate = 0.0
        
        # Error rates từ TCP flags
        total_flags = sum(self.flag_counts.values())
        if total_flags > 0:
            s0_count = self.flag_counts.get("S0", 0)  # SYN không response
            serror_rate = float(s0_count) / total_flags
            
            rerror_count = self.flag_counts.get("RSTR", 0) + self.flag_counts.get("RSTO", 0)
            rerror_rate = float(rerror_count) / total_flags
        else:
            serror_rate = 0.0
            rerror_rate = 0.0
        
        # Gán các chỉ số rate
        srv_serror_rate = serror_rate
        srv_rerror_rate = rerror_rate
        dst_host_serror_rate = serror_rate
        dst_host_srv_serror_rate = serror_rate
        dst_host_rerror_rate = rerror_rate
        dst_host_srv_rerror_rate = rerror_rate
        
        # Các trường NSL-KDD khác
        logged_in = 1 if self.service in ['ssh', 'telnet', 'ftp', 'pop_3', 'imap4'] else 0
        is_guest_login = 0

        # NSL-KDD 41 features
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
            "logged_in": logged_in,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": is_guest_login,
            # Window-based features
            "count": count,
            "srv_count": srv_count,
            # Rate features
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": srv_rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            # dst_host features
            "dst_host_count": dst_host_count,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_diff_srv_rate": dst_host_diff_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate,
            "dst_host_srv_diff_host_rate": dst_host_srv_diff_host_rate,
            "dst_host_serror_rate": dst_host_serror_rate,
            "dst_host_srv_serror_rate": dst_host_srv_serror_rate,
            "dst_host_rerror_rate": dst_host_rerror_rate,
            "dst_host_srv_rerror_rate": dst_host_srv_rerror_rate,
        }
        return row
