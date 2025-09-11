#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Realtime IDS Engine - Phiên bản cải tiến với hỗ trợ giao diện web
"""

import time
import threading
import logging
import os
import re
import queue
import configparser
from collections import defaultdict, deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# ------------ Cấu hình mặc định ------------
SERVICE_PORT_MAP = {
    80: "http", 443: "http_443", 21: "ftp", 20: "ftp_data",
    22: "ssh", 23: "telnet", 25: "smtp", 53: "domain_u", 110: "pop_3",
    143: "imap4", 8080: "http_8080"
}

# Danh sách các tên miền và IP tin cậy - thêm vào khi cần
TRUSTED_DOMAINS = [
    'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com', 
    'facebook.com', 'fbcdn.net', 'microsoft.com', 'windows.com',
    'apple.com', 'icloud.com', 'amazon.com', 'cloudfront.net',
    'cloudflare.com', 'akamai.net', 'fastly.net', 'github.com',
    'gmail.com', 'yahoo.com', 'twitter.com', 'instagram.com'
]

# Các IP nội bộ/private sẽ được xem là an toàn hơn
PRIVATE_IP_PATTERNS = [
    r'^10\.', 
    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    r'^192\.168\.',
    r'^127\.',
    r'^169\.254\.'
]

# Thiết lập logging
def setup_logging():
    # Tạo thư mục logs nếu chưa tồn tại
    os.makedirs("logs", exist_ok=True)
    
    # Thiết lập logger cho các cảnh báo tấn công
    attack_logger = logging.getLogger("attack_logger")
    attack_logger.setLevel(logging.INFO)
    
    # File handler
    file_handler = logging.FileHandler("logs/attack.log")
    file_format = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_format)
    attack_logger.addHandler(file_handler)
    
    # Không gửi log tới console
    attack_logger.propagate = False
    
    return attack_logger

def is_private_ip(ip):
    """Kiểm tra xem IP có phải là IP riêng/nội bộ không"""
    for pattern in PRIVATE_IP_PATTERNS:
        if re.match(pattern, ip):
            return True
    return False

def tcp_flag_to_nslkdd(pkt) -> str:
    """
    Ánh xạ TCP flags về nhãn gần giống NSL-KDD
    """
    if not pkt.haslayer(TCP):
        return "SF"
    flags = pkt[TCP].flags
    # bit flags
    F = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}
    fS, fF, fR, fA = bool(flags & F["S"]), bool(flags & F["F"]), bool(flags & F["R"]), bool(flags & F["A"])
    if fR and not fA:
        return "REJ"
    if fS and not fA:
        return "S0"
    if fR and fA:
        return "RSTR"
    if fF and fA:
        return "RSTO"
    if fS and fF:
        return "SH"
    return "SF"

def proto_name(pkt) -> str:
    if pkt.haslayer(TCP):  return "tcp"
    if pkt.haslayer(UDP):  return "udp"
    if pkt.haslayer(ICMP): return "icmp"
    return "tcp"  # mặc định

def guess_service(pkt) -> str:
    dport = None
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        dport = pkt[UDP].dport
    if dport in SERVICE_PORT_MAP:
        return SERVICE_PORT_MAP[dport]
    return "other"

# --------- Bộ gom & đặc trưng luồng ----------
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

class IDSEngine:
    def __init__(self, config_path='config.ini'):
        # Đọc cấu hình
        config = configparser.ConfigParser()
        config.read(config_path)
        
        # Network config
        self.iface = config.get('Network', 'interface')
        self.window = config.getint('Network', 'window')
        self.min_pkts = config.getint('Network', 'min_packets')
        self.min_bytes = config.getint('Network', 'min_bytes')
        
        # Model config
        self.model_path = config.get('Model', 'model_path')
        self.preprocess_path = config.get('Model', 'preprocess_path')
        self.alert_threshold = config.getfloat('Model', 'threshold')
        
        # Filtering config
        self.whitelist_file = config.get('Filtering', 'whitelist_file')
        self.blacklist_file = config.get('Filtering', 'blacklist_file')
        
        # Thiết lập logging
        self.attack_logger = setup_logging()
        
        # Hàng đợi thông báo
        self.alert_queue = queue.Queue()
        
        # Biến điều khiển
        self.running = False
        self.sniff_thread = None
        self.predict_thread = None
        
        # Khởi tạo whitelist/blacklist từ file nếu có
        self.whitelist = set()
        self.blacklist = set()
        if os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, 'r') as f:
                self.whitelist = set(line.strip() for line in f if line.strip())
        if os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'r') as f:
                self.blacklist = set(line.strip() for line in f if line.strip())

        # Thêm các tên miền tin cậy vào whitelist
        self.whitelist.update(TRUSTED_DOMAINS)

        # luồng: key = (src, sport, dst, dport, proto)
        self.flows = {}
        self.lock = threading.Lock()

        # hàng đợi thống kê theo cửa sổ (để ước lượng count/srv_count)
        self.host_events = deque(maxlen=100000)
        
        # Lưu trữ các dự đoán trước đó
        self.previous_alerts = {}  # key: flow_key, value: (count, last_time)
        
        # Ngưỡng số lượng gói tin TCP/s để phát hiện quét cổng
        self.port_scan_threshold = 10
        self.port_scan_window = {}  # {src_ip: {dst_port: count}}
        self.port_scan_last_clean = time.time()
        
        # Thống kê
        self.stats = {
            "packets_processed": 0,
            "flows_analyzed": 0,
            "alerts_generated": 0,
            "start_time": None,
            "packets_per_second": 0,
            "last_update_time": time.time(),
            "bytes_processed": 0
        }
        
        # Lưu 100 cảnh báo gần nhất để hiển thị trên giao diện
        self.recent_alerts = deque(maxlen=100)

    def load_model(self):
        """Tải mô hình và pipeline tiền xử lý"""
        print("[*] Loading model and preprocessing pipeline...")
        try:
            # Kiểm tra xem thư mục chứa mô hình có tồn tại không
            model_dir = os.path.dirname(self.model_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir, exist_ok=True)
                
            # Nếu mô hình chưa tồn tại, cảnh báo người dùng
            if not os.path.exists(self.model_path):
                print(f"[!] Warning: Model file {self.model_path} does not exist")
                return False
                
            if not os.path.exists(self.preprocess_path):
                print(f"[!] Warning: Preprocess file {self.preprocess_path} does not exist")
                return False
                
            self.preprocess = joblib.load(self.preprocess_path)
            self.model = tf.keras.models.load_model(self.model_path)
            print("[+] Model loaded successfully")
            return True
        except Exception as e:
            print(f"[!] Error loading model: {e}")
            return False

    def _flow_key(self, pkt):
        sip, dip = pkt[IP].src, pkt[IP].dst
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        proto = proto_name(pkt)
        # dùng thứ tự src->dst cố định
        return (sip, sport, dip, dport, proto)

    def _direction_src_to_dst(self, pkt, key):
        # key theo chiều src->dst
        sip, sport, dip, dport, _ = key
        ps, pd = None, None
        if pkt.haslayer(TCP):
            ps, pd = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            ps, pd = pkt[UDP].sport, pkt[UDP].dport
        return (pkt[IP].src == sip) and (ps == sport) and (pkt[IP].dst == dip) and (pd == dport)

    def _update_host_window(self, pkt):
        # Lưu sự kiện đích để thống kê count theo cửa sổ
        now = time.time()
        dip = pkt[IP].dst
        dport = (pkt[TCP].dport if pkt.haslayer(TCP) else
                 pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        self.host_events.append((now, dip, dport))

    def _build_host_counts(self):
        # Tính count/srv_count trong cửa sổ self.window giây gần nhất
        t0 = time.time() - self.window
        dst_count = defaultdict(int)
        dst_srv_count = defaultdict(int)
        for ts, dip, dport in list(self.host_events):
            if ts >= t0:
                dst_count[("dst", dip)] += 1
                dst_srv_count[("dst_srv", (dip, dport))] += 1
        counts = {}
        counts.update(dst_count)
        counts.update(dst_srv_count)
        return counts
    
    def _is_in_whitelist(self, ip):
        """Kiểm tra xem IP có trong whitelist không"""
        return ip in self.whitelist
    
    def _is_in_blacklist(self, ip):
        """Kiểm tra xem IP có trong blacklist không"""
        return ip in self.blacklist
    
    def _should_ignore_https(self, key, state):
        """
        Xác định xem có nên bỏ qua cảnh báo cho kết nối HTTPS không
        dựa trên các tiêu chí của lưu lượng web bình thường
        """
        sip, sport, dip, dport, proto = key
        
        # Nếu là HTTPS (cổng 443)
        if dport == 443 or sport == 443:
            # Nếu thời lượng kết nối ngắn (< 10s) và lưu lượng trong mức hợp lý
            if (state.last_ts - state.first_ts < 10 and 
                state.src_bytes < 50000 and state.dst_bytes < 500000):
                # Kiểm tra các yếu tố khác của kết nối web thông thường
                if "SF" in state.flag_counts or "S0" in state.flag_counts:
                    # Tính tỉ lệ byte gửi/nhận, kết nối web thường nhận nhiều hơn gửi
                    if state.dst_bytes > 0 and state.src_bytes / state.dst_bytes < 0.5:
                        return True
        return False

    def _check_port_scan(self, pkt):
        """Kiểm tra dấu hiệu quét cổng TCP"""
        if not pkt.haslayer(TCP):
            return False
        
        now = time.time()
        # Dọn dẹp cửa sổ quét cổng cũ (mỗi 60s)
        if now - self.port_scan_last_clean > 60:
            self.port_scan_window = {}
            self.port_scan_last_clean = now
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        
        # Chỉ quan tâm đến các gói SYN (dấu hiệu quét cổng)
        if pkt[TCP].flags & 0x02:  # SYN flag
            if src_ip not in self.port_scan_window:
                self.port_scan_window[src_ip] = defaultdict(int)
            
            # Đếm số lượng cổng đích khác nhau
            self.port_scan_window[src_ip][dst_port] += 1
            
            # Nếu số lượng cổng đích vượt ngưỡng, coi là quét cổng
            if len(self.port_scan_window[src_ip]) > self.port_scan_threshold:
                port_list = list(self.port_scan_window[src_ip].keys())
                alert_msg = f"PORT SCAN DETECTED from {src_ip} to {dst_ip} (ports: {port_list[:5]}...)"
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                print(f"[{now_str}] {alert_msg}")
                self.attack_logger.info(alert_msg)
                
                # Thêm vào hàng đợi thông báo
                alert_data = {
                    "type": "port_scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ports": port_list[:10],
                    "time": now_str,
                    "message": alert_msg
                }
                self.alert_queue.put(alert_data)
                self.recent_alerts.append(alert_data)
                self.stats["alerts_generated"] += 1
                
                # Reset lại để không cảnh báo liên tục
                self.port_scan_window[src_ip] = {}
                return True
        
        return False

    def _should_process_pkt(self, pkt):
        """Kiểm tra xem gói tin có nên được xử lý hay không (lọc DNS/QUIC và lưu lượng nhỏ)"""
        if not pkt.haslayer(IP):
            return False
            
        # Kiểm tra quét cổng
        if self._check_port_scan(pkt):
            return False  # Đã xử lý ở hàm _check_port_scan
        
        # Lấy địa chỉ IP
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Kiểm tra whitelist/blacklist
        if self._is_in_whitelist(src_ip) or self._is_in_whitelist(dst_ip):
            return False
        
        if self._is_in_blacklist(src_ip) or self._is_in_blacklist(dst_ip):
            alert_msg = f"BLACKLISTED IP DETECTED: {src_ip} -> {dst_ip}"
            now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
            print(f"[{now_str}] {alert_msg}")
            self.attack_logger.info(alert_msg)
            
            # Thêm vào hàng đợi thông báo
            alert_data = {
                "type": "blacklist",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "time": now_str,
                "message": alert_msg
            }
            self.alert_queue.put(alert_data)
            self.recent_alerts.append(alert_data)
            self.stats["alerts_generated"] += 1
            return False
        
        # Bỏ qua các gói UDP phổ biến từ DNS và QUIC
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            # Lọc DNS (port 53) và QUIC (thường dùng 443/UDP)
            if dport == 53 or sport == 53 or dport == 443 or sport == 443:
                return False
        
        # Kiểm tra kích thước gói tin quá nhỏ
        if len(pkt) < 40:  # Kích thước tối thiểu cho IP + TCP/UDP header
            return False
            
        # Nếu cả hai IP đều là private, có thể là lưu lượng nội bộ an toàn
        if is_private_ip(src_ip) and is_private_ip(dst_ip):
            # Vẫn xử lý nhưng sẽ cân nhắc khi cảnh báo
            pass
            
        # Xử lý các kết nối HTTPS thông thường (cổng 443)
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if dport == 443 or sport == 443:
                # Sẽ vẫn thu thập nhưng áp dụng logic đặc biệt khi dự đoán
                pass
        
        return True

    def _packet_cb(self, pkt):
        try:
            # Cập nhật thống kê
            self.stats["packets_processed"] += 1
            pkt_size = len(pkt)
            self.stats["bytes_processed"] += pkt_size
            
            # Cập nhật packets_per_second mỗi giây
            now = time.time()
            if now - self.stats["last_update_time"] >= 1:
                elapsed = now - self.stats["last_update_time"]
                if elapsed > 0:
                    self.stats["packets_per_second"] = int(self.stats["packets_processed"] / 
                                                         (now - self.stats["start_time"]))
                self.stats["last_update_time"] = now
            
            if not self._should_process_pkt(pkt):
                return
                
            key = self._flow_key(pkt)
            with self.lock:
                if key not in self.flows:
                    self.flows[key] = FlowState(proto_name(pkt), guess_service(pkt))
                state = self.flows[key]
                direction = self._direction_src_to_dst(pkt, key)
                state.update(pkt, direction)
                self._update_host_window(pkt)
        except Exception as e:
            # tránh crash callback
            print(f"CB error: {e}")

    def _post_process_alert(self, key, prob, state):
        """
        Hậu xử lý để quyết định có nên cảnh báo không 
        dựa trên heuristic và lịch sử
        """
        sip, sport, dip, dport, proto = key
        
        # Nếu là kết nối HTTPS thông thường, áp dụng kiểm tra bổ sung
        if self._should_ignore_https(key, state):
            return False
            
        # Kiểm tra tần suất lưu lượng (DoS thường có rate cao)
        if state.rate_src > 1000000 or state.rate_dst > 1000000:  # >1MB/s
            return True  # Cảnh báo DoS có độ tin cậy cao
            
        # Kiểm tra lịch sử cảnh báo cho luồng tương tự
        flow_id = f"{sip}-{dip}-{proto}"
        now = time.time()
        
        # Nếu đã cảnh báo gần đây, giảm số lượng cảnh báo lặp
        if flow_id in self.previous_alerts:
            count, last_time = self.previous_alerts[flow_id]
            # Nếu cảnh báo trong 60 giây gần đây
            if now - last_time < 60:
                # Chỉ cảnh báo lại nếu prob tăng đáng kể
                if count > 3 and prob < 0.95:
                    return False
                self.previous_alerts[flow_id] = (count + 1, now)
            else:
                # Quá 60s, đặt lại bộ đếm
                self.previous_alerts[flow_id] = (1, now)
        else:
            self.previous_alerts[flow_id] = (1, now)
            
        # Kiểm tra ngoại lệ cho HTTPS với các website phổ biến
        if dport == 443 and prob < 0.9:
            # Áp dụng ngưỡng cao hơn cho HTTPS để giảm cảnh báo sai
            return False
            
        # Kiểm tra kết nối nội bộ
        if is_private_ip(sip) and is_private_ip(dip):
            # Yêu cầu xác suất cao hơn cho cảnh báo nội bộ
            return prob > 0.85
            
        return True

    def _predict_and_alert(self):
        """Luồng phân tích và cảnh báo"""
        while self.running:
            time.sleep(self.window)
            with self.lock:
                if not self.flows:
                    continue
                
                # Lọc luồng có đủ số lượng gói tin và byte để phân tích
                filtered_flows = {}
                for k, state in list(self.flows.items()):
                    total_pkts = state.pkt_src + state.pkt_dst
                    total_bytes = state.src_bytes + state.dst_bytes
                    if total_pkts >= self.min_pkts and total_bytes >= self.min_bytes:
                        filtered_flows[k] = state
                
                if not filtered_flows:
                    self.flows.clear()
                    continue
                
                self.stats["flows_analyzed"] += len(filtered_flows)
                    
                host_counts = self._build_host_counts()
                rows, keys, states = [], [], []
                for k, st in list(filtered_flows.items()):
                    rows.append(st.to_feature_row(k, host_counts))
                    keys.append(k)
                    states.append(st)
                df = pd.DataFrame(rows)

                # Các cột còn thiếu so với preprocess sẽ được OneHot/Scaler bỏ qua
                # (OneHot handle_unknown='ignore'); với số thì thiếu sẽ không có scaler.
                # Đảm bảo đủ cột numeric cốt lõi
                for col in ["duration","src_bytes","dst_bytes","count","srv_count",
                            "dst_host_count","dst_host_srv_count"]:
                    if col not in df:
                        df[col] = 0.0

                X = self.preprocess.transform(df)
                # dự đoán xác suất (nếu model sigmoid 1 output)
                probs = self.model.predict(X, verbose=0).ravel()
                preds = (probs >= self.alert_threshold).astype(int)

                # In cảnh báo sau khi áp dụng hậu xử lý
                now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                for i, (k, p, pr, st) in enumerate(zip(keys, preds, probs, states)):
                    if p == 1 and self._post_process_alert(k, pr, st):
                        sip, sport, dip, dport, proto = k
                        attack_type = "DoS" if (st.rate_src > 500000 or st.rate_dst > 500000) else "Attack"
                        alert_msg = f"ALERT {attack_type} proto={proto} {sip}:{sport} -> {dip}:{dport} prob={pr:.3f} window={self.window}s"
                        print(f"[{now}] {alert_msg}")
                        
                        # Ghi log vào file
                        self.attack_logger.info(alert_msg)
                        
                        # Thêm vào hàng đợi thông báo và danh sách cảnh báo gần đây
                        alert_data = {
                            "type": attack_type.lower(),
                            "src_ip": sip,
                            "src_port": sport,
                            "dst_ip": dip,
                            "dst_port": dport, 
                            "proto": proto,
                            "probability": float(pr),
                            "time": now,
                            "message": alert_msg,
                            "bytes_src": st.src_bytes,
                            "bytes_dst": st.dst_bytes,
                            "rate_src": st.rate_src,
                            "rate_dst": st.rate_dst,
                            "duration": st.last_ts - st.first_ts
                        }
                        self.alert_queue.put(alert_data)
                        self.recent_alerts.append(alert_data)
                        self.stats["alerts_generated"] += 1

                # reset bộ đếm sau mỗi cửa sổ
                self.flows.clear()

    def start(self):
        """Bắt đầu IDS"""
        if self.running:
            return False
            
        if not hasattr(self, 'model') or not hasattr(self, 'preprocess'):
            if not self.load_model():
                return False
                
        self.running = True
        self.stats["start_time"] = time.time()
        
        # Bắt đầu luồng dự đoán
        self.predict_thread = threading.Thread(target=self._predict_and_alert)
        self.predict_thread.daemon = True
        self.predict_thread.start()
        
        # Bắt đầu luồng bắt gói tin
        def start_sniffing():
            print(f"[*] Sniffing on {self.iface}...")
            sniff(iface=self.iface, prn=self._packet_cb, store=False, 
                  stop_filter=lambda x: not self.running)
                  
        self.sniff_thread = threading.Thread(target=start_sniffing)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
        print(f"[*] IDS started on {self.iface} with window={self.window}s, threshold={self.alert_threshold}")
        return True
        
    def stop(self):
        """Dừng IDS"""
        if not self.running:
            return
            
        self.running = False
        
        # Đợi luồng dự đoán kết thúc
        if self.predict_thread and self.predict_thread.is_alive():
            self.predict_thread.join(timeout=2)
            
        # Luồng sniff sẽ tự dừng nhờ stop_filter
        print("[*] IDS stopped")
        
    def get_stats(self):
        """Lấy thống kê hiện tại"""
        stats = self.stats.copy()
        if stats["start_time"]:
            stats["uptime"] = time.time() - stats["start_time"]
        else:
            stats["uptime"] = 0
        return stats
        
    def get_recent_alerts(self):
        """Lấy danh sách các cảnh báo gần đây"""
        return list(self.recent_alerts)
        
    def get_next_alert(self, timeout=0.1):
        """Lấy cảnh báo tiếp theo từ hàng đợi, trả về None nếu không có"""
        try:
            return self.alert_queue.get(timeout=timeout)
        except queue.Empty:
            return None

# Singleton instance
_ids_instance = None

def get_ids_instance(config_path='config.ini'):
    """Lấy hoặc tạo instance IDSEngine"""
    global _ids_instance
    if _ids_instance is None:
        _ids_instance = IDSEngine(config_path)
    return _ids_instance