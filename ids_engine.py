#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

Luồng hoạt động:
1. Thu thập gói tin realtime (sniff)
2. Gom thành flows (luồng mạng)
3. Tính đặc trưng NSL-KDD
4. Dự đoán bằng AI model (ML/DL)
5. Gửi cảnh báo qua Email/Telegram

"""

import os
import time
import queue
import threading
import configparser
import fnmatch
from collections import defaultdict, deque
from datetime import datetime

import numpy as np
import pandas as pd

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from scapy.all import sniff, IP, TCP, UDP

# Internal modules
from logging_utils import setup_logging
from ids_utils import proto_name, guess_service
from flow_state import FlowState
from model_runtime import load_model_and_preprocess, predict_probabilities


class IDSEngine:
    """Simplified IDS - AI-only attack detection"""
    
    def __init__(self, config_path: str = 'config.ini'):
        # Đọc cấu hình
        config = configparser.ConfigParser()
        config.read(config_path, encoding='utf-8')
        
        # Cấu hình mạng
        self.iface = config.get('Network', 'interface')
        self.window = config.getint('Network', 'window')
        self.min_pkts = config.getint('Network', 'min_packets')
        self.min_bytes = config.getint('Network', 'min_bytes')
        
        # Cấu hình mô hình AI
        self.model_path = config.get('Model', 'model_path')
        self.preprocess_path = config.get('Model', 'preprocess_path')
        self.alert_threshold = config.getfloat('Model', 'threshold')
        
        # Server IPs để filter traffic (chỉ phân tích traffic tới server)
        self.server_ip = config.get('Network', 'server_ip', fallback='')
        self.local_ips = set(ip.strip() for ip in config.get('Network', 'local_ips', fallback='').split(',') if ip.strip())
        if self.server_ip:
            self.local_ips.add(self.server_ip)
        
        # Whitelist/Blacklist
        self.whitelist_file = config.get('Filtering', 'whitelist_file', fallback='data/whitelist.txt')
        self.blacklist_file = config.get('Filtering', 'blacklist_file', fallback='data/blacklist.txt')
        self.ignore_https = config.getboolean('Filtering', 'ignore_https', fallback=True)
        self.whitelist_ips = set()
        self.blacklist_ips = set()
        self._load_lists()
        
        # Logger
        self.attack_logger = setup_logging()
        
        # Trạng thái
        self.running = False
        self.sniff_thread = None
        self.predict_thread = None
        
        # Lưu trạng thái flows
        self.flows = {}
        self.lock = threading.Lock()
        
        # Bộ nhớ cho host count features
        self.host_events = deque(maxlen=100000)
        
        # ===== FLOOD DETECTION =====
        # Theo dõi packets per FLOW (src_ip:src_port)
        self.flood_tracker = defaultdict(lambda: deque(maxlen=1000))  # {flow_id: [timestamp, ...]}
        self.flood_threshold = 100  # packets/giây per flow = FLOOD
        self.flood_cooldown = {}  # {flow_id: last_alert_time} - tránh spam alerts
        
        # Theo dõi số lần ping (ICMP) từ mỗi IP - SAFE RULE: < 10 ping = an toàn
        self.icmp_counter = defaultdict(int)  # {src_ip: total_ping_count}
        self.icmp_safe_threshold = 10  # < 10 ping = an toàn, không cảnh báo
        
        # Thống kê
        self.stats = {
            "packets_processed": 0,
            "flows_analyzed": 0,
            "alerts_generated": 0,
            "start_time": None,
            "packets_per_second": 0,
            "last_update_time": time.time(),
            "bytes_processed": 0,
        }
        
        # Alert queue và recent alerts
        self.alert_queue = queue.Queue()
        self.recent_alerts = deque(maxlen=100)
        
        # Model
        self.model_type = None
        self.model = None
        self.preprocess = None
    
    def _load_lists(self):
        """Load whitelist and blacklist from files"""
        # Load whitelist
        if os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()
                    if line and not line.startswith('#'):
                        self.whitelist_ips.add(line)
            print(f"[*] Loaded {len(self.whitelist_ips)} whitelist entries")
        else:
            print(f"[!] Whitelist file not found: {self.whitelist_file}")
        
        # Load blacklist
        if os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()
                    if line and not line.startswith('#'):
                        self.blacklist_ips.add(line)
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        for pattern in self.whitelist_ips:
            # Exact match
            if ip == pattern:
                return True
            # Wildcard match (e.g., 192.168.*.*)
            if '*' in pattern:
                # Convert to regex-like pattern
                # 192.168.*.* → match any IP starting with 192.168.
                parts = pattern.split('.')
                ip_parts = ip.split('.')
                if len(parts) == len(ip_parts):
                    match = True
                    for p, i in zip(parts, ip_parts):
                        if p != '*' and p != i:
                            match = False
                            break
                    if match:
                        return True
        return False
    
    def _is_blacklisted(self, ip: str) -> bool:
        """Check if IP is in blacklist"""
        for pattern in self.blacklist_ips:
            # Exact match
            if ip == pattern:
                return True
            # Wildcard match (e.g., 192.168.*.*)
            if '*' in pattern:
                parts = pattern.split('.')
                ip_parts = ip.split('.')
                if len(parts) == len(ip_parts):
                    match = True
                    for p, i in zip(parts, ip_parts):
                        if p != '*' and p != i:
                            match = False
                            break
                    if match:
                        return True
        return False
    
    def load_model(self) -> bool:
        """Load AI model và preprocessing pipeline"""
        print("[*] Loading AI model...")
        try:
            self.preprocess, self.model, self.model_type, info = load_model_and_preprocess(
                self.preprocess_path, self.model_path
            )
            model_name = info.get('best_ml_name', 'DL') if self.model_type == 'ml' else 'DL'
            print(f"Loaded {model_name} (threshold={self.alert_threshold})")
            return True
        except Exception as e:
            print(f"❌ Model load failed: {e}")
            return False
    
    def apply_config(self, live_cfg):
        """Hot reload configuration"""
        try:
            self.window = live_cfg.getint('Network', 'window', fallback=self.window)
            self.min_pkts = live_cfg.getint('Network', 'min_packets', fallback=self.min_pkts)
            self.min_bytes = live_cfg.getint('Network', 'min_bytes', fallback=self.min_bytes)
            self.alert_threshold = live_cfg.getfloat('Model', 'threshold', fallback=self.alert_threshold)
            
            # Reload model nếu path thay đổi
            new_model_path = live_cfg.get('Model', 'model_path', fallback=self.model_path)
            new_pre_path = live_cfg.get('Model', 'preprocess_path', fallback=self.preprocess_path)
            if (new_model_path != self.model_path) or (new_pre_path != self.preprocess_path):
                self.model_path = new_model_path
                self.preprocess_path = new_pre_path
                self.load_model()
        except Exception as e:
            print(f'[Config] Error: {e}')
    
    def _flow_key(self, pkt):
        """Tạo flow key từ packet"""
        sip = pkt[IP].src
        dip = pkt[IP].dst
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        proto = proto_name(pkt)
        return (sip, sport, dip, dport, proto)
    
    def _direction_src_to_dst(self, pkt, key):
        """Xác định chiều gói tin"""
        sip, sport, dip, dport, _ = key
        ps = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        pd = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        return (pkt[IP].src == sip) and (ps == sport) and (pkt[IP].dst == dip) and (pd == dport)
    
    def _update_host_window(self, pkt):
        """Cập nhật host events cho count features"""
        now = time.time()
        dip = pkt[IP].dst
        dport = (pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        self.host_events.append((now, dip, dport))
    
    def _build_host_counts(self):
        """Tính count và srv_count features"""
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
    
    def _packet_cb(self, pkt):
        """Callback xử lý từng packet"""
        try:
            if not pkt.haslayer(IP):
                return
            
            dst_ip = pkt[IP].dst
            if self.local_ips and dst_ip not in self.local_ips:
                return  # Bỏ qua traffic không tới server
            
            # Ignore HTTPS traffic (port 443)
            if self.ignore_https:
                if pkt.haslayer(TCP):
                    if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                        return
                elif pkt.haslayer(UDP):
                    if pkt[UDP].dport == 443 or pkt[UDP].sport == 443:
                        return
            
            # ===== FLOOD DETECTION  =====
            src_ip = pkt[IP].src
            now = time.time()
            
            # Lấy source port và dest port
            src_port = 0
            dst_port = 0
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            
            # ===== ICMP SAFE RULE: < 10 ping = an toàn =====
            from scapy.all import ICMP
            is_icmp_echo = False
            if pkt.haslayer(ICMP):
                if pkt[ICMP].type == 8:  # Echo Request (ping)
                    is_icmp_echo = True
                    self.icmp_counter[src_ip] += 1
                    
                    # Nếu < ngưỡng an toàn, bỏ qua flood detection cho ICMP này
                    if self.icmp_counter[src_ip] < self.icmp_safe_threshold:
                        # Vẫn update flow state nhưng không kiểm tra flood
                        key = self._flow_key(pkt)
                        with self.lock:
                            if key not in self.flows:
                                self.flows[key] = FlowState(proto_name(pkt), guess_service(pkt))
                            state = self.flows[key]
                            direction = self._direction_src_to_dst(pkt, key)
                            state.update(pkt, direction)
                            self._update_host_window(pkt)
                        
                        # Thống kê
                        self.stats["packets_processed"] += 1
                        self.stats["bytes_processed"] += len(pkt)
                        return  # Bỏ qua flood detection
            
            # Track packets theo FLOW (src_ip:src_port)
            flow_id = f"{src_ip}:{src_port}"
            self.flood_tracker[flow_id].append(now)
            
            # Đếm packets trong 1 giây gần nhất
            one_sec_ago = now - 1.0
            recent_packets = [ts for ts in self.flood_tracker[flow_id] if ts >= one_sec_ago]
            
            # Nếu > threshold packets/giây → FLOOD ATTACK
            if len(recent_packets) >= self.flood_threshold:
                # Check cooldown (tránh spam alerts)
                last_alert = self.flood_cooldown.get(flow_id, 0)
                if now - last_alert >= 0.1:  # Alert mỗi 0.1 giây
                    self.flood_cooldown[flow_id] = now
                    
                    # Tạo alert ngay lập tức
                    alert = {
                        "timestamp": datetime.now().isoformat(),
                        "type": "attack",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "probability": 1.0,  # 100% chắc chắn (rule-based)
                        "packets": len(recent_packets),
                        "bytes": 0,
                        "message": f"FLOOD ATTACK: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({len(recent_packets)} pkt/s)"
                    }
                    
                    self.attack_logger.info(alert["message"])
                    self.alert_queue.put(alert)
                    self.recent_alerts.append(alert)
                    self.stats["alerts_generated"] += 1
                    
                    print(f"[!] FLOOD: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({len(recent_packets)} pkt/s)")
            
            # Thống kê
            self.stats["packets_processed"] += 1
            self.stats["bytes_processed"] += len(pkt)
            
            if now - self.stats["last_update_time"] >= 1:
                if self.stats["start_time"]:
                    self.stats["packets_per_second"] = int(
                        self.stats["packets_processed"] / (now - self.stats["start_time"])
                    )
                self.stats["last_update_time"] = now
            
            # Cập nhật flow state
            key = self._flow_key(pkt)
            with self.lock:
                if key not in self.flows:
                    self.flows[key] = FlowState(proto_name(pkt), guess_service(pkt))
                
                state = self.flows[key]
                direction = self._direction_src_to_dst(pkt, key)
                state.update(pkt, direction)
                self._update_host_window(pkt)
        
        except Exception as e:
            if not isinstance(e, (AttributeError, IndexError)):
                pass  # Bỏ qua lỗi packet không đầy đủ
    
    def _predict_and_alert(self):
        """Thread chính: phân tích flows và phát hiện tấn công"""
        while self.running:
            time.sleep(self.window)
            
            with self.lock:
                if not self.flows:
                    continue
                
                # Lọc flows đủ điều kiện
                filtered_flows = {}
                for k, state in list(self.flows.items()):
                    total_pkts = state.pkt_src + state.pkt_dst
                    total_bytes = state.src_bytes + state.dst_bytes
                    
                    if total_pkts >= self.min_pkts or total_bytes >= self.min_bytes:
                        filtered_flows[k] = state
                
                if not filtered_flows:
                    self.flows.clear()
                    continue
                
                self.stats["flows_analyzed"] += len(filtered_flows)
                
                # Chuyển flows thành features
                host_counts = self._build_host_counts()
                rows, keys, states = [], [], []
                
                for k, st in filtered_flows.items():
                    rows.append(st.to_feature_row(k, host_counts))
                    keys.append(k)
                    states.append(st)
                
                if not rows:
                    self.flows.clear()
                    continue
                
                # Tạo DataFrame và preprocess
                df = pd.DataFrame(rows)
                
                # Đảm bảo có đủ columns cơ bản
                for col in ["duration", "src_bytes", "dst_bytes", "count", "srv_count", 
                           "dst_host_count", "dst_host_srv_count"]:
                    if col not in df:
                        df[col] = 0.0
                
                # Predict (41 NSL-KDD features chuẩn)
                X = self.preprocess.transform(df)
                probs = predict_probabilities(self.model, self.model_type, X).ravel()
                preds = (probs >= self.alert_threshold).astype(int)
                
                # Generate alerts
                alert_count = 0
                for k, pred, prob, st in zip(keys, preds, probs, states):
                    if pred == 1:  # Attack detected
                        sip, sport, dip, dport, _ = k  # Bỏ proto, không hiển thị
                        
                        # Skip whitelisted IPs (internal network)
                        src_wl = self._is_whitelisted(sip)
                        dst_wl = self._is_whitelisted(dip)
                        if src_wl or dst_wl:
                            continue
                        
                        # Force alert if blacklisted
                        if not (self._is_blacklisted(sip) or self._is_blacklisted(dip)):
                            # Normal AI threshold check
                            pass  # Already pred==1 means passed threshold
                        
                        # Tạo alert (không có protocol)
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "type": "attack",  # CHỈ có 1 loại: ATTACK
                            "src_ip": sip,
                            "src_port": sport,
                            "dst_ip": dip,
                            "dst_port": dport,
                            "probability": float(prob),
                            "packets": st.pkt_src + st.pkt_dst,
                            "bytes": st.src_bytes + st.dst_bytes,
                            "message": f"ATTACK detected: {sip}:{sport} → {dip}:{dport} - Probability: {prob:.3f}"
                        }
                        
                        # Log
                        self.attack_logger.info(alert["message"])
                        
                        # Add to queues
                        self.alert_queue.put(alert)
                        self.recent_alerts.append(alert)
                        
                        self.stats["alerts_generated"] += 1
                        alert_count += 1
                
                if alert_count > 0:
                    print(f"[!] {alert_count} ATTACK(S) detected in this window")
                
                # Reset flows
                self.flows.clear()
    
    def start(self) -> bool:
        """Khởi động IDS"""
        if self.running:
            return False
        
        # Load model
        if not hasattr(self, 'model') or self.model is None:
            if not self.load_model():
                return False
        
        self.running = True
        self.stats["start_time"] = time.time()
        
        # Start prediction thread
        self.predict_thread = threading.Thread(target=self._predict_and_alert, daemon=True)
        self.predict_thread.start()
        
        # Start sniffing thread
        def start_sniffing():
            iface = str(self.iface).strip()
            ifaces = [i.strip() for i in iface.split(',') if i.strip()]
            iface_arg = ifaces if len(ifaces) > 1 else (ifaces[0] if ifaces else None)
            
            print(f"[*] Sniffing on {iface_arg}")
            
            sniff(iface=iface_arg, prn=self._packet_cb, store=False, 
                  stop_filter=lambda x: not self.running)
        
        self.sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniff_thread.start()
        
        print(f"[*] IDS started")
        print(f"    Interface: {self.iface}")
        print(f"    Window: {self.window}s")
        print(f"    Threshold: {self.alert_threshold}")
        print(f"    Monitoring IPs: {self.local_ips if self.local_ips else 'ALL'}")
        print(f"    Ignore HTTPS: {self.ignore_https}")
        return True
    
    def stop(self):
        """Dừng IDS"""
        if not self.running:
            return
        self.running = False
        if self.predict_thread and self.predict_thread.is_alive():
            self.predict_thread.join(timeout=2)
        print("[*] IDS stopped")
    
    def get_stats(self):
        """Lấy thống kê"""
        stats = self.stats.copy()
        if stats["start_time"]:
            stats["uptime"] = time.time() - stats["start_time"]
        else:
            stats["uptime"] = 0
        return stats
    
    def get_recent_alerts(self):
        """Lấy danh sách alerts gần đây"""
        return list(self.recent_alerts)
    
    def get_next_alert(self, timeout: float = 0.1):
        """Lấy alert tiếp theo từ queue"""
        try:
            return self.alert_queue.get(timeout=timeout)
        except queue.Empty:
            return None


# Singleton instance
_ids_instance = None

def get_ids_instance(config_path: str = 'config.ini') -> IDSEngine:
    """Get singleton instance"""
    global _ids_instance
    if _ids_instance is None:
        _ids_instance = IDSEngine(config_path)
    return _ids_instance
