#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
1. Thu thập gói tin (sniff) theo giao diện cấu hình
2. Gom nhóm thành luồng (flow) và duy trì trạng thái FlowState
3. Tính đặc trưng gần giống NSL-KDD + đặc trưng bổ sung (tốc độ, is_https...)
4. Chạy qua pipeline tiền xử lý + mô hình ML/DL (tự động tải dựa metrics)
5. Áp dụng heuristics hậu xử lý để giảm false positive
6. Kết hợp nhiều detector chuyên biệt: SYN/UDP/ICMP Flood (global & distributed), Port Scan
7. Đẩy cảnh báo sang hàng đợi cho notifier + giao diện web

Thiết kế hot-reload: apply_config() cho phép cập nhật ngưỡng, cửa sổ, mô hình
không cần khởi động lại thread sniffing.
"""

import os
import time
import queue
import threading
import configparser
from collections import defaultdict, deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from detectors.port_scan import PortScanDetector

# Giảm log TF (nếu môi trường có cài TF)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from scapy.all import sniff, IP, TCP, UDP

# Internal modules
from logging_utils import setup_logging
from ids_utils import (
    TRUSTED_DOMAINS,
    proto_name,
    guess_service,
)
from flow_state import FlowState
from detectors.heuristics import (
    is_trusted_source as _h_is_trusted_source,
    post_process_alert as _h_post_process_alert,
    determine_attack_type as _h_determine_attack_type,
)
from detectors.floods import (
    SynFloodGlobalDetector,
    SynFloodDistributedDetector,
    UDPGlobalDetector,
    UDPDistributedDetector,
    ICMPGlobalDetector,
    ICMPDistributedDetector,
)
from detectors.packet_filter import PacketFilter
from model_runtime import load_model_and_preprocess, predict_probabilities
from ids.flow_classifier import FlowClassifier
from ids.alert_manager import AlertManager


class IDSEngine:
    def __init__(self, config_path: str = 'config.ini'):
        # Đọc cấu hình
        config = configparser.ConfigParser()
        config.read(config_path, encoding='utf-8')

    # -------- Cấu hình mạng / cửa sổ --------
        self.iface = config.get('Network', 'interface')
        self.window = config.getint('Network', 'window')
        self.min_pkts = config.getint('Network', 'min_packets')
        self.min_bytes = config.getint('Network', 'min_bytes')

    # IP cục bộ/máy chủ để phân biệt chiều lưu lượng (inbound/outbound)
        self.local_ips = set()
        try:
            server_ip = config.get('Network', 'server_ip', fallback='').strip()
            local_ips_str = config.get('Network', 'local_ips', fallback='').strip()
            if server_ip:
                self.local_ips.add(server_ip)
            if local_ips_str:
                for tok in local_ips_str.split(','):
                    tok = tok.strip()
                    if tok:
                        self.local_ips.add(tok)
        except Exception:
            pass

    # -------- Cấu hình mô hình --------
        self.model_path = config.get('Model', 'model_path')
        self.preprocess_path = config.get('Model', 'preprocess_path')
        self.alert_threshold = config.getfloat('Model', 'threshold')
        # Ngưỡng flood cho lab/production
        try:
            self.dos_packet_rate = config.getint('Model', 'dos_packet_rate', fallback=1000)
        except Exception:
            self.dos_packet_rate = 1000
        try:
            # Thời gian reset bộ đếm flood (giây) – mặc định 5 để cảnh báo nhanh hơn
            self.dos_reset_seconds = config.getint('Model', 'dos_reset_seconds', fallback=5)
        except Exception:
            self.dos_reset_seconds = 5

    # -------- Cấu hình lọc gói --------
        self.whitelist_file = config.get('Filtering', 'whitelist_file')
        self.blacklist_file = config.get('Filtering', 'blacklist_file')
        self.ignore_https = config.getboolean('Filtering', 'ignore_https', fallback=False)

    # Logger ghi file tấn công
        self.attack_logger = setup_logging()

    # Cờ trạng thái
        self.running = False
        self.sniff_thread = None
        self.predict_thread = None

    # Nạp whitelist / blacklist từ file
        self.whitelist = set()
        self.blacklist = set()
        if os.path.exists(self.whitelist_file):
            with open(self.whitelist_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.whitelist = set(line.strip() for line in f if line.strip())
        if os.path.exists(self.blacklist_file):
            with open(self.blacklist_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.blacklist = set(line.strip() for line in f if line.strip())
        # Bổ sung domain tin cậy
        self.whitelist.update(TRUSTED_DOMAINS)

    # Bản đồ lưu trạng thái từng luồng + lock bảo vệ
        self.flows = {}
        self.lock = threading.Lock()

    # Flow classifier module
        self.flow_classifier = FlowClassifier(config)
        self.flow_classifier.attack_logger = self.attack_logger

    # Bộ nhớ vòng để tính các chỉ số count/srv_count theo cửa sổ
        self.host_events = deque(maxlen=100000)

    # Thống kê phục vụ UI / giám sát
        self.stats = {
            "packets_processed": 0,
            "flows_analyzed": 0,
            "alerts_generated": 0,
            "start_time": None,
            "packets_per_second": 0,
            "last_update_time": time.time(),
            "bytes_processed": 0,
        }

    # Alert queue and manager (must be before PacketFilter and flood detectors)
        self.alert_queue = queue.Queue()
        self.alert_manager = AlertManager(self.alert_queue, self.attack_logger, self.stats)

    # Detector: quét cổng
        try:
            self.port_scan_threshold = config.getint('Filtering', 'port_scan_threshold', fallback=15)
        except Exception:
            self.port_scan_threshold = 15
        self.port_scan = PortScanDetector(threshold=self.port_scan_threshold)

    # Detector: SYN Flood (toàn cục + phân tán)
        self.syn_flood_global = SynFloodGlobalDetector(total_threshold=self.dos_packet_rate, reset_seconds=self.dos_reset_seconds)
        self.syn_flood_dist = SynFloodDistributedDetector()
    # Detector: UDP Flood
        self.udp_flood_global = UDPGlobalDetector(total_threshold=self.dos_packet_rate, reset_seconds=self.dos_reset_seconds)
        self.udp_flood_dist = UDPDistributedDetector()
    # Detector: ICMP Flood
        self.icmp_flood_global = ICMPGlobalDetector(total_threshold=self.dos_packet_rate, reset_seconds=self.dos_reset_seconds)
        self.icmp_flood_dist = ICMPDistributedDetector()

    # Packet filter (gom các logic lọc gói ra module riêng)
        self.packet_filter = PacketFilter(
            ignore_https=self.ignore_https,
            whitelist=self.whitelist,
            blacklist=self.blacklist,
            port_scan_detector=self.port_scan,
            attack_logger=self.attack_logger,
            alert_queue=self.alert_manager.alert_queue,
            recent_alerts=self.alert_manager.recent_alerts,
            stats=self.stats,
        )

    # Trạng thái mô hình / pipeline tiền xử lý
        self.model_type = None  # 'dl' hoặc 'ml'
        self.model = None       # Keras model hoặc sklearn estimator
        self.preprocess = None  # sklearn ColumnTransformer

    def _should_classify(self, flow_key, flow_data):
        """Delegate to flow_classifier module"""
        return self.flow_classifier.should_classify(flow_key, flow_data)

    # -------- Hot reload configuration (áp dụng thay đổi động) ---------
    def apply_config(self, live_cfg):
        """Update runtime parameters from LiveConfig without restarting threads."""
        try:
            # Cập nhật tham số cửa sổ / ngưỡng lọc tối thiểu
            self.window = live_cfg.getint('Network', 'window', fallback=self.window)
            self.min_pkts = live_cfg.getint('Network', 'min_packets', fallback=self.min_pkts)
            self.min_bytes = live_cfg.getint('Network', 'min_bytes', fallback=self.min_bytes)

            # Cập nhật ngưỡng cảnh báo & đường dẫn mô hình
            new_model_path = live_cfg.get('Model', 'model_path', fallback=self.model_path)
            new_pre_path = live_cfg.get('Model', 'preprocess_path', fallback=self.preprocess_path)
            self.alert_threshold = live_cfg.getfloat('Model', 'threshold', fallback=self.alert_threshold)

            # Nếu đổi file mô hình / preprocessing => tải lại
            if (new_model_path != self.model_path) or (new_pre_path != self.preprocess_path):
                self.model_path = new_model_path
                self.preprocess_path = new_pre_path
                self.load_model()

            # Cập nhật tham số lọc HTTPS động
            self.ignore_https = live_cfg.getboolean('Filtering', 'ignore_https', fallback=self.ignore_https)
            if hasattr(self, 'packet_filter'):
                self.packet_filter.ignore_https = self.ignore_https

            # Cập nhật ngưỡng flood động
            new_dos_pkt = live_cfg.getint('Model', 'dos_packet_rate', fallback=self.dos_packet_rate)
            new_dos_reset = live_cfg.getint('Model', 'dos_reset_seconds', fallback=self.dos_reset_seconds)
            if new_dos_pkt != self.dos_packet_rate or new_dos_reset != self.dos_reset_seconds:
                self.dos_packet_rate = new_dos_pkt
                self.dos_reset_seconds = new_dos_reset
                # áp dụng cho 3 detector global
                self.syn_flood_global.total_threshold = self.dos_packet_rate
                self.udp_flood_global.total_threshold = self.dos_packet_rate
                self.icmp_flood_global.total_threshold = self.dos_packet_rate
                self.syn_flood_global.reset_seconds = self.dos_reset_seconds
                self.udp_flood_global.reset_seconds = self.dos_reset_seconds
                self.icmp_flood_global.reset_seconds = self.dos_reset_seconds

            # Cập nhật ngưỡng quét cổng động nếu thay đổi
            new_ps_threshold = live_cfg.getint('Filtering', 'port_scan_threshold', fallback=self.port_scan_threshold)
            if new_ps_threshold != self.port_scan_threshold:
                self.port_scan_threshold = new_ps_threshold
                self.port_scan.threshold = new_ps_threshold

            # Update flow classifier parameters
            self.flow_classifier.small_flow_threshold = live_cfg.getint('Detection', 'small_flow_threshold', fallback=50)
            self.flow_classifier.small_flow_window = live_cfg.getint('Detection', 'small_flow_window', fallback=5)
            self.flow_classifier.global_flow_threshold = live_cfg.getint('Detection', 'global_flow_threshold', fallback=100)
        except Exception as e:
            print('[Config] Error:', e)

    def _is_local_ip(self, ip: str) -> bool:
        return ip in self.local_ips

    def load_model(self) -> bool:
        print("[*] Loading model...")
        try:
            self.preprocess, self.model, self.model_type, info = load_model_and_preprocess(
                self.preprocess_path, self.model_path
            )
            model_name = info.get('best_ml_name', 'DL') if self.model_type == 'ml' else 'DL'
            print(f"✅ Loaded {model_name} (threshold={self.alert_threshold})")
            return True
        except Exception as e:
            print(f"❌ Model load failed: {e}")
            return False

    def _predict_probabilities(self, X: np.ndarray) -> np.ndarray:
        return predict_probabilities(self.model, self.model_type, X)

    def _flow_key(self, pkt):
        sip, dip = pkt[IP].src, pkt[IP].dst
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        proto = proto_name(pkt)
        return (sip, sport, dip, dport, proto)

    def _direction_src_to_dst(self, pkt, key):
        sip, sport, dip, dport, _ = key
        ps, pd = None, None
        if pkt.haslayer(TCP):
            ps, pd = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            ps, pd = pkt[UDP].sport, pkt[UDP].dport
        return (pkt[IP].src == sip) and (ps == sport) and (pkt[IP].dst == dip) and (pd == dport)

    def _update_host_window(self, pkt):
        now = time.time()
        dip = pkt[IP].dst
        dport = (pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        self.host_events.append((now, dip, dport))

    def _build_host_counts(self):
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
        try:
            if not pkt.haslayer(IP):
                return

            # Thống kê cơ bản
            self.stats["packets_processed"] += 1
            self.stats["bytes_processed"] += len(pkt)
            
            now = time.time()
            if now - self.stats["last_update_time"] >= 1:
                if self.stats["start_time"]:
                    self.stats["packets_per_second"] = int(self.stats["packets_processed"] / (now - self.stats["start_time"]))
                self.stats["last_update_time"] = now

            # Flood detectors (toàn cục) – chạy trước để phát hiện sớm tấn công volumetric
            # SYN flood: chỉ xét SYN khởi tạo (SYN=1, ACK=0) để tránh tính cả SYN-ACK
            if pkt.haslayer(TCP):
                _flags = int(pkt[TCP].flags)
                _is_syn = (_flags & 0x02) != 0
                _is_ack = (_flags & 0x10) != 0
                if _is_syn and not _is_ack:
                    self.syn_flood_global.process(
                        pkt,
                        is_trusted_source_fn=self._is_trusted_source,
                        window_seconds=self.window,
                        attack_logger=self.attack_logger,
                        alert_queue=self.alert_manager.alert_queue,
                        recent_alerts=self.alert_manager.recent_alerts,
                        stats=self.stats,
                    )
            # UDP flood
            self.udp_flood_global.process(
                pkt,
                is_trusted_source_fn=self._is_trusted_source,
                window_seconds=self.window,
                attack_logger=self.attack_logger,
                alert_queue=self.alert_manager.alert_queue,
                recent_alerts=self.alert_manager.recent_alerts,
                stats=self.stats,
            )
            # ICMP flood
            self.icmp_flood_global.process(
                pkt,
                is_trusted_source_fn=self._is_trusted_source,
                window_seconds=self.window,
                attack_logger=self.attack_logger,
                alert_queue=self.alert_manager.alert_queue,
                recent_alerts=self.alert_manager.recent_alerts,
                stats=self.stats,
            )

            # Bước lọc gói trước khi cập nhật trạng thái luồng
            if not self.packet_filter.should_process(pkt):
                return

            # Cập nhật hoặc khởi tạo FlowState
            key = self._flow_key(pkt)
            with self.lock:
                is_new = key not in self.flows
                if is_new:
                    self.flows[key] = FlowState(proto_name(pkt), guess_service(pkt))
                state = self.flows[key]
                direction = self._direction_src_to_dst(pkt, key)
                state.update(pkt, direction)
                self._update_host_window(pkt)

        except Exception as e:
            if isinstance(e, (AttributeError, IndexError)) and ('sport' in str(e) or 'dport' in str(e)):
                pass
            else:
                print(f"CB error: {type(e).__name__}: {str(e)}")

    def _is_trusted_source(self, ip: str) -> bool:
        return _h_is_trusted_source(ip, getattr(self, 'local_ips', set()), self.whitelist)

    def _post_process_alert(self, key, prob, state) -> bool:
        return self.alert_manager.should_alert(key, prob, state, self.local_ips, self.window)

    def _predict_and_alert(self):
        while self.running:
            time.sleep(self.window)
            with self.lock:
                if not self.flows:
                    continue

                # Lọc các luồng chưa đủ số gói / bytes tối thiểu
                filtered_flows = {}
                
                # 🔥 NEW: Track flows per destination (for --rand-source detection)
                dst_flow_tracker = defaultdict(list)  # {(dip, dport, proto): [flow_keys]}
                
                for k, state in list(self.flows.items()):
                    sip, sport, dip, dport, proto = k
                    total_pkts = state.pkt_src + state.pkt_dst
                    total_bytes = state.src_bytes + state.dst_bytes
                    
                    # Chỉ bỏ qua LOCAL server response (cả SIP và DIP đều local)
                    if self._is_local_ip(sip) and self._is_local_ip(dip) and sport < 1024:
                        continue
                    
                    # Track flows targeting same destination
                    if not self._is_local_ip(sip) and self._is_local_ip(dip):
                        dst_key = (dip, dport, proto)
                        dst_flow_tracker[dst_key].append(k)
                    
                    # Sử dụng logic thông minh: classify cả flow lớn VÀ flow nhỏ từ IP nghi ngờ
                    flow_data = {
                        'packet_count': total_pkts,
                        'total_bytes': total_bytes
                    }
                    if self._should_classify(k, flow_data):
                        filtered_flows[k] = state
                
                # 🔥 Check if destination is under attack (many sources → one target)
                for dst_key, flow_keys in dst_flow_tracker.items():
                    if len(flow_keys) > self.flow_classifier.global_flow_threshold:
                        # Add all flows to classification queue (DDoS/spoofed-IP)
                        for fk in flow_keys:
                            if fk not in filtered_flows and fk in self.flows:
                                filtered_flows[fk] = self.flows[fk]
                
                # Flow classification complete

                if not filtered_flows:
                    self.flows.clear()
                    continue

                self.stats["flows_analyzed"] += len(filtered_flows)

                # Chạy flood detector phân tán trên tập luồng đã đủ điều kiện
                self.syn_flood_dist.process_aggregated(
                    filtered_flows,
                    is_local_ip_fn=self._is_local_ip,
                    window_seconds=self.window,
                    attack_logger=self.attack_logger,
                    alert_queue=self.alert_manager.alert_queue,
                    recent_alerts=self.alert_manager.recent_alerts,
                    stats=self.stats,
                )
                self.udp_flood_dist.process_aggregated(
                    filtered_flows,
                    is_local_ip_fn=self._is_local_ip,
                    window_seconds=self.window,
                    attack_logger=self.attack_logger,
                    alert_queue=self.alert_manager.alert_queue,
                    recent_alerts=self.alert_manager.recent_alerts,
                    stats=self.stats,
                )
                self.icmp_flood_dist.process_aggregated(
                    filtered_flows,
                    is_local_ip_fn=self._is_local_ip,
                    window_seconds=self.window,
                    attack_logger=self.attack_logger,
                    alert_queue=self.alert_manager.alert_queue,
                    recent_alerts=self.alert_manager.recent_alerts,
                    stats=self.stats,
                )

                # Chuyển FlowState -> vector đặc trưng
                host_counts = self._build_host_counts()
                rows, keys, states = [], [], []
                for k, st in list(filtered_flows.items()):
                    rows.append(st.to_feature_row(k, host_counts))
                    keys.append(k)
                    states.append(st)

                if not rows:
                    self.flows.clear()
                    continue

                df = pd.DataFrame(rows)
                for col in ["duration","src_bytes","dst_bytes","count","srv_count","dst_host_count","dst_host_srv_count"]:
                    if col not in df:
                        df[col] = 0.0
                
                # 🆕 Drop new features nếu model chưa được retrain
                # Model hiện tại chỉ biết 41 features gốc
                new_features = ['rej_rate', 'syn_ratio', 'syn_ack_ratio', 
                               'packet_imbalance', 'byte_imbalance', 'small_packet_ratio']
                for feat in new_features:
                    if feat in df.columns:
                        df = df.drop(columns=[feat])

                X = self.preprocess.transform(df)
                probs = self._predict_probabilities(X).ravel()
                preds = (probs >= self.alert_threshold).astype(int)

                # Generate alerts for flows exceeding threshold
                alert_count = 0

                # Apply confidence boosting and rule-based fallback
                boosted_probs = self.flow_classifier.boost_probabilities(keys, probs, states, self.min_pkts)
                probs = np.array(boosted_probs)
                preds = (probs >= self.alert_threshold).astype(int)
                preds = self.flow_classifier.apply_rule_based_fallback(keys, probs, states, preds, self.min_pkts)

                
                # Generate alerts using AlertManager (group by attack type)
                attack_summary = {}  # {(dst, proto, attack_type): [flows]}
                
                for k, p, pr, st in zip(keys, preds, probs, states):
                    if p == 1 and self._post_process_alert(k, pr, st):
                        sip, sport, dip, dport, proto = k
                        attack_type = self._determine_attack_type(k, st)
                        
                        # Group attacks by destination + protocol + type
                        attack_key = (dip, dport, proto, attack_type)
                        if attack_key not in attack_summary:
                            attack_summary[attack_key] = []
                        attack_summary[attack_key].append((k, pr, st))
                
                # Generate one alert per attack group
                for attack_key, flows in attack_summary.items():
                    dip, dport, proto, attack_type = attack_key
                    
                    # Pick representative flow (highest probability)
                    flows.sort(key=lambda x: x[1], reverse=True)
                    best_flow = flows[0]
                    k, pr, st = best_flow
                    
                    # Generate grouped alert with flow count
                    if self.alert_manager.generate_alert(k, pr, st, attack_type, self.local_ips, flow_count=len(flows)):
                        alert_count += 1

                if alert_count > 0:
                    print(f"[*] Generated {alert_count} attack alerts this window")

                # Reset toàn bộ state để chuẩn bị cửa sổ kế tiếp
                self.flows.clear()

    def _determine_attack_type(self, key, state) -> str:
        return _h_determine_attack_type(key, state)

    def start(self) -> bool:
        if self.running:
            return False
        
        if not hasattr(self, 'model') or self.model is None:
            if not self.load_model():
                return False

        self.running = True
        self.stats["start_time"] = time.time()

        self.predict_thread = threading.Thread(target=self._predict_and_alert, daemon=True)
        self.predict_thread.start()

        def start_sniffing():
            ifaces = [i.strip() for i in str(self.iface).split(',') if i.strip()]
            iface_arg = ifaces if len(ifaces) > 1 else (ifaces[0] if ifaces else None)
            sniff(iface=iface_arg, prn=self._packet_cb, store=False, stop_filter=lambda x: not self.running)

        self.sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniff_thread.start()

        print(f"[*] IDS started: {self.iface}, window={self.window}s, threshold={self.alert_threshold}")
        return True

    def stop(self):
        if not self.running:
            return
        self.running = False
        if self.predict_thread and self.predict_thread.is_alive():
            self.predict_thread.join(timeout=2)
        print("[*] IDS stopped")

    def get_stats(self):
        stats = self.stats.copy()
        if stats["start_time"]:
            stats["uptime"] = time.time() - stats["start_time"]
        else:
            stats["uptime"] = 0
        return stats

    def get_recent_alerts(self):
        return self.alert_manager.get_recent_alerts()

    def get_next_alert(self, timeout: float = 0.1):
        try:
            return self.alert_manager.alert_queue.get(timeout=timeout)
        except queue.Empty:
            return None


# Singleton instance
_ids_instance = None

def get_ids_instance(config_path: str = 'config.ini') -> IDSEngine:
    global _ids_instance
    if _ids_instance is None:
        _ids_instance = IDSEngine(config_path)
    return _ids_instance