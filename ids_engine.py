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

    # Hàng đợi chuyển tiếp cảnh báo ra ngoài
        self.alert_queue = queue.Queue()

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

    # Bộ nhớ vòng để tính các chỉ số count/srv_count theo cửa sổ
        self.host_events = deque(maxlen=100000)

    # Lưu lịch sử cảnh báo (giảm lặp lại ngắn hạn)
        self.previous_alerts = {}

    # Detector: quét cổng (theo dõi SYN trên nhiều cổng) – đọc ngưỡng từ config nếu có
        try:
            self.port_scan_threshold = config.getint('Filtering', 'port_scan_threshold', fallback=15)
        except Exception:
            self.port_scan_threshold = 15
        self.port_scan = PortScanDetector(threshold=self.port_scan_threshold)

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

    # Detector: SYN Flood (toàn cục + phân tán)
        self.syn_flood_global = SynFloodGlobalDetector(total_threshold=self.dos_packet_rate, reset_seconds=self.dos_reset_seconds)
        self.syn_flood_dist = SynFloodDistributedDetector()
    # Detector: UDP Flood
        self.udp_flood_global = UDPGlobalDetector(total_threshold=self.dos_packet_rate, reset_seconds=self.dos_reset_seconds)
        self.udp_flood_dist = UDPDistributedDetector()
    # Detector: ICMP Flood
        self.icmp_flood_global = ICMPGlobalDetector(total_threshold=self.dos_packet_rate, reset_seconds=self.dos_reset_seconds)
        self.icmp_flood_dist = ICMPDistributedDetector()

    # Danh sách cảnh báo gần đây cho dashboard
        self.recent_alerts = deque(maxlen=100)

    # Packet filter (gom các logic lọc gói ra module riêng)
        self.packet_filter = PacketFilter(
            ignore_https=self.ignore_https,
            whitelist=self.whitelist,
            blacklist=self.blacklist,
            port_scan_detector=self.port_scan,
            attack_logger=self.attack_logger,
            alert_queue=self.alert_queue,
            recent_alerts=self.recent_alerts,
            stats=self.stats,
        )

    # Trạng thái mô hình / pipeline tiền xử lý
        self.model_type = None  # 'dl' hoặc 'ml'
        self.model = None       # Keras model hoặc sklearn estimator
        self.preprocess = None  # sklearn ColumnTransformer

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
                print('[Config] Model path changed → reloading model...')
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
                print(f"[Config] Flood thresholds updated → packets={self.dos_packet_rate}/reset={self.dos_reset_seconds}s")

            # Cập nhật ngưỡng quét cổng động nếu thay đổi
            new_ps_threshold = live_cfg.getint('Filtering', 'port_scan_threshold', fallback=self.port_scan_threshold)
            if new_ps_threshold != self.port_scan_threshold:
                self.port_scan_threshold = new_ps_threshold
                self.port_scan.threshold = new_ps_threshold
                print(f"[Config] Port scan threshold updated → {new_ps_threshold}")

            print(f"[Config] IDS updated: window={self.window} min_pkts={self.min_pkts} min_bytes={self.min_bytes} threshold={self.alert_threshold} port_scan_threshold={self.port_scan_threshold} dos_packet_rate={self.dos_packet_rate} dos_reset_seconds={self.dos_reset_seconds}")
        except Exception as e:
            print('[Config] IDS apply_config error:', e)

    def _is_local_ip(self, ip: str) -> bool:
        return ip in self.local_ips

    def load_model(self) -> bool:
        print("[*] Đang tải mô hình & pipeline tiền xử lý...")
        try:
            self.preprocess, self.model, self.model_type, info = load_model_and_preprocess(
                self.preprocess_path, self.model_path
            )
            path = info.get('path')
            if self.model_type == 'ml':
                print(f"[+] Đã tải mô hình ML từ {path} (best: {info.get('best_ml_name')})")
            else:
                print(f"[+] Đã tải mô hình DL từ {path}")
            
            # 🔍 DEBUG: Verify model loaded
            print(f"🤖 Model type: {type(self.model).__name__}")
            print(f"🔧 Preprocess type: {type(self.preprocess).__name__}")
            print(f"🎯 Alert threshold: {self.alert_threshold}")
            if self.model is None:
                print("❌ WARNING: MODEL IS NONE!")
            if self.preprocess is None:
                print("❌ WARNING: PREPROCESS IS NONE!")
            
            return True
        except Exception as e:
            print(f"[!] Lỗi tải mô hình: {e}")
            import traceback
            traceback.print_exc()
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
                        alert_queue=self.alert_queue,
                        recent_alerts=self.recent_alerts,
                        stats=self.stats,
                    )
            # UDP flood
            self.udp_flood_global.process(
                pkt,
                is_trusted_source_fn=self._is_trusted_source,
                window_seconds=self.window,
                attack_logger=self.attack_logger,
                alert_queue=self.alert_queue,
                recent_alerts=self.recent_alerts,
                stats=self.stats,
            )
            # ICMP flood
            self.icmp_flood_global.process(
                pkt,
                is_trusted_source_fn=self._is_trusted_source,
                window_seconds=self.window,
                attack_logger=self.attack_logger,
                alert_queue=self.alert_queue,
                recent_alerts=self.recent_alerts,
                stats=self.stats,
            )

            # Bước lọc gói trước khi cập nhật trạng thái luồng
            if not self.packet_filter.should_process(pkt):
                return

            # Cập nhật hoặc khởi tạo FlowState
            key = self._flow_key(pkt)
            with self.lock:
                if key not in self.flows:
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
        return _h_post_process_alert(key, prob, state, self.previous_alerts, self.window)

    def _predict_and_alert(self):
        while self.running:
            time.sleep(self.window)
            with self.lock:
                if not self.flows:
                    continue

                # 🔍 DEBUG: Đếm flows trước khi lọc
                total_flows = len(self.flows)
                filtered_count = 0

                # Lọc các luồng chưa đủ số gói / bytes tối thiểu
                filtered_flows = {}
                for k, state in list(self.flows.items()):
                    sip, sport, dip, dport, proto = k
                    total_pkts = state.pkt_src + state.pkt_dst
                    total_bytes = state.src_bytes + state.dst_bytes
                    
                    # Bỏ qua flows từ local_ips với port < 1024 (server response traffic)
                    if self._is_local_ip(sip) and sport < 1024:
                        filtered_count += 1
                        continue
                    
                    if total_pkts >= self.min_pkts and total_bytes >= self.min_bytes:
                        filtered_flows[k] = state
                    else:
                        filtered_count += 1

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
                    alert_queue=self.alert_queue,
                    recent_alerts=self.recent_alerts,
                    stats=self.stats,
                )
                self.udp_flood_dist.process_aggregated(
                    filtered_flows,
                    is_local_ip_fn=self._is_local_ip,
                    window_seconds=self.window,
                    attack_logger=self.attack_logger,
                    alert_queue=self.alert_queue,
                    recent_alerts=self.recent_alerts,
                    stats=self.stats,
                )
                self.icmp_flood_dist.process_aggregated(
                    filtered_flows,
                    is_local_ip_fn=self._is_local_ip,
                    window_seconds=self.window,
                    attack_logger=self.attack_logger,
                    alert_queue=self.alert_queue,
                    recent_alerts=self.recent_alerts,
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

                X = self.preprocess.transform(df)
                probs = self._predict_probabilities(X).ravel()
                preds = (probs >= self.alert_threshold).astype(int)

                # Generate alerts for flows exceeding threshold
                alert_count = 0

                # Phát cảnh báo (nếu vượt ngưỡng + qua hậu xử lý)
                for k, p, pr, st in zip(keys, preds, probs, states):
                    # Post-processing enabled (filters obvious false positives)
                    should_alert = self._post_process_alert(k, pr, st)
                    
                    if p == 1 and should_alert:
                        alert_count += 1
                        sip, sport, dip, dport, proto = k
                        attack_type = self._determine_attack_type(k, st)
                        # Thêm context: pkts, flags, prob để debug
                        total_pkts = st.pkt_src + st.pkt_dst
                        flags_str = ",".join([f"{flag}:{count}" for flag, count in st.flag_counts.items() if count > 0])
                        alert_msg = f"ALERT {attack_type} proto={proto} {sip}:{sport} -> {dip}:{dport} [pkts={total_pkts} prob={pr:.3f} flags={flags_str}]"
                        # Dùng giờ hệ thống địa phương, bỏ hậu tố Z (UTC)
                        now_str_local = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        print(f"[{now_str_local}] {alert_msg}")
                        self.attack_logger.info(alert_msg)

                        alert_data = {
                            "type": attack_type.lower(),
                            "detail_type": attack_type,
                            "src_ip": sip,
                            "src_port": sport,
                            "dst_ip": dip,
                            "dst_port": dport,
                            "proto": proto,
                            "probability": float(pr),
                            "time": now_str_local,
                            "message": alert_msg,
                            "bytes_src": st.src_bytes,
                            "bytes_dst": st.dst_bytes,
                            "rate_src": st.rate_src,
                            "rate_dst": st.rate_dst,
                            "duration": st.last_ts - st.first_ts,
                            "pkt_src": st.pkt_src,
                            "pkt_dst": st.pkt_dst,
                        }
                        self.alert_queue.put(alert_data)
                        self.recent_alerts.append(alert_data)
                        self.stats["alerts_generated"] += 1

                # Log summary if alerts were generated
                if alert_count > 0:
                    print(f"[*] Generated {alert_count} ML-based alerts this window")

                # Reset toàn bộ state để chuẩn bị cửa sổ kế tiếp
                self.flows.clear()

    def _determine_attack_type(self, key, state) -> str:
        return _h_determine_attack_type(key, state)

    def start(self) -> bool:
        if self.running:
            return False
        if not hasattr(self, 'model') or not hasattr(self, 'preprocess') or self.model is None or self.preprocess is None:
            if not self.load_model():
                return False

        self.running = True
        self.stats["start_time"] = time.time()

        self.predict_thread = threading.Thread(target=self._predict_and_alert, daemon=True)
        self.predict_thread.start()

        def start_sniffing():
            # Hỗ trợ nhiều interface: ví dụ "ens33,ens37"
            ifaces = [i.strip() for i in str(self.iface).split(',') if i.strip()]
            iface_arg = ifaces if len(ifaces) > 1 else (ifaces[0] if ifaces else None)
            print(f"[*] Sniffing on {iface_arg}...")
            sniff(iface=iface_arg, prn=self._packet_cb, store=False, stop_filter=lambda x: not self.running)

        self.sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
        self.sniff_thread.start()

        print(f"[*] IDS started on {self.iface} with window={self.window}s, threshold={self.alert_threshold}")
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
        return list(self.recent_alerts)

    def get_next_alert(self, timeout: float = 0.1):
        try:
            return self.alert_queue.get(timeout=timeout)
        except queue.Empty:
            return None


# Singleton instance
_ids_instance = None

def get_ids_instance(config_path: str = 'config.ini') -> IDSEngine:
    global _ids_instance
    if _ids_instance is None:
        _ids_instance = IDSEngine(config_path)
    return _ids_instance