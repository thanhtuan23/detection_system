import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Tuple

# ----------------------------- SYN FLOOD -----------------------------
class SynFloodGlobalDetector:
    """Detector SYN flood cấp độ toàn cục (aggregate nhanh theo cửa sổ ngắn).

    Ý tưởng: đếm tổng số gói TCP có cờ SYN trong khoảng reset_seconds.
    Khi vượt ngưỡng total_threshold và một nguồn chiếm tỷ lệ lớn ⇒ cảnh báo.
    """
    def __init__(self, total_threshold: int = 1000, reset_seconds: int = 10):
        self.total_threshold = total_threshold
        self.reset_seconds = reset_seconds
        self.last_reset = time.time()
        self.sources: Dict[str, int] = defaultdict(int)
        self.targets: Dict[str, int] = defaultdict(int)
        self.total_syns = 0

    def process(self, pkt, is_trusted_source_fn, window_seconds: int, attack_logger, alert_queue, recent_alerts, stats) -> bool:
        try:
            from scapy.all import IP, TCP
        except Exception:
            return False
        now = time.time()
        if now - self.last_reset > self.reset_seconds:
            self.last_reset = now
            self.sources.clear()
            self.targets.clear()
            self.total_syns = 0
        if not pkt.haslayer(TCP) or not (pkt[TCP].flags & 0x02):
            return False
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if is_trusted_source_fn and is_trusted_source_fn(src_ip):
            return False
        self.sources[src_ip] += 1
        self.targets[dst_ip] += 1
        self.total_syns += 1
        if self.total_syns > self.total_threshold:
            main_source = max(self.sources.items(), key=lambda x: x[1])
            main_target = max(self.targets.items(), key=lambda x: x[1])
            if main_source[1] >= self.total_syns * 0.25:
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                # Rút gọn log: bỏ 'prob=1.000 window=..s'
                alert_msg = f"ALERT SYN_Flood proto=tcp {main_source[0]}:* -> {main_target[0]}:*"
                print(f"[{now_str}] {alert_msg}")
                attack_logger.info(alert_msg)
                alert_data = {
                    "type": "syn_flood",
                    "src_ip": main_source[0],
                    "src_port": "*",
                    "dst_ip": main_target[0],
                    "dst_port": "*",
                    "proto": "tcp",
                    "probability": 1.0,
                    "time": now_str,
                    "message": alert_msg,
                    "syn_count": main_source[1],
                    "total_syns": self.total_syns,
                }
                alert_queue.put(alert_data)
                recent_alerts.append(alert_data)
                stats["alerts_generated"] += 1
                self.total_syns = 0
                return True
        return False

class SynFloodDistributedDetector:
    """Detector SYN flood phân tán dựa trên tập luồng đã xây dựng.

    Tập trung vào các luồng có flag "S0" (kết nối nửa mở) xuất hiện nhiều từ
    cùng một nguồn đến nhiều đích / cổng khác nhau.
    """
    def process_aggregated(self, filtered_flows: Dict[Tuple[str,int,str,int,str], object], is_local_ip_fn, window_seconds: int, attack_logger, alert_queue, recent_alerts, stats) -> None:
        source_ip_pkts: Dict[str, int] = defaultdict(int)
        candidates: Dict[str, list] = defaultdict(list)  # src_ip -> list[(key, state)]
        for k, state in filtered_flows.items():
            sip, sport, dip, dport, proto = k
            source_ip_pkts[sip] += state.pkt_src + state.pkt_dst
            if proto == "tcp" and "S0" in state.flag_counts:
                candidates[sip].append((k, state))
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
        for src_ip, items in candidates.items():
            if is_local_ip_fn and is_local_ip_fn(src_ip):
                continue
            if len(items) >= 3 or source_ip_pkts[src_ip] > 50:
                targets = set(k[2] for k, _ in items)
                ports = set(k[3] for k, _ in items)
                if len(targets) >= 2 or len(ports) >= 5:
                    target_str = ", ".join(list(targets)[:3])
                    if len(targets) > 3:
                        target_str += f" và {len(targets)-3} IP khác"
                    alert_msg = f"ALERT SYN_Flood proto=tcp {src_ip}:* -> [{target_str}]:*"
                    print(f"[{now_str}] {alert_msg}")
                    attack_logger.info(alert_msg)
                    alert_data = {
                        "type": "syn_flood",
                        "src_ip": src_ip,
                        "src_port": "*",
                        "dst_ip": target_str,
                        "dst_port": "*",
                        "proto": "tcp",
                        "probability": 1.0,
                        "time": now_str,
                        "message": alert_msg,
                        "bytes_src": sum(st.src_bytes for _, st in items),
                        "bytes_dst": sum(st.dst_bytes for _, st in items),
                        "rate_src": sum(st.rate_src for _, st in items),
                        "rate_dst": sum(st.rate_dst for _, st in items),
                        "duration": window_seconds,
                        "flow_count": len(items),
                        "total_pkts": sum(st.pkt_src + st.pkt_dst for _, st in items),
                    }
                    alert_queue.put(alert_data)
                    recent_alerts.append(alert_data)
                    stats["alerts_generated"] += 1

# ----------------------------- UDP FLOOD -----------------------------
class UDPGlobalDetector:
    """Detector UDP flood toàn cục: đếm toàn bộ gói UDP trong khoảng reset_seconds."""
    def __init__(self, total_threshold: int = 1500, reset_seconds: int = 10):
        self.total_threshold = total_threshold
        self.reset_seconds = reset_seconds
        self.last_reset = time.time()
        self.sources: Dict[str, int] = defaultdict(int)
        self.targets: Dict[str, int] = defaultdict(int)
        self.total_udp = 0

    def process(self, pkt, is_trusted_source_fn, window_seconds: int, attack_logger, alert_queue, recent_alerts, stats) -> bool:
        try:
            from scapy.all import IP, UDP
        except Exception:
            return False
        now = time.time()
        if now - self.last_reset > self.reset_seconds:
            self.last_reset = now
            self.sources.clear()
            self.targets.clear()
            self.total_udp = 0
        if not pkt.haslayer(UDP):
            return False
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if is_trusted_source_fn and is_trusted_source_fn(src_ip):
            return False
        self.sources[src_ip] += 1
        self.targets[dst_ip] += 1
        self.total_udp += 1
        if self.total_udp > self.total_threshold:
            main_source = max(self.sources.items(), key=lambda x: x[1])
            main_target = max(self.targets.items(), key=lambda x: x[1])
            if main_source[1] >= self.total_udp * 0.25:
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                alert_msg = f"ALERT UDP_Flood proto=udp {main_source[0]}:* -> {main_target[0]}:*"
                print(f"[{now_str}] {alert_msg}")
                attack_logger.info(alert_msg)
                alert_data = {
                    "type": "udp_flood",
                    "src_ip": main_source[0],
                    "src_port": "*",
                    "dst_ip": main_target[0],
                    "dst_port": "*",
                    "proto": "udp",
                    "probability": 1.0,
                    "time": now_str,
                    "message": alert_msg,
                    "udp_from_source": main_source[1],
                    "udp_total": self.total_udp,
                }
                alert_queue.put(alert_data)
                recent_alerts.append(alert_data)
                stats["alerts_generated"] += 1
                self.total_udp = 0
                return True
        return False

class UDPDistributedDetector:
    """Detector UDP flood phân tán trên tập luồng: kiểm tra một nguồn gửi tới nhiều đích/cổng."""
    def process_aggregated(self, filtered_flows: Dict[Tuple[str,int,str,int,str], object], is_local_ip_fn, window_seconds: int, attack_logger, alert_queue, recent_alerts, stats) -> None:
        source_ip_pkts: Dict[str, int] = defaultdict(int)
        candidates: Dict[str, list] = defaultdict(list)
        for k, state in filtered_flows.items():
            sip, sport, dip, dport, proto = k
            if proto != "udp":
                continue
            source_ip_pkts[sip] += state.pkt_src + state.pkt_dst
            candidates[sip].append((k, state))
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
        for src_ip, items in candidates.items():
            if is_local_ip_fn and is_local_ip_fn(src_ip):
                continue
            if len(items) >= 3 or source_ip_pkts[src_ip] > 200:
                targets = set(k[2] for k, _ in items)
                ports = set(k[3] for k, _ in items)
                if len(targets) >= 2 or len(ports) >= 5:
                    target_str = ", ".join(list(targets)[:3])
                    if len(targets) > 3:
                        target_str += f" và {len(targets)-3} IP khác"
                    alert_msg = f"ALERT UDP_Flood proto=udp {src_ip}:* -> [{target_str}]:*"
                    print(f"[{now_str}] {alert_msg}")
                    attack_logger.info(alert_msg)
                    alert_data = {
                        "type": "udp_flood",
                        "src_ip": src_ip,
                        "src_port": "*",
                        "dst_ip": target_str,
                        "dst_port": "*",
                        "proto": "udp",
                        "probability": 1.0,
                        "time": now_str,
                        "message": alert_msg,
                        "bytes_src": sum(st.src_bytes for _, st in items),
                        "bytes_dst": sum(st.dst_bytes for _, st in items),
                        "rate_src": sum(st.rate_src for _, st in items),
                        "rate_dst": sum(st.rate_dst for _, st in items),
                        "duration": window_seconds,
                        "flow_count": len(items),
                        "total_pkts": sum(st.pkt_src + st.pkt_dst for _, st in items),
                    }
                    alert_queue.put(alert_data)
                    recent_alerts.append(alert_data)
                    stats["alerts_generated"] += 1

# ----------------------------- ICMP FLOOD -----------------------------
class ICMPGlobalDetector:
    """Detector ICMP (ping) flood toàn cục: đếm tổng số gói ICMP và tìm nguồn vượt trội."""
    def __init__(self, total_threshold: int = 1200, reset_seconds: int = 10):
        self.total_threshold = total_threshold
        self.reset_seconds = reset_seconds
        self.last_reset = time.time()
        self.sources: Dict[str, int] = defaultdict(int)
        self.targets: Dict[str, int] = defaultdict(int)
        self.total_icmp = 0

    def process(self, pkt, is_trusted_source_fn, window_seconds: int, attack_logger, alert_queue, recent_alerts, stats) -> bool:
        try:
            from scapy.all import IP, ICMP
        except Exception:
            return False
        now = time.time()
        if now - self.last_reset > self.reset_seconds:
            self.last_reset = now
            self.sources.clear()
            self.targets.clear()
            self.total_icmp = 0
        if not pkt.haslayer(ICMP):
            return False
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        if is_trusted_source_fn and is_trusted_source_fn(src_ip):
            return False
        self.sources[src_ip] += 1
        self.targets[dst_ip] += 1
        self.total_icmp += 1
        if self.total_icmp > self.total_threshold:
            main_source = max(self.sources.items(), key=lambda x: x[1])
            main_target = max(self.targets.items(), key=lambda x: x[1])
            if main_source[1] >= self.total_icmp * 0.25:
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                alert_msg = f"ALERT ICMP_Flood proto=icmp {main_source[0]}:* -> {main_target[0]}:*"
                print(f"[{now_str}] {alert_msg}")
                attack_logger.info(alert_msg)
                alert_data = {
                    "type": "icmp_flood",
                    "src_ip": main_source[0],
                    "src_port": "*",
                    "dst_ip": main_target[0],
                    "dst_port": "*",
                    "proto": "icmp",
                    "probability": 1.0,
                    "time": now_str,
                    "message": alert_msg,
                    "icmp_from_source": main_source[1],
                    "icmp_total": self.total_icmp,
                }
                alert_queue.put(alert_data)
                recent_alerts.append(alert_data)
                stats["alerts_generated"] += 1
                self.total_icmp = 0
                return True
        return False

class ICMPDistributedDetector:
    """Detector ICMP flood phân tán: nguồn gửi ICMP tới nhiều đích khác nhau trong cùng cửa sổ."""
    def process_aggregated(self, filtered_flows: Dict[Tuple[str,int,str,int,str], object], is_local_ip_fn, window_seconds: int, attack_logger, alert_queue, recent_alerts, stats) -> None:
        source_ip_pkts: Dict[str, int] = defaultdict(int)
        candidates: Dict[str, list] = defaultdict(list)
        for k, state in filtered_flows.items():
            sip, sport, dip, dport, proto = k
            if proto != "icmp":
                continue
            source_ip_pkts[sip] += state.pkt_src + state.pkt_dst
            candidates[sip].append((k, state))
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
        for src_ip, items in candidates.items():
            if is_local_ip_fn and is_local_ip_fn(src_ip):
                continue
            if len(items) >= 3 or source_ip_pkts[src_ip] > 200:
                targets = set(k[2] for k, _ in items)
                if len(targets) >= 2:
                    target_str = ", ".join(list(targets)[:3])
                    if len(targets) > 3:
                        target_str += f" và {len(targets)-3} IP khác"
                    alert_msg = f"ALERT ICMP_Flood proto=icmp {src_ip}:* -> [{target_str}]:*"
                    print(f"[{now_str}] {alert_msg}")
                    attack_logger.info(alert_msg)
                    alert_data = {
                        "type": "icmp_flood",
                        "src_ip": src_ip,
                        "src_port": "*",
                        "dst_ip": target_str,
                        "dst_port": "*",
                        "proto": "icmp",
                        "probability": 1.0,
                        "time": now_str,
                        "message": alert_msg,
                        "bytes_src": sum(st.src_bytes for _, st in items),
                        "bytes_dst": sum(st.dst_bytes for _, st in items),
                        "rate_src": sum(st.rate_src for _, st in items),
                        "rate_dst": sum(st.rate_dst for _, st in items),
                        "duration": window_seconds,
                        "flow_count": len(items),
                        "total_pkts": sum(st.pkt_src + st.pkt_dst for _, st in items),
                    }
                    alert_queue.put(alert_data)
                    recent_alerts.append(alert_data)
                    stats["alerts_generated"] += 1
