import time
from collections import defaultdict
from datetime import datetime, timezone

GOOGLE_PREFIXES = ['74.125.', '142.250.', '64.233.', '216.58.', '172.217.']
CLOUDFLARE_PREFIXES = ['104.18.', '104.19.', '104.20.', '172.65.', '146.75.']

class PortScanDetector:
    """Phát hiện quét cổng dựa trên số lượng cổng khác nhau mà một nguồn SYN tới.

    - Mỗi nguồn (src_ip) có một dict đếm cổng
    - Vượt quá threshold số cổng duy nhất trong cửa sổ 60s => Cảnh báo
    """
    def __init__(self, threshold: int = 15):
        # window structure: { src_ip: { dst_ip: set(dport) } }
        self.window = {}
        self.last_clean = time.time()
        self.threshold = threshold

    def process(self, pkt, attack_logger, alert_queue, recent_alerts, stats) -> bool:
        from scapy.all import IP, TCP

        if not pkt.haslayer(TCP):
            return False

        now = time.time()
        # Dọn bộ nhớ mỗi 60s để tránh phình to
        if now - self.last_clean > 60:
            self.window = {}
            self.last_clean = now

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport

        # Bỏ qua một số prefix phổ biến (dịch vụ hợp lệ)
        for prefix in GOOGLE_PREFIXES + CLOUDFLARE_PREFIXES:
            if src_ip.startswith(prefix):
                return False

        # Chỉ xét SYN khởi tạo (SYN=1 và ACK=0) để tránh nhầm SYN-ACK là nguồn quét
        flags = int(pkt[TCP].flags)
        is_syn = (flags & 0x02) != 0
        is_ack = (flags & 0x10) != 0
        if is_syn and not is_ack:
            if src_ip not in self.window:
                self.window[src_ip] = {}
            if dst_ip not in self.window[src_ip]:
                self.window[src_ip][dst_ip] = set()
            self.window[src_ip][dst_ip].add(int(dst_port))

            unique_ports = len(self.window[src_ip][dst_ip])
            if unique_ports >= self.threshold:
                ports_sorted = sorted(list(self.window[src_ip][dst_ip]))
                preview = f"[{', '.join(map(str, ports_sorted[:5]))}]..."
                alert_msg = f"PORT SCAN DETECTED proto=TCP from {src_ip} to {dst_ip} (ports: {preview})"
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                print(f"[{now_str}] {alert_msg}")
                attack_logger.info(alert_msg)

                alert_data = {
                    "type": "port_scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": "TCP",
                    "ports": ports_sorted[:10],
                    "time": now_str,
                    "message": alert_msg
                }
                alert_queue.put(alert_data)
                recent_alerts.append(alert_data)
                stats["alerts_generated"] += 1

                # reset cho cặp nguồn-đích này để tránh spam liên tục
                self.window[src_ip][dst_ip] = set()
                return True
        return False
