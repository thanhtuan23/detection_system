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

        # Chỉ xét gói SYN
        if pkt[TCP].flags & 0x02:
            if src_ip not in self.window:
                self.window[src_ip] = defaultdict(int)
            self.window[src_ip][dst_port] += 1

            if len(self.window[src_ip]) > self.threshold:
                port_list = list(self.window[src_ip].keys())
                alert_msg = f"PORT SCAN DETECTED from {src_ip} to {dst_ip} (ports: {port_list[:5]}...)"
                now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
                print(f"[{now_str}] {alert_msg}")
                attack_logger.info(alert_msg)

                alert_data = {
                    "type": "port_scan",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ports": port_list[:10],
                    "time": now_str,
                    "message": alert_msg
                }
                alert_queue.put(alert_data)
                recent_alerts.append(alert_data)
                stats["alerts_generated"] += 1

                # reset cho nguồn này để tránh spam liên tục
                self.window[src_ip] = {}
                return True
        return False
