from datetime import datetime, timezone
from scapy.all import IP, TCP, UDP
from ids_utils import is_private_ip

class PacketFilter:
    """Bộ lọc gói (packet pre-filter) nhằm:

    - Loại bỏ lưu lượng không hữu ích / gây nhiễu (DNS, QUIC, gói quá nhỏ...)
    - Bỏ qua HTTPS nếu được cấu hình (giảm false positive do mã hoá)
    - Phát hiện sớm IP trong blacklist và tạo cảnh báo ngay
    - Kết hợp detector quét cổng trước khi chuyển tiếp sang xây dựng luồng

    """
    def __init__(self, *, ignore_https: bool, whitelist: set, blacklist: set,
                 port_scan_detector, attack_logger, alert_queue, recent_alerts, stats: dict):
        self.ignore_https = ignore_https
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.port_scan_detector = port_scan_detector
        self.attack_logger = attack_logger
        self.alert_queue = alert_queue
        self.recent_alerts = recent_alerts
        self.stats = stats

    def _check_port_scan(self, pkt) -> bool:
        """Kiểm tra và xử lý quét cổng (nếu vượt ngưỡng PortScanDetector sẽ phát cảnh báo).

        Trả về True nếu gói đã được xử lý như quét cổng và không cần phân tích tiếp.
        """
        if self.port_scan_detector is None:
            return False
        return self.port_scan_detector.process(
            pkt, self.attack_logger, self.alert_queue, self.recent_alerts, self.stats
        )

    def should_process(self, pkt) -> bool:
        """Quyết định có chuyển gói sang bước phân tích sâu hay loại bỏ.

        Trả về False nếu gói bị bỏ qua, True nếu nên tiếp tục xử lý.
        """
        if not pkt.haslayer(IP):
            return False

        # Bỏ qua lưu lượng HTTPS nếu được bật cờ ignore_https
        if self.ignore_https and pkt.haslayer(TCP):
            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                return False

        # Phát hiện quét cổng (nếu đã cảnh báo thì bỏ qua tiếp)
        if self._check_port_scan(pkt):
            return False

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Whitelist: bỏ qua hoàn toàn
        if src_ip in self.whitelist or dst_ip in self.whitelist:
            return False

        # Blacklist: tạo cảnh báo ngay lập tức rồi dừng
        if src_ip in self.blacklist or dst_ip in self.blacklist:
            now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
            alert_msg = f"BLACKLISTED IP DETECTED: {src_ip} -> {dst_ip}"
            print(f"[{now_str}] {alert_msg}")
            self.attack_logger.info(alert_msg)
            alert_data = {
                "type": "blacklist",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "time": now_str,
                "message": alert_msg,
            }
            self.alert_queue.put(alert_data)
            self.recent_alerts.append(alert_data)
            self.stats["alerts_generated"] += 1
            return False

        # Bỏ DNS (53/UDP) & QUIC (443/UDP) vì thường xuyên và ít giá trị cho mô hình
        if pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            if dport in (53, 443) or sport in (53, 443):
                return False

        # Gói quá nhỏ (< 40 bytes) thường là nhiễu / header chưa đủ
        if len(pkt) < 40:
            return False

        # Lưu lượng private↔private thường hợp lệ – vẫn cho qua để mô hình đánh giá
        if is_private_ip(src_ip) and is_private_ip(dst_ip):
            pass

        return True
