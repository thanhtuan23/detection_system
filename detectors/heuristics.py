from datetime import datetime, timezone
from typing import Dict, Tuple
from ids_utils import is_private_ip

# Các dải IP phổ biến cho HTTPS/CDN
GOOGLE_PREFIXES = ['74.125.', '142.250.', '64.233.', '216.58.', '172.217.']
CLOUDFLARE_PREFIXES = ['104.18.', '104.19.', '104.20.', '172.65.', '146.75.']


def is_trusted_source(ip: str, local_ips, whitelist) -> bool:
    """Nguồn tin cậy nếu là IP cục bộ/máy chủ, hoặc trong whitelist, hoặc trong vài dải phổ biến."""
    if ip in local_ips:
        return True
    if ip in whitelist:
        return True
    trusted_prefixes = GOOGLE_PREFIXES + CLOUDFLARE_PREFIXES + [
        '52.', '54.', '35.', '18.',           # AWS
        '157.240.', '69.171.', '31.13.',      # Facebook
    ]
    return any(ip.startswith(p) for p in trusted_prefixes)


def should_ignore_https(key: Tuple[str, int, str, int, str], state) -> bool:
    """Bỏ qua các kết nối HTTPS phổ biến theo một số tiêu chí lưu lượng."""
    sip, sport, dip, dport, _ = key

    # Nếu là HTTPS (cổng 443)
    if dport == 443 or sport == 443:
        # Bỏ qua nếu IP thuộc dải phổ biến
        for ip in (sip, dip):
            if any(ip.startswith(p) for p in GOOGLE_PREFIXES):
                return True
            if any(ip.startswith(p) for p in CLOUDFLARE_PREFIXES):
                return True

        # Lưu lượng web điển hình: thời lượng ngắn, nhận nhiều hơn gửi
        if (state.last_ts - state.first_ts < 15 and  # < 15s
            state.src_bytes < 100_000 and            # < 100KB gửi
            state.dst_bytes < 1_000_000):            # < 1MB nhận
            if ("SF" in state.flag_counts or "S0" in state.flag_counts):
                if state.src_bytes == 0 or (state.dst_bytes > 0 and state.src_bytes / state.dst_bytes < 0.2):
                    return True

        # TLS keep-alive nhỏ
        if (state.pkt_src + state.pkt_dst < 10 and state.src_bytes < 1000 and state.dst_bytes < 1000):
            return True
    return False


def post_process_alert(key, prob: float, state, previous_alerts: Dict[str, Tuple[int, float]], window_seconds: int) -> bool:
    """Heuristic sau dự đoán để quyết định có nên cảnh báo không."""
    sip, sport, dip, dport, proto = key

    # HTTPS ngoại lệ
    if should_ignore_https(key, state):
        return False

    # Tốc độ rất lớn -> nhiều khả năng là DoS
    if state.rate_src > 1_000_000 or state.rate_dst > 1_000_000:
        return True

    # Lịch sử cảnh báo
    import time
    flow_id = f"{sip}-{dip}-{proto}"
    now = time.time()

    if flow_id in previous_alerts:
        count, last_time = previous_alerts[flow_id]
        if now - last_time < 60:
            # Chỉ cảnh báo lại nếu prob tăng đáng kể
            if count > 3 and prob < 0.95:
                return False
            previous_alerts[flow_id] = (count + 1, now)
        else:
            previous_alerts[flow_id] = (1, now)
    else:
        previous_alerts[flow_id] = (1, now)

    # HTTPS cần ngưỡng cao hơn
    if dport == 443 or sport == 443:
        return prob > 0.95

    # Nội bộ lab environment: relaxed threshold for testing
    # (Production: increase to 0.85 to reduce false positives)
    if is_private_ip(sip) and is_private_ip(dip):
        return prob > 0.5

    return True


def determine_attack_type(key, state) -> str:
    """Suy luận loại tấn công từ đặc điểm luồng."""
    sip, sport, dip, dport, proto = key

    # SYN Flood
    if proto == "tcp" and "S0" in state.flag_counts:
        if dport == 0 or state.flag_counts["S0"] > 3:
            return "SYN_Flood"

    # Tính tốc độ gói tin
    duration = max(0.1, state.last_ts - state.first_ts)
    pkt_rate = (state.pkt_src + state.pkt_dst) / duration

    # DoS dựa trên tốc độ hoặc throughput
    if pkt_rate > 50 or state.rate_src > 500_000 or state.rate_dst > 500_000:
        if proto == "tcp":
            if "R" in state.flag_counts and state.flag_counts["R"] > 3:
                return "RST_Flood"
            elif "F" in state.flag_counts and state.flag_counts["F"] > 3:
                return "FIN_Flood"
            elif "P" in state.flag_counts and pkt_rate > 100:
                return "HTTP_Flood"
        if proto == "udp" and pkt_rate > 100:
            return "UDP_Flood"
        return "DoS"

    # Port Scan
    if proto == "tcp" and state.pkt_src > 3 and state.pkt_dst < 2:
        if "S0" in state.flag_counts or "REJ" in state.flag_counts:
            return "Port_Scan"

    # Brute Force vào các cổng xác thực phổ biến
    if dport in [22, 23, 3389, 5900, 21, 25, 110, 143] and state.pkt_src > 10:
        return "Brute_Force"

    return "Attack"
