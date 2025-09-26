import re
from scapy.all import TCP, UDP, ICMP

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

def is_private_ip(ip: str) -> bool:
    """Kiểm tra xem IP có phải là IP riêng/nội bộ không"""
    for pattern in PRIVATE_IP_PATTERNS:
        if re.match(pattern, ip):
            return True
    return False

def tcp_flag_to_nslkdd(pkt) -> str:
    """Ánh xạ TCP flags về nhãn gần giống NSL-KDD"""
    if not pkt.haslayer(TCP):
        return "SF"
    flags = pkt[TCP].flags
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
    if pkt.haslayer(TCP):  
        return "tcp"
    if pkt.haslayer(UDP):  
        return "udp"
    if pkt.haslayer(ICMP): 
        return "icmp"
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
