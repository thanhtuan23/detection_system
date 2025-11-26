# Các hàm tiện ích để phân tích gói tin
from scapy.all import TCP, UDP, ICMP

# Service port mapping cho NSL-KDD features
SERVICE_PORT_MAP = {
    80: "http", 443: "http_443", 21: "ftp", 20: "ftp_data",
    22: "ssh", 23: "telnet", 25: "smtp", 53: "domain_u", 110: "pop_3",
    143: "imap4", 8080: "http_8080"
}

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
