#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alert Management and Filtering"""

from datetime import datetime
from collections import deque

class AlertManager:
    """Handles alert generation, filtering, and direction correction"""
    
    def __init__(self, alert_queue, attack_logger, stats):
        self.alert_queue = alert_queue
        self.attack_logger = attack_logger
        self.stats = stats
        self.recent_alerts = deque(maxlen=100)
        self.previous_alerts = {}
    
    def should_alert(self, key, prob, state, local_ips, window):
        """Post-process alert to filter false positives"""
        from detectors.heuristics import post_process_alert as _h_post_process_alert
        return _h_post_process_alert(key, prob, state, self.previous_alerts, window)
    
    def is_legitimate_outbound(self, sip, dip, proto, state, local_ips):
        """Check if flow is legitimate outbound traffic (should skip alert)"""
        # Skip LOCAL → * traffic (outbound/internal)
        if sip in local_ips:
            # Special case: ICMP replies from local server
            if proto == "icmp":
                total_pkts = state.pkt_src + state.pkt_dst
                if total_pkts < 20 and state.pkt_dst > 0:
                    imbalance = state.pkt_src / state.pkt_dst
                    if imbalance < 2.0:  # Balanced = normal reply
                        return True
            return True  # Skip all LOCAL source traffic
        return False
    
    def generate_alert(self, key, prob, state, attack_type, local_ips):
        """Generate and queue alert if conditions are met"""
        sip, sport, dip, dport, proto = key
        
        # Skip if not EXTERNAL → LOCAL (inbound attack)
        if sip not in local_ips and dip not in local_ips:
            return False  # Neither is local
        
        if self.is_legitimate_outbound(sip, dip, proto, state, local_ips):
            return False
        
        # Only alert on EXTERNAL → LOCAL
        if sip not in local_ips and dip in local_ips:
            total_pkts = state.pkt_src + state.pkt_dst
            flags_str = ",".join([f"{flag}:{count}" for flag, count in state.flag_counts.items() if count > 0])
            
            alert_msg = f"ALERT {attack_type} proto={proto} {sip}:{sport} -> {dip}:{dport} [pkts={total_pkts} prob={prob:.3f} flags={flags_str}]"
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
                "probability": float(prob),
                "time": now_str_local,
                "message": alert_msg,
                "bytes_src": state.src_bytes,
                "bytes_dst": state.dst_bytes,
                "rate_src": state.rate_src,
                "rate_dst": state.rate_dst,
                "duration": state.last_ts - state.first_ts,
                "pkt_src": state.pkt_src,
                "pkt_dst": state.pkt_dst,
            }
            
            self.alert_queue.put(alert_data)
            self.recent_alerts.append(alert_data)
            self.stats["alerts_generated"] += 1
            return True
        
        return False
    
    def get_recent_alerts(self):
        """Return recent alerts list"""
        return list(self.recent_alerts)
