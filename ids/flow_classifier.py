#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flow Classification and Boosting Logic"""

import time
from collections import defaultdict

class FlowClassifier:
    """Handles flow classification decisions and probability boosting"""
    
    def __init__(self, config):
        self.min_pkts = config.getint('Network', 'min_packets')
        self.min_bytes = config.getint('Network', 'min_bytes')
        self.small_flow_threshold = config.getint('Detection', 'small_flow_threshold', fallback=50)
        self.small_flow_window = config.getint('Detection', 'small_flow_window', fallback=5)
        self.global_flow_threshold = config.getint('Detection', 'global_flow_threshold', fallback=100)
        
        self.small_flow_tracker = defaultdict(lambda: {'count': 0, 'last_reset': time.time()})
        self.global_flow_tracker = {'count': 0, 'last_reset': time.time()}
        self.attack_logger = None  # Will be set by engine
    
    def should_classify(self, flow_key, flow_data):
        """Decide if flow should be classified by ML"""
        pkt_count = flow_data.get('packet_count', 0)
        total_bytes = flow_data.get('total_bytes', 0)
        
        # Rule 1: Large flow → Always classify
        if pkt_count >= self.min_pkts and total_bytes >= self.min_bytes:
            return True
        
        # Rule 2: Small flow from suspicious IP
        if not isinstance(flow_key, tuple) or len(flow_key) < 5:
            return False
            
        src_ip = flow_key[0]
        current_time = time.time()
        tracker = self.small_flow_tracker[src_ip]
        
        # Reset counter if window expired
        if current_time - tracker['last_reset'] > self.small_flow_window:
            tracker['count'] = 0
            tracker['last_reset'] = current_time
        
        tracker['count'] += 1
        
        # Track global flow count
        global_tracker = self.global_flow_tracker
        if current_time - global_tracker['last_reset'] > self.small_flow_window:
            global_tracker['count'] = 0
            global_tracker['last_reset'] = current_time
        global_tracker['count'] += 1
        
        # Check per-IP threshold
        if tracker['count'] > self.small_flow_threshold:
            return True  # Classify without logging (reduce spam)
        
        # Check global threshold (DDoS/spoofed-IP detection)
        if global_tracker['count'] > self.global_flow_threshold:
            return True  # Classify all flows (--rand-source detection)
        
        return False
    
    def boost_probabilities(self, keys, probs, states, min_pkts):
        """Apply confidence boosting based on DoS patterns"""
        boost_min_pkts = max(min_pkts, 3)
        boosted_probs = []
        
        for k, pr, st in zip(keys, probs, states):
            sip, sport, dip, dport, proto = k
            
            # TCP SYN Flood Boosting
            if proto == "tcp":
                total_flags = sum(st.flag_counts.values())
                if total_flags >= boost_min_pkts:
                    s0_count = st.flag_counts.get("S0", 0)
                    rej_count = st.flag_counts.get("REJ", 0)
                    attack_flags = s0_count + rej_count
                    if attack_flags >= boost_min_pkts:
                        attack_rate = attack_flags / total_flags
                        if attack_rate > 0.4:
                            boost_factor = 1.0 + (attack_rate - 0.4) * 3.33  # Max +200%
                            pr = min(0.99, pr * boost_factor)
            
            # UDP Flood Boosting
            elif proto == "udp":
                total_pkts = st.pkt_src + st.pkt_dst
                if total_pkts >= boost_min_pkts:
                    imbalance = st.pkt_src / st.pkt_dst if st.pkt_dst > 0 else 100.0
                    if imbalance > 5.0:
                        boost_factor = 1.0 + min(1.5, (imbalance - 5.0) / 63.3)  # Max +150%
                        pr = min(0.99, pr * boost_factor)
            
            # ICMP Flood Boosting
            elif proto == "icmp":
                total_pkts = st.pkt_src + st.pkt_dst
                if total_pkts >= boost_min_pkts:
                    imbalance = st.pkt_src / st.pkt_dst if st.pkt_dst > 0 else 100.0
                    if imbalance > 3.0:
                        boost_factor = 1.0 + min(2.0, (imbalance - 3.0) / 48.5)  # Max +200%
                        pr = min(0.99, pr * boost_factor)
            
            boosted_probs.append(pr)
        
        return boosted_probs
    
    def apply_rule_based_fallback(self, keys, probs, states, preds, min_pkts):
        """Force alert for clear DoS patterns even if ML prob is low"""
        boost_min_pkts = max(min_pkts, 1)  # Allow 1+ packets for --rand-source
        fallback_min_pkts = max(boost_min_pkts * 3, 10)
        
        for idx, (k, pr, st) in enumerate(zip(keys, probs, states)):
            sip, sport, dip, dport, proto = k
            total_pkts = st.pkt_src + st.pkt_dst
            
            # TCP SYN/REJ flood (including --rand-source with 1 SYN packet)
            if proto == "tcp" and total_pkts >= 1:
                total_flags = sum(st.flag_counts.values())
                if total_flags > 0:
                    s0_count = st.flag_counts.get("S0", 0)
                    rej_count = st.flag_counts.get("REJ", 0)
                    attack_rate = (s0_count + rej_count) / total_flags
                    # Lower threshold for single-packet flows (--rand-source)
                    threshold = 0.5 if total_pkts == 1 else 0.8
                    if attack_rate >= threshold:
                        preds[idx] = 1
            
            # UDP/ICMP flood (including --rand-source)
            if proto in ["udp", "icmp"]:
                if total_pkts >= 1:  # Allow 1+ packets
                    imbalance = st.pkt_src / st.pkt_dst if st.pkt_dst > 0 else 100.0
                    # Lower threshold for small flows
                    threshold = 5.0 if total_pkts <= 3 else 20.0
                    if imbalance > threshold:
                        preds[idx] = 1
        
        return preds
