#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Module gửi thông báo qua Email / Telegram với cơ chế gom (batch) theo chu kỳ.
"""

import os
import smtplib
import requests
import threading
import time
import configparser
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from collections import deque

class Notifier:
    def __init__(self, config_path='config.ini'):
        # Đọc cấu hình
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        
        # Cấu hình email
        self.enable_email = self.config.getboolean('Notification', 'enable_email', fallback=False)
        self.email_sender = self.config.get('Notification', 'email_sender', fallback='')
        self.email_password = self.config.get('Notification', 'email_password', fallback='')
        self.email_recipient = self.config.get('Notification', 'email_recipient', fallback='')
        self.email_interval = self.config.getint('Notification', 'email_interval', fallback=300) 
        
        # Cấu hình Telegram
        self.enable_telegram = self.config.getboolean('Notification', 'enable_telegram', fallback=False)
        self.telegram_token = self.config.get('Notification', 'telegram_token', fallback='')
        self.telegram_chat_id = self.config.get('Notification', 'telegram_chat_id', fallback='')
        self.telegram_interval = self.config.getint('Notification', 'telegram_interval', fallback=60)
        
        # Trạng thái và bộ đếm
        self.running = False
        self.notification_thread = None
        
        # Hàng đợi cảnh báo
        self.email_alerts = deque(maxlen=1000)
        self.telegram_alerts = deque(maxlen=1000)
        
        # Thời gian gửi thông báo cuối cùng
        self.last_email_time = 0
        self.last_telegram_time = 0

    def apply_config(self, live_cfg):
        """Hot reload cấu hình thông báo mà không cần khởi động lại thread."""
        try:
            self.enable_email = live_cfg.getboolean('Notification', 'enable_email', fallback=self.enable_email)
            self.email_sender = live_cfg.get('Notification', 'email_sender', fallback=self.email_sender)
            # password intentionally not logged
            self.email_password = live_cfg.get('Notification', 'email_password', fallback=self.email_password)
            self.email_recipient = live_cfg.get('Notification', 'email_recipient', fallback=self.email_recipient)
            self.email_interval = live_cfg.getint('Notification', 'email_interval', fallback=self.email_interval)

            self.enable_telegram = live_cfg.getboolean('Notification', 'enable_telegram', fallback=self.enable_telegram)
            self.telegram_token = live_cfg.get('Notification', 'telegram_token', fallback=self.telegram_token)
            self.telegram_chat_id = live_cfg.get('Notification', 'telegram_chat_id', fallback=self.telegram_chat_id)
            self.telegram_interval = live_cfg.getint('Notification', 'telegram_interval', fallback=self.telegram_interval)
            print(f"[Config] Notifier updated: email={self.enable_email} telegram={self.enable_telegram}")
        except Exception as e:
            print('[Config] Notifier apply_config error:', e)
        
    def start(self):
        """Bắt đầu dịch vụ thông báo (tạo thread nền)."""
        if self.running:
            return
            
        self.running = True
        self.notification_thread = threading.Thread(target=self._notification_loop)
        self.notification_thread.daemon = True
        self.notification_thread.start()
        print("[*] Notification service started")
        
    def stop(self):
        """Dừng dịch vụ thông báo."""
        self.running = False
        if self.notification_thread and self.notification_thread.is_alive():
            self.notification_thread.join(timeout=2)
        print("[*] Notification service stopped")
        
    def add_alert(self, alert_data):
        """Thêm cảnh báo vào hàng đợi – chỉ lưu nếu kênh tương ứng đang bật."""
        if not alert_data:
            return
            
        if self.enable_email:
            self.email_alerts.append(alert_data)
            
        if self.enable_telegram:
            self.telegram_alerts.append(alert_data)
            
    def _notification_loop(self):
        """Vòng lặp chính: mỗi chu kỳ kiểm tra có đủ điều kiện gửi Email/Telegram."""
        while self.running:
            now = time.time()
            
            # Kiểm tra xem có nên gửi email không
            if (self.enable_email and self.email_alerts and 
                now - self.last_email_time >= self.email_interval):
                self._send_email_notification()
                self.last_email_time = now
                
            # Kiểm tra xem có nên gửi Telegram không
            if (self.enable_telegram and self.telegram_alerts and 
                now - self.last_telegram_time >= self.telegram_interval):
                self._send_telegram_notification()
                self.last_telegram_time = now
                
            # Nghỉ một chút
            time.sleep(5)
            
    def _send_email_notification(self):
        """Kết hợp các cảnh báo đã thu thập và gửi một email HTML."""
        if not self.email_alerts:
            return
            
        try:
            # Tạo nội dung email
            alerts = list(self.email_alerts)
            self.email_alerts.clear()
            
            msg = MIMEMultipart()
            msg['From'] = self.email_sender
            msg['To'] = self.email_recipient
            msg['Subject'] = f"IDS Alert: {len(alerts)} security alerts detected"
            
            # Tạo nội dung HTML
            html = """
            <html>
            <head>
                <style>
                    table { border-collapse: collapse; width: 100%; }
                    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background-color: #f2f2f2; }
                    .high { color: red; font-weight: bold; }
                    .medium { color: orange; }
                </style>
            </head>
            <body>
                <h2>IDS Security Alerts</h2>
                <p>The following security alerts were detected:</p>
                <table>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Source</th>
                        <th>Destination</th>
                    </tr>
            """
            
            for alert in alerts:
                prob_class = "high" if alert.get('probability', 0) > 0.9 else "medium"
                src = f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}"
                dst = f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}"
                html += f"""
                    <tr>
                        <td>{alert.get('time', '')}</td>
                        <td>{alert.get('type', 'attack').upper()}</td>
                        <td>{src}</td>
                        <td>{dst}</td>
                    </tr>
                """
                
            html += """
                </table>
                <p>This is an automated message from your IDS system.</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            # Gửi email
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(self.email_sender, self.email_password)
                server.send_message(msg)
                
            print(f"[+] Email notification sent with {len(alerts)} alerts")
            
        except Exception as e:
            print(f"[!] Error sending email: {e}")
            
    def _send_telegram_notification(self):
        """Nhóm cảnh báo theo loại và gửi tin nhắn Markdown qua Telegram Bot API."""
        if not self.telegram_alerts:
            return
            
        try:
            # Lấy các cảnh báo
            alerts = list(self.telegram_alerts)
            self.telegram_alerts.clear()
            
            # Nhóm các cảnh báo theo loại
            alert_types = {}
            for alert in alerts:
                alert_type = alert.get('type', 'attack')
                if alert_type not in alert_types:
                    alert_types[alert_type] = []
                alert_types[alert_type].append(alert)
                
            # Tạo tin nhắn
            message = "🚨 *IDS Security Alerts* 🚨\n\n"
            
            for alert_type, type_alerts in alert_types.items():
                message += f"*{alert_type.upper()}* ({len(type_alerts)} alerts):\n"
                for i, alert in enumerate(type_alerts[:5]):  # Giới hạn 5 cảnh báo mỗi loại
                    src = f"{alert.get('src_ip', '')}:{alert.get('src_port', '')}"
                    dst = f"{alert.get('dst_ip', '')}:{alert.get('dst_port', '')}"
                    message += f"{i+1}. {src} -> {dst}\n"
                
                if len(type_alerts) > 5:
                    message += f"_...and {len(type_alerts) - 5} more {alert_type} alerts_\n"
                message += "\n"
                
            # Thêm thời gian
            message += f"_Report time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
            
            # Gửi tin nhắn qua Telegram API
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, data=data)
            response.raise_for_status()
            
            print(f"[+] Telegram notification sent with {len(alerts)} alerts")
            
        except Exception as e:
            print(f"[!] Error sending Telegram notification: {e}")

# Singleton instance
_notifier_instance = None

def get_notifier_instance(config_path='config.ini'):
    """Lấy hoặc tạo singleton Notifier."""
    global _notifier_instance
    if _notifier_instance is None:
        _notifier_instance = Notifier(config_path)
    return _notifier_instance