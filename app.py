#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ứng dụng web cho Realtime IDS
"""

import os
import json
import time
import threading
import configparser
import logging
from flask import Flask, render_template, jsonify, request, redirect, url_for, Response, session
from functools import wraps
from datetime import datetime

# Import modules
from ids_engine import get_ids_instance
from notifier import get_notifier_instance
from config_manager import GLOBAL_CONFIG
config = configparser.ConfigParser()
config.read('config.ini', encoding='utf-8')  # Use GLOBAL_CONFIG for initial values

# Tạo Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key cho session

# Lấy thông tin đăng nhập từ config
USERNAME = config.get('WebUI', 'username', fallback='admin')
PASSWORD = config.get('WebUI', 'password', fallback='admin123')
PORT = config.getint('WebUI', 'port', fallback=5000)

# Khởi tạo IDS và Notifier
ids = get_ids_instance('config.ini')
notifier = get_notifier_instance('config.ini')
ids.apply_config(GLOBAL_CONFIG)
notifier.apply_config(GLOBAL_CONFIG)

# Đảm bảo app không ghi log giản lược vào logs/attack.log
attack_logger = logging.getLogger("attack_logger")

def log_alert_to_file(alert: dict):
    """
    Ghi log chi tiết vào file nếu thật sự cần từ web (mặc định KHÔNG cần vì engine đã ghi).
    Nếu phải ghi, luôn ưu tiên message chi tiết do engine tạo.
    """
    msg = alert.get("message")
    if not msg:
        t = (alert.get("detail_type") or alert.get("type") or "Attack")
        proto = alert.get("proto") or "tcp"
        sip = alert.get("src_ip") or "-"
        sport = alert.get("src_port") or "-"
        dip = alert.get("dst_ip") or "-"
        dport = alert.get("dst_port") or "-"
        prob = alert.get("probability")
        # fallback dạng chi tiết, tránh mẫu "ALERT attack - Probability"
        if prob is not None:
            msg = f"ALERT {t} proto={proto} {sip}:{sport} -> {dip}:{dport} prob={float(prob):.3f}"
        else:
            msg = f"ALERT {t} proto={proto} {sip}:{sport} -> {dip}:{dport}"
    attack_logger.info(msg)

# Luồng chuyển tiếp cảnh báo đến notifier
def forward_alerts():
    while True:
        alert = ids.get_next_alert()
        if alert:
            notifier.add_alert(alert)
        time.sleep(0.1)

alert_thread = threading.Thread(target=forward_alerts)
alert_thread.daemon = True
alert_thread.start()

# Yêu cầu đăng nhập
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', running=ids.running)

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html')

@app.route('/settings')
@login_required
def settings():
    # Đọc cấu hình hiện tại
    config = configparser.ConfigParser()
    config.read('config.ini', encoding='utf-8')
    
    # Chuẩn bị dữ liệu cấu hình
    settings = {
        'network': {
            'interface': config.get('Network', 'interface'),
            'window': config.getint('Network', 'window'),
            'min_packets': config.getint('Network', 'min_packets'),
            'min_bytes': config.getint('Network', 'min_bytes')
        },
        'model': {
            'model_path': config.get('Model', 'model_path'),
            'preprocess_path': config.get('Model', 'preprocess_path'),
            'threshold': config.getfloat('Model', 'threshold')
        },
        'notification': {
            'enable_email': config.getboolean('Notification', 'enable_email', fallback=False),
            'email_sender': config.get('Notification', 'email_sender', fallback=''),
            'email_recipient': config.get('Notification', 'email_recipient', fallback=''),
            'email_interval': config.getint('Notification', 'email_interval', fallback=300),
            'enable_telegram': config.getboolean('Notification', 'enable_telegram', fallback=False),
            'telegram_chat_id': config.get('Notification', 'telegram_chat_id', fallback=''),
            'telegram_interval': config.getint('Notification', 'telegram_interval', fallback=60)
        }
    }
    
    return render_template('settings.html', settings=settings)

# API endpoints
@app.route('/api/start', methods=['POST'])
@login_required
def start_ids():
    success = ids.start()
    if success and not notifier.running:
        notifier.start()
    return jsonify({'success': success})

@app.route('/api/stop', methods=['POST'])
@login_required
def stop_ids():
    ids.stop()
    return jsonify({'success': True})

@app.route('/api/stats')
@login_required
def get_stats():
    return jsonify(ids.get_stats())

@app.route('/api/alerts')
@login_required
def get_alerts():
    # Gom các loại tấn công thành 'attack' trên web, nhưng giữ nguyên chi tiết trong log
    raw_alerts = ids.get_recent_alerts()
    attack_types = {
        'attack', 'dos', 'syn_flood', 'udp_flood', 'port_scan', 'brute_force',
        'web_attack', 'rst_flood', 'fin_flood', 'http_flood'
    }
    ui_alerts = []
    for a in raw_alerts:
        # Sao chép để không ảnh hưởng dữ liệu gốc dùng cho notifier/log
        b = dict(a)
        original_type = (b.get('type') or '').lower()
        if original_type in attack_types:
            b['detail_type'] = original_type  # giữ lại loại chi tiết nếu cần hiển thị sau này
            b['type'] = 'attack'              # gom nhóm cho UI
        ui_alerts.append(b)
    return jsonify(ui_alerts)

@app.route('/api/log')
@login_required
def get_log():
    lines = 100
    if 'lines' in request.args:
        try:
            lines = int(request.args['lines'])
        except ValueError:
            lines = 100
    
    log_path = 'logs/attack.log'
    if not os.path.exists(log_path):
        return jsonify({'lines': []})
        
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        # Đọc toàn bộ tệp và lấy các dòng cuối
        all_lines = f.readlines()
        last_lines = all_lines[-lines:] if lines < len(all_lines) else all_lines
        
    return jsonify({'lines': last_lines})

@app.route('/api/settings', methods=['POST'])
@login_required
def save_settings():
    payload = request.json or {}
    updates = {}
    if 'network' in payload:
        updates['Network'] = payload['network']
    if 'model' in payload:
        model_updates = {}
        for k, v in payload['model'].items():
            if v in ('', None):
                continue
            if k == 'threshold':
                try:
                    fv = float(v)
                    if 0 <= fv <= 1:
                        model_updates[k] = fv
                except Exception:
                    continue
            else:
                model_updates[k] = v
        if model_updates:
            updates.setdefault('Model', {}).update(model_updates)
    if 'notification' in payload:
        # Bỏ qua các trường rỗng để không overwrite mật khẩu/token cũ
        cleaned = {}
        for k, v in payload['notification'].items():
            if v in ('', None):
                continue
            cleaned[k] = v
        updates.setdefault('Notification', {}).update(cleaned)

    if updates:
        GLOBAL_CONFIG.write_updates(updates)
        ids.apply_config(GLOBAL_CONFIG)
        notifier.apply_config(GLOBAL_CONFIG)

    return jsonify({'success': True, 'hot_reloaded': True})

@app.route('/api/log/stream')
@login_required
def stream_log():
    def generate():
        with open('logs/attack.log', 'r', encoding='utf-8', errors='ignore') as f:
            # Di chuyển con trỏ đến cuối tệp
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield f"data: {json.dumps({'line': line.strip()})}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

# Start the app
if __name__ == '__main__':
    # Khởi động IDS và notifier
    ids.start()
    notifier.start()
    
    print(f"[*] Starting web server on port {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=False)