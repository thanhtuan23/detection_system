#!/usr/bin/env python3
# -*- coding: utf-8 -*-


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
SUPPRESS_ACCESS_LOG = config.getboolean('WebUI', 'suppress_access_log', fallback=True)

# Tắt log truy cập HTTP (werkzeug) nếu được yêu cầu
if SUPPRESS_ACCESS_LOG:
    wl = logging.getLogger('werkzeug')
    wl.setLevel(logging.ERROR)
    # Có thể tắt hoàn toàn nếu muốn: wl.disabled = True
    # Đồng thời tắt logger Flask nếu không cần
    app.logger.disabled = True
    # Ngăn Flask tự thêm handler mới
    app.config['LOGGER_HANDLER_POLICY'] = 'never'

# Khởi tạo IDS và Notifier
ids = get_ids_instance('config.ini')
notifier = get_notifier_instance('config.ini')
ids.apply_config(GLOBAL_CONFIG)
notifier.apply_config(GLOBAL_CONFIG)

# Đảm bảo app không ghi log giản lược vào logs/attack.log
attack_logger = logging.getLogger("attack_logger")

def log_alert_to_file(alert: dict):
    """Ghi log (không cần thiết vì engine đã ghi, giữ lại để tương thích)"""
    msg = alert.get("message", "ATTACK detected")
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
@app.route('/')
def index():
    return render_template('index.html', running=ids.running)

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/settings')
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
def start_ids():
    success = ids.start()
    if success and not notifier.running:
        notifier.start()
    return jsonify({'success': success})

@app.route('/api/stop', methods=['POST'])
def stop_ids():
    ids.stop()
    return jsonify({'success': True})

@app.route('/api/stats')
def get_stats():
    return jsonify(ids.get_stats())

@app.route('/api/alerts')
def get_alerts():
    # Simplified: Chỉ có 1 loại alert = "attack"
    return jsonify(ids.get_recent_alerts())

@app.route('/api/log')
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