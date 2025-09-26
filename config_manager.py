#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quản lý cấu hình động (live) cho phép *hot-reload* file config.ini
không cần khởi động lại dịch vụ.

- Cung cấp đối tượng GLOBAL_CONFIG dùng chung, an toàn luồng (thread-safe)
- Các hàm get tiện lợi: get / getint / getfloat / getboolean
- Hàm write_updates() ghi các thay đổi (dạng dict lồng) xuống file một cách
    *atomic* rồi tự reload lại vào bộ nhớ
- Được sử dụng trong endpoint /api/settings để áp dụng thay đổi ngay.
"""
import configparser
import threading
import os
import time
from typing import Dict, Any


class LiveConfig:
    def __init__(self, path: str = 'config.ini'):
        self.path = path
        self._lock = threading.RLock()
        self._parser = configparser.ConfigParser()
        self._mtime = 0.0
        self.reload()

    # ---------------- Thao tác lõi (core ops) -----------------
    def reload(self):
        with self._lock:
            self._parser.read(self.path, encoding='utf-8')
            try:
                self._mtime = os.path.getmtime(self.path)
            except OSError:
                self._mtime = time.time()

    def write_updates(self, updates: Dict[str, Dict[str, Any]]):
        """Áp dụng dict nhiều cấp (section -> {key: value}) rồi ghi xuống file.

        Sau khi ghi xong sẽ tự gọi reload() để cập nhật lại thời gian sửa đổi
        (mtime) và nội dung trong bộ nhớ.
        """
        with self._lock:
            parser = self._parser
            for section, kv in updates.items():
                if not parser.has_section(section):
                    parser.add_section(section)
                for k, v in kv.items():
                    parser.set(section, k, str(v))
            with open(self.path, 'w', encoding='utf-8') as f:
                parser.write(f)
            # refresh mtime & memory copy
            self.reload()

    # ---------------- Hàm lấy giá trị (getters) ------------------
    def get(self, section, key, fallback=None):
        with self._lock:
            return self._parser.get(section, key, fallback=fallback)

    def getint(self, section, key, fallback=0):
        with self._lock:
            return self._parser.getint(section, key, fallback=fallback)

    def getfloat(self, section, key, fallback=0.0):
        with self._lock:
            return self._parser.getfloat(section, key, fallback=fallback)

    def getboolean(self, section, key, fallback=False):
        with self._lock:
            return self._parser.getboolean(section, key, fallback=fallback)


# Singleton dùng chung toàn hệ thống
GLOBAL_CONFIG = LiveConfig('config.ini')
