import logging
import os


def setup_logging():
    """Tạo logger ghi vào logs/attack.log (UTF-8) và tránh gắn trùng handler."""
    os.makedirs("logs", exist_ok=True)

    attack_logger = logging.getLogger("attack_logger")
    attack_logger.setLevel(logging.INFO)

    log_path = os.path.abspath(os.path.join("logs", "attack.log"))
    has_same = False
    for h in attack_logger.handlers:
        if isinstance(h, logging.FileHandler):
            try:
                if os.path.abspath(getattr(h, "baseFilename", "")) == log_path:
                    has_same = True
                    break
            except Exception:
                pass
    if not has_same:
        file_handler = logging.FileHandler("logs/attack.log", encoding='utf-8')
        file_format = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_format)
        attack_logger.addHandler(file_handler)

    attack_logger.propagate = False
    return attack_logger
