"""
utils/logger.py
Console + file logging used across all modules. configure_logging() must be
called once from main.py before any get_logger() calls if you want non-default
verbosity or a log file; otherwise get_logger() falls back to INFO/console-only.
"""

import logging
import sys
from pathlib import Path

_CONFIGURED = False


def configure_logging(level: str = "INFO", log_file: Path = None):
    """
    Call once at startup. level: 'DEBUG', 'INFO', 'WARNING', or 'ERROR'.
    If log_file is given, logs are written there in addition to the console
    (file always captures DEBUG+ regardless of console level, so a run can
    be replayed/debugged after the fact even if the console was quiet).
    """
    global _CONFIGURED
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # handlers below control what's actually shown/written
    root.handlers.clear()

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s", datefmt="%H:%M:%S")

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    console_handler.setFormatter(fmt)
    root.addHandler(console_handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        # Fallback for any module imported before main.py calls configure_logging()
        # (e.g. during tests) — sane INFO/console-only default.
        configure_logging(level="INFO", log_file=None)
    return logging.getLogger(name)