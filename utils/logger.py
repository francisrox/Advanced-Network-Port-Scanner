# utils/logger.py
# Centralised logging setup used by every module in the scanner.

import logging
import os
from logging.handlers import RotatingFileHandler

from utils.config import LOG_FILE, LOG_LEVEL, OUTPUT_DIR

_initialized = False
_scanner_logger: logging.Logger | None = None


def get_logger(name: str = "scanner") -> logging.Logger:
    """
    Return a named logger.  On first call the root 'scanner' logger is
    configured (file + console handlers).  Subsequent calls reuse the
    existing handler configuration.
    """
    global _initialized, _scanner_logger

    logger = logging.getLogger(name)

    if _initialized:
        return logger

    # ── Create output dir if it doesn't exist ───────────────────────────────
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log_path = os.path.join(OUTPUT_DIR, LOG_FILE)

    level = getattr(logging, LOG_LEVEL.upper(), logging.DEBUG)
    logger.setLevel(level)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Rotating file handler (max 5 MB, keep 3 backups)
    fh = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setFormatter(fmt)
    fh.setLevel(level)
    logger.addHandler(fh)

    # Console handler (INFO and above only)
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

    logger.propagate = False
    _initialized = True
    _scanner_logger = logger
    return logger
