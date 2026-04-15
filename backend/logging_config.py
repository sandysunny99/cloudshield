"""
CloudShield Logging Configuration
Provides consistent structured logging across all services.
Call configure_logging() from app.py at startup.
"""

import logging
import os
import sys
from datetime import datetime

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def configure_logging():
    """Configure the root logger for the CloudShield application."""
    numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)

    # Root logger
    logging.basicConfig(
        level=numeric_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        stream=sys.stdout,
        force=True
    )

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "botocore", "boto3", "pymongo", "apscheduler"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logger = logging.getLogger("cloudshield")
    logger.info("CloudShield logging initialized (level=%s)", LOG_LEVEL)
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the cloudshield namespace."""
    return logging.getLogger(f"cloudshield.{name}")
