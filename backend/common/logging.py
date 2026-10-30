"""Structured logging setup (structlog). Never log full secrets/tokens."""
from __future__ import annotations

import logging

import structlog

from config.settings import get_settings


def configure() -> None:
    level = getattr(logging, get_settings().log_level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", level=level)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
    )


def get_logger(name: str = "apkookies"):
    return structlog.get_logger(name)
