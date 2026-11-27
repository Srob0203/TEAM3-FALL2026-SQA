"""
forensics_logger.py
Forensics integration for SLI-KUBE (COMP 5710/6710 SQA project, activity 4.b).

Every instrumented method writes to one append-only log (forensics.log) so that
after an incident you can reconstruct: WHAT ran, WITH WHAT inputs, WHAT it
returned, HOW LONG it took, and WHAT went wrong.

Usage inside a method:
    from forensics_logger import get_logger
    logger = get_logger()
    logger.info("scanSingleManifest: start path=%s", path)
"""
import logging
import os

LOG_FILE = os.environ.get("SLIKUBE_FORENSICS_LOG", "forensics.log")
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(module)s.%(funcName)s:%(lineno)d | %(message)s"

_logger = None


def get_logger():
    """Return the single shared forensics logger (created on first call)."""
    global _logger
    if _logger is None:
        _logger = logging.getLogger("slikube.forensics")
        _logger.setLevel(logging.DEBUG)
        _logger.propagate = False
        handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        _logger.addHandler(handler)
    return _logger


def safe_repr(value, limit=200, mask=False):
    """Shorten values for the log and never let logging itself crash the tool.
    mask=True hides the content entirely (keeps only type and length). Use it for
    anything that could BE a secret value, since SLI-KUBE scans for secrets and
    the forensics log must not become a second copy of them."""
    try:
        text = repr(value)
    except Exception:
        return "<unrepresentable>"
    if mask:
        return "<masked %s len=%d>" % (type(value).__name__, len(text))
    return text if len(text) <= limit else text[:limit] + "...<truncated>"
