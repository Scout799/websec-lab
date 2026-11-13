"""Dynamic browser-based auditing (M7)."""

from websec_lab.auditor.dynamic.models import DynamicAuditResult
from websec_lab.auditor.dynamic.runner import (
    DynamicAuditConfig,
    LoginConfig,
    StateCheckConfig,
    run_dynamic_audit,
)
from websec_lab.auditor.dynamic.session import BrowserSession, BrowserSessionError

__all__ = [
    "BrowserSession",
    "BrowserSessionError",
    "DynamicAuditConfig",
    "DynamicAuditResult",
    "LoginConfig",
    "StateCheckConfig",
    "run_dynamic_audit",
]
