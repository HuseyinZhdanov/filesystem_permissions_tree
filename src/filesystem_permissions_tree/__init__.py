"""filesystem_permissions_tree: audit filesystem permission bits against an expected mask.

Public API:
    Violation         -- dataclass describing a single deviation
    AuditResult       -- dataclass holding the full violation list and a clean flag
    audit_tree        -- walk a directory and collect permission-bit deviations
"""

from .core import Violation, AuditResult, audit_tree

__all__ = ["Violation", "AuditResult", "audit_tree"]
