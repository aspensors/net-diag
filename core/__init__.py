"""Network-diagnostic domain layer. It deliberately has no UI dependencies."""

from .checker import NetworkChecker
from .models import CheckReport, ProbeOptions

__all__ = ["NetworkChecker", "CheckReport", "ProbeOptions"]
