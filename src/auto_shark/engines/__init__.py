"""External protocol-engine adapters."""

from .tshark import TsharkCapabilities, probe_tshark

__all__ = ["TsharkCapabilities", "probe_tshark"]
