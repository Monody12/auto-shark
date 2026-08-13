"""Protocol-specific structured adapters."""

from .http import HttpMessage, parse_http_line, tshark_http_arguments

__all__ = ["HttpMessage", "parse_http_line", "tshark_http_arguments"]
