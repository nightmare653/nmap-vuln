"""nmapvuln — validate nmap scan output and correlate services with known CVEs."""

from .cli import VERSION, main

__version__ = VERSION
__all__ = ["main", "VERSION", "__version__"]
