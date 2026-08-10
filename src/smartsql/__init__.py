"""SmartSQL - an adaptive SQL injection engine with self-adapting WAF evasion.

SmartSQL is a defensive/offensive security research tool for *authorized*
penetration testing. It probes a target for SQL injection using multiple
techniques and continuously adapts its behaviour (payload encoding, request
timing, request identity) in response to what the target does - most notably
Web Application Firewalls.

Only use this tool against systems you own or have explicit written
permission to test.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
