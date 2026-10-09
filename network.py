"""
Client Network Identification for RBAC AI Platform.

Resolves the IP address of the browser that is using the current Streamlit session,
so that logins and audit events record where a request really came from.
"""

import ipaddress
from typing import Optional

FALLBACK_IP = "127.0.0.1"


def _is_internal(ip: Optional[str]) -> bool:
    """True if the IP is missing, loopback or private (i.e. could be a proxy hop)."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return addr.is_loopback or addr.is_private


def _clean(ip: Optional[str]) -> Optional[str]:
    """Validate an IP string; return the normalized form or None."""
    if not ip:
        return None
    candidate = ip.strip()
    # Strip IPv4-mapped IPv6 prefix (e.g. ::ffff:192.168.1.5)
    if candidate.lower().startswith("::ffff:"):
        candidate = candidate[7:]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def get_client_ip() -> str:
    """
    Returns the IP address of the client of the active Streamlit session.

    Resolution order:
      1. The direct socket peer address (st.context.ip_address).
      2. If that is missing/loopback/private (the app sits behind a reverse proxy, as on
         Streamlit Community Cloud or Render), the first address in X-Forwarded-For,
         then X-Real-IP.
      3. 127.0.0.1 when there is no Streamlit request (CLI, tests) or nothing is resolvable.
    """
    try:
        import streamlit as st
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        if get_script_run_ctx(suppress_warning=True) is None:
            return FALLBACK_IP  # not inside a browser session (CLI import, tests)
        ctx = st.context
        peer = _clean(getattr(ctx, "ip_address", None))
        headers = ctx.headers or {}
    except Exception:
        return FALLBACK_IP

    if peer and not _is_internal(peer):
        return peer

    try:
        forwarded = headers.get("X-Forwarded-For") or ""
        first_hop = _clean(forwarded.split(",")[0]) if forwarded else None
        real_ip = _clean(headers.get("X-Real-IP"))
    except Exception:
        first_hop, real_ip = None, None

    return first_hop or real_ip or peer or FALLBACK_IP
