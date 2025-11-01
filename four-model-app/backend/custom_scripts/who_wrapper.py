"""WHOIS risk wrapper.

If a user-provided `who.py` exists/imports cleanly (on PYTHONPATH), we use:
  - get_domain_info(domain: str) -> dict
  - check_phishing_risk(info: dict) -> dict{"verdict": str, "risk_score": float, ...}
Otherwise we fall back to a stub that returns a low-risk verdict.
"""
from typing import Any, Dict
import tldextract

try:
    from who import get_domain_info, check_phishing_risk  # type: ignore
except Exception:  # pragma: no cover
    from .who_fallback import get_domain_info, check_phishing_risk  # type: ignore

def _domain_from_url(url_or_domain: str) -> str:
    ext = tldextract.extract(url_or_domain)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return url_or_domain

def analyze_domain(url_or_domain: str) -> Dict[str, Any]:
    domain = _domain_from_url(url_or_domain)
    info = get_domain_info(domain)
    verdict = check_phishing_risk(info)
    return {"domain": domain, "whois": info, "risk": verdict}
