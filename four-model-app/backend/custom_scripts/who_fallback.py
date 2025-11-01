from datetime import datetime, timedelta
from typing import Dict, Any

def get_domain_info(domain: str) -> Dict[str, Any]:
    now = datetime.utcnow()
    return {
        "domain": domain,
        "creation_date": (now - timedelta(days=400)).isoformat(),
        "expiration_date": (now + timedelta(days=300)).isoformat(),
        "registrar": "ExampleRegistrar",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "domain_age_days": 400,
    }

def check_phishing_risk(domain_info: Dict[str, Any]) -> Dict[str, Any]:
    # Simple safe default
    return {"verdict": "Low", "risk_score": 1.0, "reasons": ["fallback"]}
