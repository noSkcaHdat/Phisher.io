import base64
import time
from typing import Any, Dict
import requests

API_BASE = "https://www.virustotal.com/api/v3"

def _encode_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def vt_check_url(url: str, api_key: str, timeout_sec: int = 20, interval: float = 2.0) -> Dict[str, Any]:
    headers = {"x-apikey": api_key}
    url_id = _encode_url(url)

    # Try existing report
    r = requests.get(f"{API_BASE}/urls/{url_id}", headers=headers, timeout=timeout_sec)
    if r.status_code == 200:
        return r.json()

    # Submit and poll if not found
    if r.status_code == 404:
        sub = requests.post(f"{API_BASE}/urls", headers=headers, data={"url": url}, timeout=timeout_sec)
        sub.raise_for_status()
        analysis_id = sub.json().get("data", {}).get("id")
        if not analysis_id:
            return {"error": "submission_failed"}
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            res = requests.get(f"{API_BASE}/analyses/{analysis_id}", headers=headers, timeout=timeout_sec)
            res.raise_for_status()
            status = res.json().get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                rep = requests.get(f"{API_BASE}/urls/{url_id}", headers=headers, timeout=timeout_sec)
                if rep.status_code == 200:
                    return rep.json()
                break
            time.sleep(interval)
    return {"error": "vt_unavailable_or_timeout"}
