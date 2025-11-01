from fastapi.testclient import TestClient
from app.main import app
from app import pipeline as pipeline_module

client = TestClient(app)

def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_infer_stubs(monkeypatch):
    def _classify_email(self, text):
        return {"label": "Phishing", "probabilities": {"legitimate": 0.1, "phishing": 0.9}}

    def _summarize(self, text):
        return [{"summary_text": "summary"}]

    def _whois(self, url):
        return {"domain": "example.com", "risk": {"verdict": "Low", "risk_score": 2, "reasons": []}}

    def _vt(self, url):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}

    monkeypatch.setattr(pipeline_module.UnifiedPipeline, "classify_email", _classify_email)
    monkeypatch.setattr(pipeline_module.UnifiedPipeline, "summarize", _summarize)
    monkeypatch.setattr(pipeline_module.UnifiedPipeline, "whois_risk", _whois)
    monkeypatch.setattr(pipeline_module.UnifiedPipeline, "vt_report", _vt)

    r = client.post("/infer", json={"text": "test email", "url": "http://example.com"})
    assert r.status_code == 200
    j = r.json()
    assert j["input"]["text"] == "test email"
    assert "email_classifier" in j["outputs"]
    assert "whois" in j["outputs"]
    assert "virustotal" in j["outputs"]
    assert j["verdict"]["verdict"] in {"High Risk", "Medium Risk", "Low Risk"}
