from typing import Dict, Any, Optional
import traceback
import torch
import torch.nn.functional as F
from transformers import BertForSequenceClassification, BertTokenizer
from transformers.pipelines import pipeline as hf_pipeline
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from custom_scripts.who_wrapper import analyze_domain
from custom_scripts.vt_wrapper import vt_check_url


class UnifiedPipeline:
    """
    Combine BERT email classifier + URL phishing model + WHOIS + VirusTotal (+ optional HF summarizer).
    """

    def __init__(self, hf_model_1: str, hf_model_2: Optional[str] = None, vt_api_key: Optional[str] = None) -> None:
        # For Email
        self.bert_model = BertForSequenceClassification.from_pretrained(hf_model_1)
        self.bert_tokenizer = BertTokenizer.from_pretrained(hf_model_1)
        self.bert_model.eval()

        
        self.model2 = hf_pipeline("summarization", model=hf_model_2) if hf_model_2 else None

        # For Url
        self.url_tokenizer = AutoTokenizer.from_pretrained("darshan8950/phishing_url_detection_BERT")
        self.url_model = AutoModelForSequenceClassification.from_pretrained("darshan8950/phishing_url_detection_BERT")
        self.url_model.eval()

        #VT API KEY INIT
        self.vt_api_key = vt_api_key

   
    def classify_email(self, text: str) -> Dict[str, Any]:
        inputs = self.bert_tokenizer(
            text, return_tensors="pt", truncation=True, padding="max_length", max_length=512
        )
        with torch.no_grad():
            outputs = self.bert_model(**inputs)
            logits = outputs.logits
            probs = F.softmax(logits, dim=-1)[0].tolist()
            pred = int(torch.argmax(logits, dim=-1).item())
        label = "Phishing" if pred == 1 else "Legitimate"
        return {
            "label": label,
            "probabilities": {"legitimate": float(probs[0]), "phishing": float(probs[1])},
        }

    def classify_url(self, url: Optional[str]) -> Optional[Dict[str, Any]]:
        if not url:
            return None
        inputs = self.url_tokenizer(url, return_tensors="pt", truncation=True, padding="max_length", max_length=128)
        with torch.no_grad():
            outputs = self.url_model(**inputs)
            probs = F.softmax(outputs.logits, dim=-1)[0].tolist()
            pred = int(torch.argmax(outputs.logits, dim=-1).item())
        label = "Phishing" if pred == 1 else "Legitimate"
        return {
            "label": label,
            "probabilities": {"legitimate": float(probs[0]), "phishing": float(probs[1])},
        }

    def summarize(self, text: str) -> Optional[Any]:
        if not self.model2:
            return None
        return self.model2(text, max_length=120, min_length=20, do_sample=False)

    def whois_risk(self, url_or_domain: Optional[str]) -> Optional[Dict[str, Any]]:
        if not url_or_domain:
            return None
        return analyze_domain(url_or_domain)

    def vt_report(self, url: Optional[str]) -> Optional[Dict[str, Any]]:
        if not url or not self.vt_api_key:
            return None
        return vt_check_url(url, self.vt_api_key)

    def run_all(self, text: str, url: Optional[str] = None) -> Dict[str, Any]:
        def safe(call, *args, **kwargs):
            try:
                return call(*args, **kwargs)
            except Exception as e:
                return {"error": f"{e.__class__.__name__}: {e}", "trace": traceback.format_exc()}

        out_email_cls = safe(self.classify_email, text)
        out_url_cls = safe(self.classify_url, url)
        out_summary = safe(self.summarize, text) if self.model2 else None
        out_whois = safe(self.whois_risk, url) if url else None
        out_vt = safe(self.vt_report, url) if url and self.vt_api_key else None

        return {
            "email_classifier": out_email_cls,
            "url_classifier": out_url_cls,
            "summary": out_summary,
            "whois": out_whois,
            "virustotal": out_vt,
        }

    def aggregate(self, outputs: Dict[str, Any]) -> Dict[str, Any]:
        phishing_prob = float(outputs.get("email_classifier", {}).get("probabilities", {}).get("phishing", 0.0))

        url_phish_prob = float(outputs.get("url_classifier", {}).get("probabilities", {}).get("phishing", 0.0))

        whois_risk_score = 0.0
        whois = outputs.get("whois")
        if isinstance(whois, dict) and not whois.get("error"):
            risk = whois.get("risk") or {}
            whois_risk_score = float(risk.get("risk_score", 0.0))

        vt_malicious = 0
        vt = outputs.get("virustotal")
        if isinstance(vt, dict) and not vt.get("error"):
            try:
                vt_stats = vt["data"]["attributes"]["last_analysis_stats"]
                vt_malicious = int(vt_stats.get("malicious", 0))
            except Exception:
                vt_malicious = 0

        whois_norm = min(max(whois_risk_score / 10.0, 0.0), 1.0)
        vt_norm = 1.0 if vt_malicious >= 1 else 0.0

        risk_score = 0.50 * phishing_prob + 0.25 * url_phish_prob + 0.15 * whois_norm + 0.10 * vt_norm

        if risk_score >= 0.75 or vt_malicious >= 3:
            verdict, color = "High Risk", "🔴"
        elif risk_score >= 0.45 or vt_malicious >= 1:
            verdict, color = "Medium Risk", "🟠"
        else:
            verdict, color = "Low Risk", "🟢"

        reasons = [
            f"email_phishing_prob={phishing_prob:.2f}",
            f"url_phishing_prob={url_phish_prob:.2f}",
            f"whois_risk_score={whois_risk_score:.2f}",
            f"vt_malicious={vt_malicious}",
        ]

        return {
            "verdict": verdict,
            "icon": color,
            "risk_score": round(risk_score, 3),
            "signals": {
                "email_phishing_prob": phishing_prob,
                "url_phishing_prob": url_phish_prob,
                "whois_risk_score": whois_risk_score,
                "vt_malicious": vt_malicious,
            },
            "reasons": reasons,
        }
