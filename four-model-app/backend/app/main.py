from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os, traceback

from .pipeline import UnifiedPipeline

app = FastAPI(title="Four-Model Orchestrator — Phishing", version="3.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = UnifiedPipeline(
    hf_model_1=os.getenv("HF_MODEL_1", "ElSlay/BERT-Phishing-Email-Model"),
    hf_model_2=os.getenv("HF_MODEL_2"),  # optional summarizer; leave empty to disable
    vt_api_key=os.getenv("VT_API_KEY"),
)

class InferenceRequest(BaseModel):
    text: str
    url: Optional[str] = None

class InferenceResponse(BaseModel):
    input: Dict[str, Any]
    outputs: Dict[str, Any]
    verdict: Dict[str, Any]

@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}

@app.post("/infer", response_model=InferenceResponse)
def infer(req: InferenceRequest) -> InferenceResponse:
    try:
        outputs = pipeline.run_all(req.text, req.url)
        verdict = pipeline.aggregate(outputs)
        return InferenceResponse(input=req.model_dump(), outputs=outputs, verdict=verdict)
    except Exception as e:
        print("ERROR in /infer:\n", traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
