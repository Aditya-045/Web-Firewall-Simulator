from pydantic import BaseModel
from typing import Optional, List


class UrlScanRequest(BaseModel):
    url: str


class TextScanRequest(BaseModel):
    text: str


class ApiScanRequest(BaseModel):
    call_sequence: str


class ScanResponse(BaseModel):
    scan_id: int
    content_type: str
    input_value: str
    verdict: str
    ml_confidence: float
    final_confidence: float
    detection_path: str
    heuristic_reasons: List[str] = []
    source_metadata: Optional[dict] = None


class FeedbackRequest(BaseModel):
    scan_id: int
    confirmed_label: int  # 1 = malicious, 0 = safe
