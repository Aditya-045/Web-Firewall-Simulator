"""
routers/scan.py -- URL and text scanning endpoints.
"""
import json
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db, ScanResult
from app.schemas import UrlScanRequest, TextScanRequest, ScanResponse
from app.ml.model_manager import get_model_manager

router = APIRouter(prefix="/scan", tags=["scan"])


def _persist_and_respond(
    db: Session,
    content_type: str,
    input_value: str,
    prediction: dict,
    source_metadata: Optional[dict],
) -> ScanResponse:
    row = ScanResult(
        content_type=content_type,
        input_value=input_value,
        ml_confidence=prediction["ml_confidence"],
        ml_used=prediction["detection_path"],
        final_verdict=prediction["verdict"],
        final_confidence=prediction["final_confidence"],
        metadata_json=json.dumps(source_metadata) if source_metadata else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return ScanResponse(
        scan_id=row.id,
        content_type=content_type,
        input_value=input_value,
        verdict=prediction["verdict"],
        ml_confidence=prediction["ml_confidence"],
        final_confidence=prediction["final_confidence"],
        detection_path=prediction["detection_path"],
        heuristic_reasons=prediction["heuristic_reasons"],
        source_metadata=source_metadata,
        timestamp=row.timestamp,
    )


@router.post("/url", response_model=ScanResponse)
def scan_url(payload: UrlScanRequest, db: Session = Depends(get_db)):
    prediction = get_model_manager().predict_url(payload.url)
    # network_details (DNS, TLS, redirects, DNSBL, WHOIS, domain age,
    # Punycode, port -- see network_checks.py) already IS the richer
    # superset of what a separate get_source_metadata() call would have
    # produced, so it's used directly as source_metadata here rather than
    # looking the same domain up a second time.
    source_metadata = prediction.pop("network_details", None)
    return _persist_and_respond(db, "url", payload.url, prediction, source_metadata)


@router.post("/text", response_model=ScanResponse)
def scan_text(payload: TextScanRequest, db: Session = Depends(get_db)):
    prediction = get_model_manager().predict_text(payload.text)
    return _persist_and_respond(db, "text", payload.text, prediction, None)
