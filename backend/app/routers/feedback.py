"""
routers/feedback.py -- online-learning feedback endpoint (POST /feedback).

Drives the "Confirm malicious / Confirm safe" buttons in the UI
(FeedbackButtons.jsx). Looks up the original scan by scan_id, then calls
.partial_fit() on the matching live model via model_manager, and persists
the updated model back to disk immediately.

Only url/text scans are retrainable -- the api_model retrain path has
been removed along with the rest of the (out-of-scope) API call-sequence
detector.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db, ScanResult
from app.schemas import FeedbackRequest
from app.ml.model_manager import get_model_manager

router = APIRouter(tags=["feedback"])


@router.post("/feedback")
def submit_feedback(payload: FeedbackRequest, db: Session = Depends(get_db)):
    row = db.query(ScanResult).filter(ScanResult.id == payload.scan_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Scan {payload.scan_id} not found.")

    row.confirmed_label = payload.confirmed_label

    if row.content_type == "url":
        get_model_manager().retrain_url(row.input_value, payload.confirmed_label)
    elif row.content_type == "text":
        get_model_manager().retrain_text(row.input_value, payload.confirmed_label)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown content_type '{row.content_type}' -- cannot retrain.",
        )

    row.used_in_retrain = 1
    db.commit()

    return {"status": "ok", "scan_id": row.id, "content_type": row.content_type}
