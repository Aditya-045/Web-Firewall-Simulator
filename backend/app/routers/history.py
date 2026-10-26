from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db, ScanResult

router = APIRouter(prefix="/history", tags=["history"])


@router.get("")
def get_history(limit: int = 25, db: Session = Depends(get_db)):
    rows = (
        db.query(ScanResult)
        .order_by(desc(ScanResult.timestamp))
        .limit(limit)
        .all()
    )
    return [
        {
            "scan_id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "content_type": r.content_type,
            "input_value": r.input_value[:200],
            "verdict": r.final_verdict,
            "final_confidence": r.final_confidence,
            "confirmed_label": r.confirmed_label,
        }
        for r in rows
    ]
