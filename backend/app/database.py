import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "app.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    content_type = Column(String)       # "url" | "text"
    input_value = Column(Text)
    ml_confidence = Column(Float)       # 0..1 probability of malicious, from ML model
    ml_used = Column(String)            # "ml" | "heuristic_fallback"
    final_verdict = Column(String)      # "malicious" | "safe" | "unknown"
    final_confidence = Column(Float)    # 0..1
    metadata_json = Column(Text, nullable=True)  # DNS/WHOIS info as JSON, url only
    confirmed_label = Column(Integer, nullable=True)  # user feedback: 1 malicious, 0 safe, null=no feedback
    used_in_retrain = Column(Integer, default=0)


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
