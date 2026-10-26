import logging
import traceback
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.database import init_db
from app.ml.model_manager import init_model_manager
from app.routers import scan, feedback, history

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threat_scanner")

app = FastAPI(title="Malicious Content Detection System", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Without this, any unhandled exception becomes a bare 500 with zero
    detail in the browser, making it impossible to tell what actually broke.
    This logs the FULL traceback to the backend terminal (check there first
    whenever you see "Server returned 500") and also returns the error
    message itself in the response so the frontend can show something
    more useful than just a status code.
    """
    tb = traceback.format_exc()
    logger.error(f"Unhandled exception on {request.method} {request.url.path}:\n{tb}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"{type(exc).__name__}: {exc}"},
    )


@app.on_event("startup")
def startup():
    init_db()
    init_model_manager()  # raises a clear error here if models haven't been trained yet


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(scan.router)
app.include_router(feedback.router)
app.include_router(history.router)
