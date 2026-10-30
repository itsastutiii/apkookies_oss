from fastapi import FastAPI, UploadFile, File
from pathlib import Path
from dataclasses import asdict
import tempfile

from backend.static_analysis import run as run_static
from backend.scoring import risk_score

app = FastAPI(title="APKookies ML API")


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):

    suffix = Path(file.filename or "received.apk").suffix

    with tempfile.NamedTemporaryFile(
        suffix=suffix,
        delete=False
    ) as tmp:

        apk_path = Path(tmp.name)

        while chunk := await file.read(1024 * 1024):
            tmp.write(chunk)

    try:
        print(f"Received APK: {file.filename}")
        print(f"Running static analysis: {apk_path}")

        bundle = run_static(str(apk_path))

        print("Static analysis complete")

        result = risk_score.score_static(bundle)

        print("ML/scoring complete")

        return {
            "filename": file.filename,
            "result": asdict(result)
        }

    finally:
        apk_path.unlink(missing_ok=True)