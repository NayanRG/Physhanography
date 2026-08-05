import os

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

# Load environment variables from a .env file (see .env.example)
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")

app = FastAPI(title="Security Toolkit API")

# Allow frontend (HTML/JS) to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _require_api_key():
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="VT_API_KEY is not set. Add it to your .env file.",
        )


# --- 1. Phishing / URL Detection ---
@app.post("/api/phishing")
async def phishing_scan(url: str = Form(...)):
    """Submit a URL to VirusTotal for analysis."""
    _require_api_key()
    headers = {"accept": "application/json", "x-apikey": "349a69c4c35c531f052f18314ebac219aca9b62a76d0eb3ef4579a4067b14b47"}

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


# --- 2. Steganography Decoder ---
@app.post("/api/decode")
async def decode_image(image: UploadFile):
    # Placeholder: just return filename
    # TODO: integrate with `stegano` or `Pillow` for real extraction
    return {"message": f"Decoded hidden data from {image.filename}"}


# --- 3. File Scanner (VirusTotal) ---
@app.post("/api/scan")
async def scan_file(file: UploadFile):
    """Upload a file to VirusTotal for malware scanning."""
    _require_api_key()
    headers = {"accept": "application/json", "x-apikey": "349a69c4c35c531f052f18314ebac219aca9b62a76d0eb3ef4579a4067b14b47"}

    files = {"file": (file.filename, await file.read(), file.content_type)}

    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files,
        )
        response.raise_for_status()
        vt_data = response.json()

        return {
            "status": "success",
            "message": "File submitted successfully",
            "filename": file.filename,
            "analysis_id": vt_data["data"]["id"],
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)