import base64
import hashlib
import io
import os

import requests
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.responses import FileResponse
from PIL import Image

# Load environment variables from a .env file
load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
# VirusTotal's standard /files endpoint rejects anything over 32MB.
# Anything bigger needs a special one-time upload URL instead.
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024  # 32 MB

STEG_DELIMITER = "#####END#####"


def _derive_fernet_key(passphrase: str) -> bytes:
    """Turn any user-supplied passphrase into a valid 32-byte urlsafe-base64
    Fernet key (AES-128-CBC + HMAC under the hood) via SHA-256."""
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


app = FastAPI()

@app.get("/")
async def home():
    return FileResponse("index.html")

@app.get("/style.css")
async def css():
    return FileResponse("style.css")

@app.get("/script.js")
async def js():
    return FileResponse("script.js")


# Allow frontend (HTML/JS) to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _vt_headers():
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="VT_API_KEY is not set. Add it to your .env file.",
        )
    return {"accept": "application/json", "x-apikey": API_KEY}


@app.get("/api/health")
async def health():
    """Lets the frontend confirm it's actually talking to this backend."""
    return {"status": "ok", "vt_key_configured": bool(API_KEY)}


# --- 1. Phishing / URL Detection ---
@app.post("/api/phishing")
async def phishing_scan(url: str = Form(...)):
    """Submit a URL to VirusTotal for analysis. Returns an analysis_id to poll."""
    headers = _vt_headers()
    try:
        response = requests.post(
            f"{VT_BASE}/urls",
            data={"url": url},
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        return {"status": "success", "analysis_id": data["data"]["id"]}
    except requests.exceptions.HTTPError as e:
        print(e.response.status_code)
        print(e.response.text)
        raise HTTPException(
            status_code=e.response.status_code,
            detail=e.response.text
        )
# --- 2. File Scanner (VirusTotal) ---
@app.post("/api/scan")
async def scan_file(file: UploadFile):
    """Upload a file (any type) to VirusTotal for malware scanning.
    Automatically handles files >32MB via VirusTotal's special upload URL.
    """
    #Auth check + read the file into memory
    headers = _vt_headers()
    content = await file.read()
    size = len(content)

    #Most browsers don't have .eml registered in their MIME database, so
    #file.content_type arrives as "" or "application/octet-stream". VirusTotal
    #then receives a blank/unreliable Content-Type and rejects the upload.
    #Force the correct type by extension so .eml (raw email) files scan
    #the same way any other file type does.
    content_type = file.content_type
    filename = file.filename or ""
    if filename.lower().endswith(".eml") and not content_type:
        content_type = "message/rfc822"

    try:
        if size <= DIRECT_UPLOAD_LIMIT:
            upload_endpoint = f"{VT_BASE}/files"
        else:
            # Get a one-time URL that accepts files up to 650MB
            url_resp = requests.get(f"{VT_BASE}/files/upload_url", headers=headers)
            url_resp.raise_for_status()
            upload_endpoint = url_resp.json()["data"]

        response = requests.post(
            upload_endpoint,
            headers=headers,
            files={"file": (file.filename, content, content_type)},
        )
        response.raise_for_status()
        vt_data = response.json()

        return {
            "status": "success",
            "message": "File submitted successfully",
            "filename": file.filename,
            "size_kb": round(size / 1024, 2),
            "analysis_id": vt_data["data"]["id"],
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


# --- 3. Shared analysis result lookup (works for both file & URL scans) ---
@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    headers = _vt_headers()
    try:
        response = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        return {
            "status": attributes.get("status"),  # "queued" | "completed"
            "stats": attributes.get("stats", {}),  # malicious/suspicious/harmless/undetected counts
        }
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


# --- 4. Steganography: hide a message inside an image (LSB encoding) ---
@app.post("/api/encode")
async def encode_image(image: UploadFile, message: str = Form(...), key: str = Form(None)):

    #read the image and gets raw pixel list
    raw = await image.read()
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    pixels = list(img.getdata())

    #If a passphrase was supplied, AES-encrypt the message first (Fernet =
    #AES-128-CBC + HMAC). The resulting token is itself ASCII-safe (urlsafe
    #base64), so it can be embedded with the exact same bit-writer below.
    #Without a key, behavior is unchanged -- the plain message is hidden.
    payload_text = message
    if key:
        fernet = Fernet(_derive_fernet_key(key))
        payload_text = fernet.encrypt(message.encode("utf-8")).decode("ascii")

    #Turn the (possibly encrypted) message into a bitstream
    payload = payload_text + STEG_DELIMITER
    bits = "".join(format(ord(c), "08b") for c in payload)

    #Capacity check
    if len(bits) > len(pixels) * 3:     #3 usable bits per pixel (1 per channel). A 100×100 image = 30,000 bits ≈ 3,750 characters max.
        raise HTTPException(
            status_code=400,
            detail="Message too long to hide in this image. Use a larger image or shorter message.",
        )

    #Overwrite the LSB of each channel
    new_pixels = []
    idx = 0
    for r, g, b in pixels:
        if idx < len(bits):
            r = (r & ~1) | int(bits[idx]); idx += 1
        if idx < len(bits):
            g = (g & ~1) | int(bits[idx]); idx += 1
        if idx < len(bits):
            b = (b & ~1) | int(bits[idx]); idx += 1
        new_pixels.append((r, g, b))

    #Save as PNG and stream it back
    img.putdata(new_pixels)
    buf = io.BytesIO()
    img.save(buf, format="PNG")  # PNG only -- JPEG compression destroys hidden bits
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="image/png",
        headers={"Content-Disposition": "attachment; filename=encoded.png"},
    )


# --- 5. Steganography: extract a hidden message from an image ---
@app.post("/api/decode")
async def decode_image(image: UploadFile, key: str = Form(None)):

    #Pull the LSB out of every channel
    raw = await image.read()
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    pixels = list(img.getdata())

    bits = []
    for r, g, b in pixels:
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))
    bits = "".join(bits)

    #Rebuild characters 8 bits at a time, watching for the delimiter
    chars = []
    extracted = ""
    for i in range(0, len(bits) - 7, 8):
        byte = bits[i:i + 8]
        chars.append(chr(int(byte, 2)))
        extracted = "".join(chars)
        if extracted.endswith(STEG_DELIMITER):
            payload_text = extracted[: -len(STEG_DELIMITER)]

            #If a passphrase was supplied, treat the payload as a Fernet
            #token and decrypt it; wrong/missing key -> clear error instead
            #of returning garbled ciphertext.
            if key:
                try:
                    fernet = Fernet(_derive_fernet_key(key))
                    plain = fernet.decrypt(payload_text.encode("ascii")).decode("utf-8")
                    return {"message": plain}
                except (InvalidToken, ValueError):
                    raise HTTPException(
                        status_code=400,
                        detail="Could not decrypt -- wrong key, or this image wasn't encrypted.",
                    )

            return {"message": payload_text}

    #Fallback if the delimiter never shows up
    return {"message": None, "note": "No hidden message found in this image."}

#runs uvicorn main:app --reload --port 8000
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)