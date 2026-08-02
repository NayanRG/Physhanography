from fastapi import FastAPI, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
import requests

app = FastAPI()

# Allow frontend (HTML/JS) to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. Phishing Detection ---
@app.post("/api/phishing")
async def phishing_scan(url: str = Form(...)):
    # Example: call VirusTotal API (replace with your API key)
    api_key = "YOUR_API_KEY"
    headers = {"x-apikey": api_key}
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data={"url": url},
        headers=headers
    )
    return response.json()

# --- 2. Steganography Decoder ---
@app.post("/api/decode")
async def decode_image(image: UploadFile):
    # Placeholder: just return filename
    # Later: integrate with stegano or pillow
    return {"message": f"Decoded hidden data from {image.filename}"}

# --- 3. File Scanner ---
@app.post("/api/scan")
async def scan_file(file: UploadFile):
    # Placeholder: simulate scanning
    content = await file.read()
    size_kb = round(len(content) / 1024, 2)
    return {"status": f"File {file.filename} scanned successfully, size {size_kb} KB"}
