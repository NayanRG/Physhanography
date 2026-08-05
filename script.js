const API_BASE = ""; // same-origin; set to your backend URL if hosted separately

// Poll VirusTotal analysis until it's done (or we give up)
async function pollAnalysis(analysisId, resultEl, { attempts = 10, delayMs = 3000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(`${API_BASE}/api/analysis/${analysisId}`);
    const data = await res.json();

    if (data.status === "completed") {
      const s = data.stats || {};
      const verdict = s.malicious > 0
        ? `⚠️ MALICIOUS (${s.malicious} engines flagged it)`
        : s.suspicious > 0
        ? `⚠️ SUSPICIOUS (${s.suspicious} engines flagged it)`
        : "✅ Clean";
      resultEl.innerText =
        `${verdict}\nmalicious: ${s.malicious ?? 0}, suspicious: ${s.suspicious ?? 0}, ` +
        `harmless: ${s.harmless ?? 0}, undetected: ${s.undetected ?? 0}`;
      return;
    }
    resultEl.innerText = `Scanning... (status: ${data.status || "queued"})`;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  resultEl.innerText = "Scan is taking longer than expected. Check back later.";
}

async function checkPhishing() {
  const url = document.getElementById("urlInput").value;
  const resultEl = document.getElementById("phishingResult");
  if (!url) {
    resultEl.innerText = "Please enter a URL.";
    return;
  }
  resultEl.innerText = "Submitting...";

  const formData = new FormData();
  formData.append("url", url);

  try {
    const response = await fetch(`${API_BASE}/api/phishing`, {
      method: "POST",
      body: formData, // NOTE: must be form data, not JSON -- matches FastAPI's Form(...) param
    });
    if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
    const data = await response.json();
    await pollAnalysis(data.analysis_id, resultEl);
  } catch (err) {
    resultEl.innerText = `Error: ${err.message}`;
  }
}

async function scanFile() {
  const file = document.getElementById("fileInput").files[0];
  const resultEl = document.getElementById("fileResult");
  if (!file) {
    resultEl.innerText = "Please choose a file.";
    return;
  }
  resultEl.innerText = "Uploading...";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE}/api/scan`, { method: "POST", body: formData });
    if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
    const data = await response.json();
    await pollAnalysis(data.analysis_id, resultEl);
  } catch (err) {
    resultEl.innerText = `Error: ${err.message}`;
  }
}

async function decodeImage() {
  const file = document.getElementById("imageInput").files[0];
  const resultEl = document.getElementById("decodeResult");
  if (!file) {
    resultEl.innerText = "Please choose an image.";
    return;
  }
  resultEl.innerText = "Decoding...";

  const formData = new FormData();
  formData.append("image", file);

  try {
    const response = await fetch(`${API_BASE}/api/decode`, { method: "POST", body: formData });
    const data = await response.json();
    resultEl.innerText = data.message ? `Hidden message: ${data.message}` : (data.note || "No message found.");
  } catch (err) {
    resultEl.innerText = `Error: ${err.message}`;
  }
}

async function encodeImage() {
  const file = document.getElementById("encodeImageInput").files[0];
  const message = document.getElementById("secretMessage").value;
  const resultEl = document.getElementById("encodeResult");
  if (!file || !message) {
    resultEl.innerText = "Please choose an image and enter a message.";
    return;
  }
  resultEl.innerText = "Encoding...";

  const formData = new FormData();
  formData.append("image", file);
  formData.append("message", message);

  try {
    const response = await fetch(`${API_BASE}/api/encode`, { method: "POST", body: formData });
    if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
    const blob = await response.blob();
    const downloadUrl = URL.createObjectURL(blob);

    resultEl.innerHTML = "";
    const link = document.createElement("a");
    link.href = downloadUrl;
    link.download = "encoded.png";
    link.innerText = "✅ Download image with hidden message";
    resultEl.appendChild(link);
  } catch (err) {
    resultEl.innerText = `Error: ${err.message}`;
  }
}