// IMPORTANT: index.html is served by Live Server (port 5501), but the API
// runs as a separate process (uvicorn, default port 8000). They are two
// different servers -- relative paths like "/api/..." would hit Live Server,
// not this backend. Point explicitly at wherever `uvicorn main:app` is running.
const API_BASE = "";
// Safely parse a fetch Response as JSON, with a clear error if the body
// is empty/HTML/not JSON at all (e.g. wrong port, backend not running,
// or a proxy/dev-server intercepting the request instead of the API).
async function safeJson(response) {
  const text = await response.text();
  if (!text) {
    throw new Error(
      `Empty response from ${response.url} (status ${response.status}). ` +
      `Is the backend running at ${API_BASE}? (uvicorn main:app --reload --port 8000)`
    );
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Backend did not return JSON (got: "${text.slice(0, 80)}...")`);
  }
}

// Ping the backend on page load and show a status banner
async function checkBackendStatus() {
  const el = document.getElementById("backendStatus");
  if (!el) return;
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    const data = await safeJson(res);
    el.innerText = data.vt_key_configured
      ? "🟢 Backend connected"
      : "🟡 Backend connected, but VT_API_KEY is not set in .env";
    el.className = data.vt_key_configured ? "status ok" : "status warn";
  } catch (err) {
    el.innerText = `🔴 Can't reach backend at ${API_BASE} — start it with: uvicorn main:app --reload --port 8000`;
    el.className = "status error";
  }
}

document.addEventListener("DOMContentLoaded", checkBackendStatus);

// Poll VirusTotal analysis until it's done (or we give up)
async function pollAnalysis(analysisId, resultEl, { attempts = 20, delayMs = 3000 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const res = await fetch(`${API_BASE}/api/analysis/${analysisId}`);
    const data = await safeJson(res);

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
    resultEl.innerText = `Scanning... (status: ${data.status || "queued"}, ${i + 1}/${attempts})`;
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
    const data = await safeJson(response);
    if (!response.ok) throw new Error(data.detail || "Request failed");
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
    const data = await safeJson(response);
    if (!response.ok) throw new Error(data.detail || "Request failed");
    await pollAnalysis(data.analysis_id, resultEl);
  } catch (err) {
    resultEl.innerText = `Error: ${err.message}`;
  }
}

async function decodeImage() {
  const file = document.getElementById("imageInput").files[0];
  const key = document.getElementById("decodeKey").value;
  const resultEl = document.getElementById("decodeResult");
  if (!file) {
    resultEl.innerText = "Please choose an image.";
    return;
  }
  resultEl.innerText = "Decoding...";

  const formData = new FormData();
  formData.append("image", file);
  if (key) formData.append("key", key);

  try {
    const response = await fetch(`${API_BASE}/api/decode`, { method: "POST", body: formData });
    const data = await safeJson(response);
    if (!response.ok) throw new Error(data.detail || "Request failed");
    resultEl.innerText = data.message ? `Hidden message: ${data.message}` : (data.note || "No message found.");
  } catch (err) {
    resultEl.innerText = `Error: ${err.message}`;
  }
}

async function encodeImage() {
  const file = document.getElementById("encodeImageInput").files[0];
  const message = document.getElementById("secretMessage").value;
  const key = document.getElementById("encodeKey").value;
  const resultEl = document.getElementById("encodeResult");
  if (!file || !message) {
    resultEl.innerText = "Please choose an image and enter a message.";
    return;
  }
  resultEl.innerText = "Encoding...";

  const formData = new FormData();
  formData.append("image", file);
  formData.append("message", message);
  if (key) formData.append("key", key);

  try {
    const response = await fetch(`${API_BASE}/api/encode`, { method: "POST", body: formData });
    if (!response.ok) {
      const data = await safeJson(response);
      throw new Error(data.detail || "Request failed");
    }
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