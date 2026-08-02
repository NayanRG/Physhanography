async function checkPhishing() {
  const url = document.getElementById('urlInput').value;
  document.getElementById('phishingResult').innerText = 'Checking...';
  // Replace with your backend endpoint
  const response = await fetch('/api/phishing', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  const data = await response.json();
  document.getElementById('phishingResult').innerText = JSON.stringify(data, null, 2);
}

async function decodeImage() {
  const file = document.getElementById('imageInput').files[0];
  document.getElementById('decodeResult').innerText = 'Decoding...';
  const formData = new FormData();
  formData.append('image', file);
  const response = await fetch('/api/decode', { method: 'POST', body: formData });
  const data = await response.json();
  document.getElementById('decodeResult').innerText = data.message || 'Decoded successfully!';
}

async function scanFile() {
  const file = document.getElementById('fileInput').files[0];
  document.getElementById('fileResult').innerText = 'Scanning...';
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch('/api/scan', { method: 'POST', body: formData });
  const data = await response.json();
  document.getElementById('fileResult').innerText = data.status || 'Scan complete!';
}
