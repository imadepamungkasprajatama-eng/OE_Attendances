/* Client-side code to:
 - get location
 - scan QR using camera (jsQR)
 - send attendance action to server
*/
async function postAction(action, qrToken, lat, lng, accuracy) {
  const res = await fetch('/attendance/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, qrToken, lat, lng, accuracy })
  });
  return res.json();
}

async function doGeolocatedAction(action, qrToken) {
  if (!qrToken) {
    alert('QR token required. Scan QR first.');
    return;
  }
  if (!navigator.geolocation) {
    alert('Geolocation not supported.');
    return;
  }
  navigator.geolocation.getCurrentPosition(async (pos) => {
    const lat = pos.coords.latitude;
    const lng = pos.coords.longitude;
    const accuracy = pos.coords.accuracy;
    const r = await postAction(action, qrToken, lat, lng, accuracy);
    if (r.error) alert('Error: ' + r.error);
    else alert('Success: ' + action);
    location.reload();
  }, (err) => alert('Geolocation error: ' + err.message), { enableHighAccuracy: true });
}

// QR Persistance + UI Locking

function getTodayString() {
  const d = new Date();
  // YYYY-MM-DD
  return d.toISOString().split('T')[0];
}

function saveQR(token) {
  const data = {
    token: token,
    date: getTodayString()
  };
  localStorage.setItem('attendance_qr', JSON.stringify(data));
  currentQRToken = token;
}

function getStoredQR() {
  const raw = localStorage.getItem('attendance_qr');
  if (!raw) return null;
  try {
    const data = JSON.parse(raw);
    if (data.date === getTodayString()) {
      return data.token;
    } else {
      // Expired (yesterday)
      localStorage.removeItem('attendance_qr');
      return null;
    }
  } catch (e) {
    return null;
  }
}

function updateUI() {
  const storedToken = getStoredQR();
  currentQRToken = storedToken;

  const btnIds = ['btn-check-in', 'btn-check-out', 'btn-break-start', 'btn-break-end'];
  const out = document.getElementById('qr-result');

  if (currentQRToken) {
    // Enable buttons
    btnIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = false;
    });
    if (out) out.innerText = 'QR Ready (Saved): ' + currentQRToken.slice(0, 15) + '...';
  } else {
    // Disable buttons
    btnIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = true;
    });
    if (out) out.innerText = 'Please scan QR to enable actions.';
  }
}

// QR scanning using camera + jsQR
let currentQRToken = null;
async function startQRScanner() {
  const video = document.createElement('video');
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const out = document.getElementById('qr-result');
  const btn = document.getElementById('start-scan');
  btn.disabled = true;
  document.body.appendChild(video);
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    video.srcObject = stream;
    await video.play();
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    const tick = () => {
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        // jsQR is loaded from CDN in the page
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code) {
          // assume payload is token string
          currentQRToken = code.data;

          // SAVE IT
          saveQR(currentQRToken);
          updateUI(); // Update UI immediately

          // out.innerText = 'Scanned QR token: ' + currentQRToken; <-- handled by updateUI
          stream.getTracks().forEach(t => t.stop());
          video.remove();
          canvas.remove();
          btn.disabled = false;
          return;
        }
      }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  } catch (e) {
    alert('Camera error: ' + e.message);
    btn.disabled = false;
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  updateUI();
});

window.doGeolocatedAction = doGeolocatedAction;
window.startQRScanner = startQRScanner;
window.getCurrentQR = () => getStoredQR() || currentQRToken;
