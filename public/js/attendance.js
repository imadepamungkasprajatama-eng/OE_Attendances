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
let videoStream = null;
let isScanning = false;

async function startQRScanner() {
  if (isScanning) return;
  const out = document.getElementById('qr-result');
  const container = document.getElementById('qr-reader-container');

  if (out) out.innerText = "Requesting camera...";

  try {
    videoStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    isScanning = true;

    // Create video element
    const video = document.createElement('video');
    video.srcObject = videoStream;
    video.setAttribute("playsinline", true);
    video.style.width = "100%";
    video.style.height = "100%";
    video.style.objectFit = "cover";
    await video.play();

    // Clear container and append video
    if (container) {
      container.innerHTML = '';
      container.appendChild(video);
    }

    const tick = () => {
      if (!isScanning) return;
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        if (out) out.innerText = "Scanning...";

        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: "dontInvert",
        });

        if (code) {
          console.log("Found QR code", code.data);
          currentQRToken = code.data;

          saveQR(currentQRToken);
          updateUI();

          if (out) {
            out.innerText = "QR Detected!";
            out.classList.add("bg-success", "text-white");
          }

          // Auto close modal
          const modalEl = document.getElementById('qrScannerModal');
          if (modalEl) {
            const closeBtn = modalEl.querySelector('.btn-close');
            if (closeBtn) closeBtn.click();
          } else {
            stopQRScanner();
          }
        } else {
          requestAnimationFrame(tick);
        }
      } else {
        requestAnimationFrame(tick);
      }
    };
    requestAnimationFrame(tick);
  } catch (e) {
    console.error(e);
    if (out) out.innerText = "Camera error: " + e.message;
    alert('Camera error: ' + e.message);
  }
}

window.stopQRScanner = function () {
  isScanning = false;
  if (videoStream) {
    videoStream.getTracks().forEach(track => track.stop());
    videoStream = null;
  }
  const container = document.getElementById('qr-reader-container');
  if (container) container.innerHTML = '';

  const out = document.getElementById('qr-result');
  if (out) {
    out.innerText = "Camera stopped.";
    out.classList.remove("bg-success", "text-white");
  }
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  updateUI();
});

window.doGeolocatedAction = doGeolocatedAction;
window.startQRScanner = startQRScanner;
window.getCurrentQR = () => getStoredQR() || currentQRToken;
