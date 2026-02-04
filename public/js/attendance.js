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
    Swal.fire({
      icon: 'warning',
      title: 'QR Code Required',
      text: 'Please scan the QR code first.'
    });
    return;
  }
  if (!navigator.geolocation) {
    Swal.fire({
      icon: 'error',
      title: 'Geolocation Error',
      text: 'Geolocation is not supported by this browser.'
    });
    return;
  }
  // Show loading state immediately because GPS can take time
  Swal.fire({
    title: 'Locating...',
    text: 'Acquiring high-accuracy GPS position. Please wait up to 30 seconds.',
    allowOutsideClick: false,
    didOpen: () => {
      Swal.showLoading();
    }
  });

  navigator.geolocation.getCurrentPosition(async (pos) => {
    // Update status to "Processing"
    Swal.update({
      title: 'Processing...',
      text: 'Sending data to server...'
    });

    const lat = pos.coords.latitude;
    const lng = pos.coords.longitude;
    const accuracy = pos.coords.accuracy;

    try {
      const r = await postAction(action, qrToken, lat, lng, accuracy);
      if (r.error) {
        Swal.fire({
          icon: 'error',
          title: 'Action Failed',
          text: r.error
        });
      } else {
        // Success
        Swal.fire({
          icon: 'success',
          title: 'Success!',
          timer: 1500,
          showConfirmButton: false
        }).then(() => {
          location.reload();
        });
      }
    } catch (err) {
      Swal.fire({
        icon: 'error',
        title: 'Network Error',
        text: err.message
      });
    }
  }, (err) => {
    Swal.fire({
      icon: 'error',
      title: 'Geolocation Error',
      text: err.message + '. Ensure GPS is enabled.'
    });
  }, { enableHighAccuracy: true, timeout: 30000, maximumAge: 0 });
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
    Swal.fire({
      icon: 'error',
      title: 'Camera Error',
      text: e.message
    });
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


// Geofence & Auto Checkout logic
let watchId = null;

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000; // meters
  const toRad = v => v * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function startGeofenceMonitor() {
  if (watchId !== null) return; // already watching
  if (!navigator.geolocation) return;

  console.log("Starting geofence monitor...");
  const office = window.OFFICE_CONFIG;
  if (!office) return;

  watchId = navigator.geolocation.watchPosition(async (pos) => {
    const lat = pos.coords.latitude;
    const lng = pos.coords.longitude;
    const dist = calculateDistance(lat, lng, office.lat, office.lng);

    // console.log(`Distance: ${dist.toFixed(1)} m. User Status: ${window.USER_STATUS}`);

    // Auto-checkout Safe Buffer
    // GPS Drift can cause "jumps". We shouldn't kick user out for small drifts.
    // We only auto-checkout if they are SIGNIFICANTLY far away (e.g., > 200m OR 5x radius).
    const safeDistance = Math.max(office.radius * 5, 200);

    if (window.USER_STATUS === 'working' && dist > safeDistance) {
      console.log(`User outside safe buffer (${Math.round(dist)}m > ${safeDistance}m)! Attempting auto check-out...`);
      const token = getCurrentQR();
      if (token) {
        // Stop watching to prevent loops
        navigator.geolocation.clearWatch(watchId);
        watchId = null;

        // Auto check-out
        try {
          const res = await postAction('check-out', token, lat, lng, pos.coords.accuracy);
          if (!res.error) {
            Swal.fire({
              icon: 'info',
              title: 'Auto Checked Out',
              text: 'You have been automatically checked out because you left the office area.',
              timer: 3000,
              showConfirmButton: false
            }).then(() => {
              location.reload();
            });
          } else {
            console.error("Auto-checkout failed:", res.error);
            // Resume watching? Or just let it be.
          }
        } catch (e) {
          console.error(e);
        }
      }
    }
  }, (err) => {
    console.warn("Geofence monitor error:", err);
  }, {
    enableHighAccuracy: true,
    maximumAge: 10000,
    timeout: 10000
  });
}

function stopGeofenceMonitor() {
  if (watchId !== null) {
    navigator.geolocation.clearWatch(watchId);
    watchId = null;
  }
}

// UI Locking (Prevent Refresh/Close)
function setupUILock() {
  const status = window.USER_STATUS;
  // window.addEventListener('beforeunload') removed as per user request


  // Geofence only if working (User didn't ask for auto-check-in/out on break, just logout prevention)
  // But usually break is taken onsite, so maybe we keep it off to avoid accidental check-outs while grabbing lunch nearby
  if (status === 'working') {
    startGeofenceMonitor();
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  updateUI();
  setupUILock();
});

window.doGeolocatedAction = doGeolocatedAction;
window.startQRScanner = startQRScanner;
window.getCurrentQR = () => getStoredQR() || currentQRToken;

