# Attendance Geospatial (Minimal Scaffold)

What this scaffold includes:
- Node.js + Express server with EJS views
- MongoDB models (User, Attendance, QRToken)
- Google OAuth sign-in scaffold (passport)
- Admin dashboard (create users, generate QR)
- User side: QR scanning (jsQR), geolocation-based attendance actions
- Basic geofence check using OFFICE_LAT, OFFICE_LNG, OFFICE_RADIUS_METERS env vars
- Uses Bootstrap 5 for styling

Steps to run:
1. Copy `.env.example` to `.env` and fill values (Google OAuth credentials required).
2. `npm install`
3. `npm start`
4. Open `http://localhost:3000`

Notes:
- This is a starting point. Security hardening, validation, role management, UI polish, and production readiness are not fully implemented here.
- QR is generated per day.
