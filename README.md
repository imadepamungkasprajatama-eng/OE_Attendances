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
- QR is generated per day. Admin can re-generate.

1. admin account harus .env yaitu: config, dbconnection, csv
2. tambah control admin account di dashboard: with CRUD
3. QR dibuat admin dan akan di reset setiap 23.59 PM UTC(device loc) 
4. tambahkan waktu kerja + waktu break
5. tambahkan anti fake location (https://github.com/jpudysz/react-native-turbo-mock-location-detector)
6. pastikan QR hanya bisa check-in (tombol abu2 sebelum scan QR)
7. tambahkan fitur untuk admin dan HR ekspor data kehadiran semuanya
8. tambah divisi untuk spv dan staff, spv bisa melihat jam kerja staff divisi masing2, staff bisa melihat jam kerja pribadi
9. tambahan filter staff untuk admin dan HR berisi nama, divisi, jam check-in,out, jumlah total jam break, indikasi centang silang
10. QR tambahan link login
11. 