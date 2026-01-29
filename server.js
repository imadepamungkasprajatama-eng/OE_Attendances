require('dotenv').config();
const XLSX = require('xlsx');
const ExcelJS = require('exceljs');
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const qrcode = require('qrcode');
const moment = require('moment');
moment.locale('id');
const bcrypt = require('bcrypt');

const User = require('./models/User');
const Attendance = require('./models/Attendance');
const QRToken = require('./models/QRToken');

const app = express();
// Trust proxy is required for Render/Heroku to correctly detect HTTPS
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI })
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID || 'GCLIENT',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'GSECRET',
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const allowed = (process.env.ALLOWED_ADMIN_EMAILS || '')
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);

    const email =
      profile.emails && profile.emails[0] && profile.emails[0].value;

    // 1) Cari berdasar googleId dulu
    let user = await User.findOne({ googleId: profile.id });

    if (!user) {
      // 2) Kalau belum ada, coba cari user yang sudah ada dengan email yang sama
      if (email) {
        const existingByEmail = await User.findOne({ email });
        if (existingByEmail) {
          existingByEmail.googleId = profile.id;   // LINK ke akun ini
          await existingByEmail.save();
          user = existingByEmail;
        }
      }

      // 3) Kalau tetap belum ada, baru buat user baru
      if (!user) {
        user = new User({
          googleId: profile.id,
          email,
          name: profile.displayName || email,
          role: allowed.includes(email) ? 'Admin' : 'Staff'
        });
        await user.save();
      }
    }

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));


passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const u = await User.findById(id);
    done(null, u);
  } catch (e) {
    done(e);
  }
});

// Middleware
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}
function ensureRole(role) {
  return (req, res, next) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    if (req.user.role === role || req.user.role === 'Admin') return next();
    return res.status(403).send('Forbidden');
  };
}

// ====== ROUTES ======

// HOME: Admin -> admin_dashboard, lainnya -> user_home
app.get('/', ensureAuth, async (req, res) => {
  // Admin dashboard
  if (req.user.role === 'Admin') {
    const users = await User.find();
    const token = await QRToken.getCurrent();
    return res.render('admin_dashboard', {
      user: req.user,
      users,
      token,
      moment,
      query: req.query
    });
  }

  // STAFF / SUPERVISOR / OM / GM -> user_home
  const token = await QRToken.getCurrent();

  // division members (untuk Supervisor / OM / GM)
  let divisionMembers = [];
  const managerRoles = ['Supervisor', 'Operational Manager', 'General Manager'];
  if (managerRoles.includes(req.user.role) && req.user.division) {
    divisionMembers = await User.find({ division: req.user.division }).sort({ name: 1 });
  }

  // Attendance hari ini
  const today = moment();
  const startOfDay = today.clone().startOf('day').toDate();
  const endOfDay = today.clone().endOf('day').toDate();

  const records = await Attendance.find({
    user: req.user._id,
    time: { $gte: startOfDay, $lte: endOfDay }
  }).sort({ time: 1 });

  let workSeconds = 0;
  let breakSeconds = 0;
  let lastCheckIn = null;
  let lastBreakStart = null;
  const workIntervals = [];
  const breakIntervals = [];

  records.forEach(r => {
    const t = r.time;
    if (r.action === 'check-in') {
      lastCheckIn = t;
    } else if (r.action === 'check-out') {
      if (lastCheckIn) {
        workSeconds += (t - lastCheckIn) / 1000;
        workIntervals.push({ start: lastCheckIn, end: t });
        lastCheckIn = null;
      }
    } else if (r.action === 'break-start') {
      if (lastCheckIn) {
        workSeconds += (t - lastCheckIn) / 1000;
        workIntervals.push({ start: lastCheckIn, end: t });
        lastCheckIn = null;
      }
      lastBreakStart = t;
    } else if (r.action === 'break-end') {
      if (lastBreakStart) {
        breakSeconds += (t - lastBreakStart) / 1000;
        breakIntervals.push({ start: lastBreakStart, end: t });
        lastBreakStart = null;
      }
      lastCheckIn = t;
    }
  });

  let status = 'idle';
  let currentWorkStart = null;
  let currentBreakStart = null;

  if (lastCheckIn) {
    status = 'working';
    currentWorkStart = lastCheckIn;
  } else if (lastBreakStart) {
    status = 'break';
    currentBreakStart = lastBreakStart;
  }

  function formatDuration(sec) {
    sec = Math.floor(sec);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    const pad = n => n.toString().padStart(2, '0');
    return `${pad(h)}:${pad(m)}:${pad(s)}`;
  }

  const attendanceSummary = {
    dateLabel: today.format('dddd, DD MMMM YYYY'),
    workText: formatDuration(workSeconds),
    breakText: formatDuration(breakSeconds),
    workIntervals: workIntervals.map(i => ({
      start: moment(i.start).format('HH:mm:ss'),
      end: moment(i.end).format('HH:mm:ss')
    })),
    breakIntervals: breakIntervals.map(i => ({
      start: moment(i.start).format('HH:mm:ss'),
      end: moment(i.end).format('HH:mm:ss')
    })),
    status,
    baseWorkSeconds: workSeconds,
    baseBreakSeconds: breakSeconds,
    currentWorkStart: currentWorkStart ? currentWorkStart.getTime() : null,
    currentBreakStart: currentBreakStart ? currentBreakStart.getTime() : null
  };

  return res.render('user_home', {
    user: req.user,
    token,
    moment,
    office: {
      lat: parseFloat(process.env.OFFICE_LAT || '0'),
      lng: parseFloat(process.env.OFFICE_LNG || '0'),
      radius: parseFloat(process.env.OFFICE_RADIUS_METERS || '100')
    },
    attendanceSummary,
    divisionMembers
  });
});

// SUPERVISOR / OM / GM DASHBOARD (bulanan + multi-divisi)
app.get('/supervisor', ensureAuth, async (req, res) => {
  try {
    const allowedRoles = ['Supervisor', 'Operational Manager', 'General Manager', 'Admin'];
    // Allow if role is in allowedRoles OR if user has explicit access
    if (!allowedRoles.includes(req.user.role) && !req.user.canAccessSupervisorDashboard) {
      return res.status(403).send('Forbidden');
    }

    const monthParam = req.query.month || moment().format('YYYY-MM'); // "YYYY-MM"

    // divisi yang di-manage user ini
    let managedDivisions = [];
    if (req.user.division) managedDivisions.push(req.user.division);
    if (req.user.secondaryDivision) managedDivisions.push(req.user.secondaryDivision);

    // Check for 'All Division' access
    if (managedDivisions.includes('All Division')) {
      managedDivisions = ['OC', 'N1', 'SnG', 'e1', 'CE', 'EC', 'PX', 'FN', 'HR'];
    }

    managedDivisions = [...new Set(managedDivisions)];

    // divisi aktif (dipilih dari query ?division=)
    let activeDivision = null;
    if (managedDivisions.length) {
      const requested = req.query.division;
      activeDivision = managedDivisions.includes(requested) ? requested : managedDivisions[0];
    }

    const startOfMonth = moment(monthParam + '-01', 'YYYY-MM-DD').startOf('month');
    const endOfMonth = startOfMonth.clone().endOf('month');

    const members = activeDivision
      ? await User.find({ division: activeDivision }).sort({ name: 1 })
      : [];

    function computeWorkSeconds(records) {
      let workSeconds = 0;
      let lastCheckIn = null;
      let lastBreakStart = null;

      records.forEach(r => {
        const t = r.time;
        if (r.action === 'check-in') {
          lastCheckIn = t;
        } else if (r.action === 'check-out') {
          if (lastCheckIn) {
            workSeconds += (t - lastCheckIn) / 1000;
            lastCheckIn = null;
          }
        } else if (r.action === 'break-start') {
          if (lastCheckIn) {
            workSeconds += (t - lastCheckIn) / 1000;
            lastCheckIn = null;
          }
          lastBreakStart = t;
        } else if (r.action === 'break-end') {
          if (lastBreakStart) {
            lastBreakStart = null;
          }
          lastCheckIn = t;
        }
      });

      return workSeconds;
    }

    function formatDuration(sec) {
      sec = Math.floor(sec);
      if (sec < 0) sec = 0;
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = sec % 60;
      const pad = n => n.toString().padStart(2, '0');
      return `${pad(h)}:${pad(m)}:${pad(s)}`;
    }

    const memberSummaries = [];
    for (const m of members) {
      const records = await Attendance.find({
        user: m._id,
        time: { $gte: startOfMonth.toDate(), $lte: endOfMonth.toDate() }
      }).sort({ time: 1 });

      const workSeconds = computeWorkSeconds(records);
      memberSummaries.push({
        user: m,
        workSeconds,
        workText: formatDuration(workSeconds)
      });
    }

    return res.render('supervisor_dashboard', {
      user: req.user,
      division: activeDivision,
      managedDivisions,
      monthParam,
      monthLabel: startOfMonth.format('MMMM YYYY'),
      memberSummaries
    });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Error loading supervisor dashboard');
  }
});

// ADMIN: Hapus SEMUA history attendance
app.post('/admin/attendance/delete-all', ensureRole('Admin'), async (req, res) => {
  try {
    await Attendance.deleteMany({});
    res.redirect('/?msg=deletedAll');
  } catch (e) {
    console.error(e);
    res.redirect('/?msg=error');
  }
});

// ADMIN: Hapus history attendance untuk 1 user
app.post('/admin/attendance/delete-by-user', ensureRole('Admin'), async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.redirect('/?msg=noUser');
    await Attendance.deleteMany({ user: userId });
    res.redirect('/?msg=deletedUser');
  } catch (e) {
    console.error(e);
    res.redirect('/?msg=error');
  }
});

// ADMIN: export CSV per user
app.get('/admin/attendance/export-by-user', ensureRole('Admin'), async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).send('userId is required');
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found');
    }

    const records = await Attendance.find({ user: userId }).sort({ time: 1 });

    const header = ['Name', 'Email', 'Date', 'Time', 'Action'];

    const esc = (v) => {
      if (v === null || v === undefined) return '';
      const s = v.toString();
      const escaped = s.replace(/"/g, '""');
      return `"${escaped}"`;
    };

    const rows = [];
    rows.push(header.map(esc).join(','));

    records.forEach(r => {
      const date = moment(r.time).format('YYYY-MM-DD');
      const time = moment(r.time).format('HH:mm:ss');

      rows.push([
        esc(user.name),
        esc(user.email || ''),
        esc(date),
        esc(time),
        esc(r.action)
      ].join(','));
    });

    const csv = rows.join('\n');

    const rawName = (user.name || 'user').toString();
    let safeName = rawName.replace(/[\r\n"]/g, '');
    safeName = safeName.replace(/\s+/g, '_');
    safeName = safeName.replace(/[^A-Za-z0-9._-]/g, '_');
    if (!safeName) safeName = 'user';
    const fileName = `attendance-${safeName}.csv`;

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(csv);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating CSV');
  }
});

// ADMIN: export Year Summary (Weekly & Monthly tabs)
app.get('/admin/attendance/export-all-xlsx', ensureRole('Admin'), async (req, res) => {
  try {
    const yearParam = req.query.year || moment().format('YYYY');
    const startOfYear = moment(yearParam + '-01-01', 'YYYY-MM-DD').startOf('year');
    const endOfYear = startOfYear.clone().endOf('year');

    const records = await Attendance.find({
      time: { $gte: startOfYear.toDate(), $lte: endOfYear.toDate() }
    }).sort({ user: 1, time: 1 });

    const users = await User.find({});
    const userMap = new Map(users.map(u => [u._id.toString(), u]));

    // --- Process Data ---
    const monthlyStats = new Map(); // "userId|MonthStr" -> { workMs }
    const weeklyStats = new Map();  // "userId|WeekNum" -> { workMs, weekStart }

    // Temporary tracker for accumulating work durations per user
    const userState = new Map(); // userId -> { lastCheckIn, lastBreakStart }

    // Constants
    const R_WORKING = 'working';
    const R_BREAK = 'break';

    // We need to iterate chronologically per user to calculate durations accurately
    // Records are already sorted by user, time.

    // Helper to add duration
    function addDuration(userId, dateObj, ms) {
      if (ms <= 0) return;

      // Monthly
      const monthKey = moment(dateObj).format('MMMM'); // January, February...
      const mKey = `${userId}|${monthKey}`;
      if (!monthlyStats.has(mKey)) monthlyStats.set(mKey, { userId, month: monthKey, workMs: 0 });
      monthlyStats.get(mKey).workMs += ms;

      // Weekly
      const weekNum = moment(dateObj).isoWeek();
      const wKey = `${userId}|${weekNum}`;
      if (!weeklyStats.has(wKey)) {
        // Find start of this week for label
        const weekStart = moment(dateObj).startOf('isoWeek').format('YYYY-MM-DD');
        weeklyStats.set(wKey, { userId, week: weekNum, weekStart, workMs: 0 });
      }
      weeklyStats.get(wKey).workMs += ms;
    }

    records.forEach(r => {
      const userId = r.user.toString();
      const t = r.time.getTime();

      if (!userState.has(userId)) userState.set(userId, { lastCheckIn: null, lastBreakStart: null });
      const state = userState.get(userId);

      if (r.action === 'check-in') {
        state.lastCheckIn = t;
        // Reset break if any (shouldn't happen if logic is strict, but safety)
        state.lastBreakStart = null;
      } else if (r.action === 'check-out') {
        if (state.lastCheckIn) {
          addDuration(userId, r.time, t - state.lastCheckIn);
          state.lastCheckIn = null;
        }
        // If checking out and was on break? (Handled by Auto-Stop logic in POST action, 
        // but here we just process raw logs. If break-end exists, it will handle it. 
        // If not, we might miss break deduction if we were tracking work time? 
        // Actually, simple logic: Work time = (CheckOut - CheckIn) - (Total Break Time inside).
        // OR: Simple Interval Logic: CheckIn->BreakStart (Work), BreakEnd->CheckOut (Work).

        // Let's use Simple Interval Logic for robustness:
        // If we see check-out, we close whatever 'work' session was open.
        // But wait, if we have CheckIn -> BreakStart -> BreakEnd -> CheckOut
        // We need to capture: (BreakStart - CheckIn) + (CheckOut - BreakEnd).
      } else if (r.action === 'break-start') {
        if (state.lastCheckIn) {
          // Time worked so far
          addDuration(userId, r.time, t - state.lastCheckIn);
          state.lastCheckIn = null; // Pause work timer
        }
        state.lastBreakStart = t;
      } else if (r.action === 'break-end') {
        state.lastBreakStart = null;
        state.lastCheckIn = t; // Resume work timer
      }
    });

    // --- Generate Excel ---
    const workbook = new ExcelJS.Workbook();

    // Worksheet 1: Monthly Summary
    const wsMonth = workbook.addWorksheet('Monthly Summary');
    wsMonth.columns = [
      { header: 'Name', key: 'name', width: 25 },
      { header: 'Division', key: 'division', width: 10 },
      { header: 'Month', key: 'month', width: 15 },
      { header: 'Total Hours', key: 'hours', width: 15 },
    ];
    wsMonth.getRow(1).font = { bold: true };

    for (const [key, val] of monthlyStats) {
      const u = userMap.get(val.userId) || { name: 'Unknown', division: '-' };
      const hours = val.workMs / (1000 * 60 * 60);

      const row = wsMonth.addRow({
        name: u.name,
        division: u.division,
        month: val.month,
        hours: hours.toFixed(2)
      });

      // Hyperlink ?? ExcelJS hyperlinks are usually URLs. 
      // Link to internal sheet or web dashboard requires full URL.
      // Let's link to the Supervisor Dashboard URL for that user & month
      // Format: /supervisor/attendance/export-user-month?userId=...&month=YYYY-MM
      // Or just the dashboard view: /supervisor?division=...

      // Let's try pointing to the web endpoint for that user's specific export
      // const link = `${process.env.BASE_URL || 'http://localhost:3000'}/supervisor/attendance/export-user-month?userId=${u._id}&month=${yearParam}-${moment().month(val.month).format('MM')}`;
      // row.getCell('name').value = { text: u.name, hyperlink: link };
    }

    // Worksheet 2: Weekly Summary
    const wsWeek = workbook.addWorksheet('Weekly Summary');
    wsWeek.columns = [
      { header: 'Name', key: 'name', width: 25 },
      { header: 'Division', key: 'division', width: 10 },
      { header: 'Week #', key: 'weekNum', width: 8 },
      { header: 'Start Date', key: 'startDate', width: 15 },
      { header: 'Total Hours', key: 'hours', width: 15 },
      { header: 'Status', key: 'status', width: 15 },
    ];
    wsWeek.getRow(1).font = { bold: true };

    for (const [key, val] of weeklyStats) {
      const u = userMap.get(val.userId) || { name: 'Unknown', division: '-' };
      const hours = val.workMs / (1000 * 60 * 60);
      let status = 'Normal';
      if (hours > 40) status = 'Overtime';
      else if (hours < 40) status = 'Under Target';

      const row = wsWeek.addRow({
        name: u.name,
        division: u.division,
        weekNum: val.week,
        startDate: val.weekStart,
        hours: hours.toFixed(2),
        status: status
      });

      if (status === 'Overtime') row.getCell('status').font = { color: { argb: 'FF0000FF' } }; // Blue? Or Green.
      if (status === 'Under Target') row.getCell('status').font = { color: { argb: 'FFFF0000' } }; // Red
    }

    const fileName = `attendance-summary-${yearParam}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating Year Summary Excel');
  }
});

// ADMIN: export attendance range tanggal ke Excel
app.get('/admin/attendance/export-range-xlsx', ensureRole('Admin'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
      return res.status(400).send('startDate and endDate are required (YYYY-MM-DD)');
    }

    const start = moment(startDate, 'YYYY-MM-DD').startOf('day').toDate();
    const end = moment(endDate, 'YYYY-MM-DD').endOf('day').toDate();

    const records = await Attendance.find({
      time: { $gte: start, $lte: end }
    }).sort({ time: 1 });

    const users = await User.find({});
    const userMap = new Map(users.map(u => [u._id.toString(), u]));

    const rows = records.map(r => {
      const u = userMap.get(r.user.toString()) || {};
      return {
        Name: u.name || '',
        Email: u.email || '',
        Date: moment(r.time).format('YYYY-MM-DD'),
        Time: moment(r.time).format('HH:mm:ss'),
        Action: r.action
      };
    });

    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Attendance');

    const buffer = XLSX.write(wb, { bookType: 'xlsx', type: 'buffer' });

    const fileName = `attendance-range-${startDate}_to_${endDate}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.send(buffer);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating Excel file');
  }
});

// SUPERVISOR / OM / GM: download history 1 pegawai 1 bulan (Excel)
app.get('/supervisor/attendance/export-user-month', ensureAuth, async (req, res) => {
  try {
    const allowedRoles = ['Supervisor', 'Operational Manager', 'General Manager', 'Admin'];
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).send('Forbidden');
    }

    const { userId, month } = req.query; // "YYYY-MM"
    if (!userId || !month) {
      return res.status(400).send('userId and month are required (month format: YYYY-MM)');
    }

    const [yearStr, monthStr] = month.split('-');
    if (!yearStr || !monthStr) {
      return res.status(400).send('Invalid month format');
    }

    const startOfMonth = moment(`${yearStr}-${monthStr}-01`, 'YYYY-MM-DD').startOf('month');
    const endOfMonth = startOfMonth.clone().endOf('month');

    const supervisor = req.user;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found');
    }

    // Divisi yang di-manage oleh supervisor/OM/GM
    let managedDivisions = [];
    if (supervisor.division) managedDivisions.push(supervisor.division);
    if (supervisor.secondaryDivision) managedDivisions.push(supervisor.secondaryDivision);
    managedDivisions = [...new Set(managedDivisions)];

    // Security check
    if (supervisor.role !== 'Admin') {
      const userDivs = [user.division, user.secondaryDivision].filter(Boolean);
      const ok = userDivs.some(d => managedDivisions.includes(d));
      if (!ok) return res.status(403).send('Forbidden');
    }

    const records = await Attendance.find({
      user: userId,
      time: { $gte: startOfMonth.toDate(), $lte: endOfMonth.toDate() }
    }).sort({ time: 1 });

    // --- LOGIC BARU: Aggregation per Hari ---
    const dayMap = new Map();
    // Inisialisasi setiap hari dalam bulan
    const daysInMonth = startOfMonth.daysInMonth();
    for (let i = 1; i <= daysInMonth; i++) {
      const d = startOfMonth.clone().date(i);
      const dayKey = d.format('YYYY-MM-DD');
      dayMap.set(dayKey, {
        dateObj: d,
        dayName: d.format('dddd'),
        checkIn: null,
        checkOut: null,
        workMs: 0,
        breakMs: 0,
        lastCheckIn: null,
        lastBreakStart: null
      });
    }

    // Proses records
    records.forEach(r => {
      const dayKey = moment(r.time).format('YYYY-MM-DD');
      const data = dayMap.get(dayKey);
      if (!data) return; // Should not happen

      const t = r.time.getTime();

      if (r.action === 'check-in') {
        if (!data.checkIn) data.checkIn = r.time;
        data.lastCheckIn = t;
        // Jika sebelumnya break, break selesai implisit? (Asumsi sistem strict: break-end harusnya ada)
        // Kita ikuti logika sederhana server.js sebelumnya
      } else if (r.action === 'check-out') {
        if (!data.checkOut || r.time > data.checkOut) data.checkOut = r.time;
        if (data.lastCheckIn) {
          data.workMs += (t - data.lastCheckIn);
          data.lastCheckIn = null;
        }
      } else if (r.action === 'break-start') {
        if (data.lastCheckIn) {
          data.workMs += (t - data.lastCheckIn);
          data.lastCheckIn = null;
        }
        data.lastBreakStart = t;
      } else if (r.action === 'break-end') {
        if (data.lastBreakStart) {
          data.breakMs += (t - data.lastBreakStart);
          data.lastBreakStart = null;
        }
        data.lastCheckIn = t;
      }
    });

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Attendance Report');

    // Kolom
    sheet.columns = [
      { header: 'Week', key: 'week', width: 8 },
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Day', key: 'day', width: 15 },
      { header: 'Clock In', key: 'in', width: 12 },
      { header: 'Clock Out', key: 'out', width: 12 },
      { header: 'Total Work', key: 'work', width: 15 },
      { header: 'Total Break', key: 'break', width: 15 },
      { header: 'Status', key: 'status', width: 15 }
    ];

    // Styling Header
    sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
    sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } }; // Indigo

    let currentWeek = null;
    let weekWorkMs = 0;

    // Iterasi Map
    for (const [key, val] of dayMap) {
      const weekNum = val.dateObj.isoWeek();

      // Jika ganti minggu (dan bukan baris pertama), insert subtotal minggu sebelumnya?
      // Atau kita print row dulu, nanti kalau ganti minggu baru insert row pemisah.

      if (currentWeek !== null && weekNum !== currentWeek) {
        // Insert Weekly Summary Row
        const row = sheet.addRow({
          day: 'Weekly Total',
          work: formatDuration(weekWorkMs / 1000)
        });
        row.font = { bold: true };
        row.getCell('work').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEEEEEE' } };
        weekWorkMs = 0; // Reset
      }
      currentWeek = weekNum;

      // Hitung durasi jam
      const workHours = val.workMs / (1000 * 60 * 60);
      const breakHours = val.breakMs / (1000 * 60 * 60);
      weekWorkMs += val.workMs;

      const rowValues = {
        week: weekNum,
        date: key,
        day: val.dayName,
        in: val.checkIn ? moment(val.checkIn).format('HH:mm') : '-',
        out: val.checkOut ? moment(val.checkOut).format('HH:mm') : '-',
        work: formatDuration(val.workMs / 1000),
        break: formatDuration(val.breakMs / 1000),
        status: workHours >= 8 ? 'Target Met' : 'Under Target'
      };

      const row = sheet.addRow(rowValues);

      // Conditional Formatting
      // 1. Work < 8h -> Red text
      if (workHours < 8 && val.dayName !== 'Saturday' && val.dayName !== 'Sunday') { // Ignore weekend
        row.getCell('work').font = { color: { argb: 'FFFF0000' } }; // Red
        row.getCell('status').font = { color: { argb: 'FFFF0000' } };
      } else if (workHours >= 8) {
        row.getCell('work').font = { color: { argb: 'FF008000' } }; // Green
        row.getCell('status').font = { color: { argb: 'FF008000' } };
      }

      // 2. Break > 1h -> Red bg
      if (breakHours > 1) {
        row.getCell('break').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFCCCC' } }; // Light Red BG
      }
    }

    // Sisa last week
    if (weekWorkMs > 0) {
      const row = sheet.addRow({
        day: 'Weekly Total',
        work: formatDuration(weekWorkMs / 1000)
      });
      row.font = { bold: true };
      row.getCell('work').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEEEEEE' } };
    }

    function formatDuration(sec) {
      if (!sec) return '00:00:00';
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);
      return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    }

    const safeName = (user.name || 'user').replace(/[^a-zA-Z0-9]/g, '_');
    const fileName = `attendance-${safeName}-${month}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);

    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating supervisor Excel file');
  }
});

// Auth routes
app.get('/login', (req, res) => res.render('login'));
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

app.get('/logout', (req, res) => {
  req.logout(() => { });
  res.redirect('/login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render('login', { error: 'User not found' });
  if (!user.password) return res.render('login', { error: 'Password not set for this user' });

  const valid = await user.validatePassword(password);
  if (!valid) return res.render('login', { error: 'Invalid password' });

  req.login(user, err => {
    if (err) return res.render('login', { error: 'Login error' });
    res.redirect('/');
  });
});

// ADMIN: create user
app.post('/admin/create-user', ensureRole('Admin'), async (req, res) => {
  const { name, email, role, division, secondaryDivision, password, canAccessSupervisorDashboard } = req.body;

  let u = await User.findOne({ email });
  if (u) return res.redirect('/?msg=exists');

  const hashed = password ? await bcrypt.hash(password, 10) : undefined;

  u = new User({
    name,
    email,
    role,
    division,
    secondaryDivision: secondaryDivision || undefined,
    canAccessSupervisorDashboard: canAccessSupervisorDashboard === 'on' || canAccessSupervisorDashboard === true,
    durationWorkHours: 8,
    durationBreakMinutes: 60,
    password: hashed
  });

  await u.save();
  res.redirect('/?msg=userCreated');
});

// ADMIN: update user
app.post('/admin/update-user', ensureRole('Admin'), async (req, res) => {
  try {
    const { userId, name, email, role, division, secondaryDivision, password, canAccessSupervisorDashboard } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.redirect('/?msg=userNotFound');
    }

    user.name = name;
    user.email = email;
    user.role = role;
    user.division = division || 'OC';
    user.secondaryDivision = secondaryDivision || undefined;
    user.canAccessSupervisorDashboard = canAccessSupervisorDashboard === 'on' || canAccessSupervisorDashboard === true;

    if (password && password.trim()) {
      user.password = await bcrypt.hash(password, 10);
    }

    await user.save();
    res.redirect('/?msg=userUpdated');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

// ADMIN: delete user + history
app.post('/admin/delete-user', ensureRole('Admin'), async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) {
      return res.redirect('/?msg=noUser');
    }

    await Attendance.deleteMany({ user: userId });
    await User.findByIdAndDelete(userId);

    res.redirect('/?msg=userDeleted');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

// ADMIN: generate daily QR
app.post('/admin/generate-qr', ensureRole('Admin'), async (req, res) => {
  const token = await QRToken.generateDaily();
  const dataUrl = await qrcode.toDataURL(token.token);
  res.json({ token: token.token, dataUrl });
});

// Attendance actions
app.post('/attendance/action', ensureAuth, async (req, res) => {
  const { action, qrToken, lat, lng, accuracy } = req.body;
  console.log(`[Attendance Action] User: ${req.user.email}, Lat: ${lat}, Lng: ${lng}, Acc: ${accuracy}`);
  try {
    const valid = await QRToken.validate(qrToken);
    if (!valid) return res.status(400).json({ error: 'Invalid QR or expired' });

    // Validate Accuracy
    const acc = Number(accuracy);
    // If accuracy is provided and > 100 meters, reject
    // Note: Some browsers might not send accuracy, or send 0 if unknown. 
    // We only reject if it's explicitly bad.
    if (accuracy && acc > 100) {
      return res.status(400).json({
        error: `Location accuracy too low (${Math.round(acc)}m). Please wait for better GPS signal.`
      });
    }

    const officeLat = Number(process.env.OFFICE_LAT || 0);
    const officeLng = Number(process.env.OFFICE_LNG || 0);
    const radius = Number(process.env.OFFICE_RADIUS_METERS || 100);

    function distanceMeters(lat1, lon1, lat2, lon2) {
      const R = 6371000;
      const toRad = v => v * Math.PI / 180;
      const dLat = toRad(lat2 - lat1);
      const dLon = toRad(lon2 - lon1);
      const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      return R * c;
    }

    const dist = distanceMeters(officeLat, officeLng, Number(lat), Number(lng));
    if (dist > radius) {
      return res.status(400).json({
        error: 'Out of allowed location. Distance: ' + Math.round(dist) + ' meters'
      });
    }

    // Check last status for Auto-Stop Break logic
    const lastAtt = await Attendance.findOne({ user: req.user._id }).sort({ time: -1 });

    if (action === 'check-out' && lastAtt && lastAtt.action === 'break-start') {
      console.log(`[Auto-Stop Break] User ${req.user.email} checking out while on break. Inserting break-end.`);
      const breakEnd = new Attendance({
        user: req.user._id,
        action: 'break-end',
        time: new Date(), // Now
        meta: { auto: true, lat, lng, qrToken, accuracy }
      });
      await breakEnd.save();
    }

    const att = new Attendance({
      user: req.user._id,
      action,
      time: new Date(),
      meta: { lat, lng, qrToken, accuracy }
    });
    await att.save();
    return res.json({ ok: true, att });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

// Simple API attendance list (Admin only)
app.get('/api/attendance/:userId', ensureRole('Admin'), async (req, res) => {
  const list = await Attendance.find({ user: req.params.userId }).sort({ time: -1 });
  res.json(list);
});

// Admin get current QR
app.get('/admin/qr/current', ensureRole('Admin'), async (req, res) => {
  const token = await QRToken.getCurrent();
  const dataUrl = await qrcode.toDataURL(token.token);
  res.json({ token: token.token, dataUrl });
});

// Ensure default admin
async function ensureDefaultAdmin() {
  try {
    const adminEmail = process.env.DEFAULT_ADMIN_EMAIL;
    const adminPass = process.env.DEFAULT_ADMIN_PASSWORD;
    const adminName = process.env.DEFAULT_ADMIN_NAME || "Administrator";

    if (!adminEmail || !adminPass) {
      console.warn("⚠️  No DEFAULT_ADMIN_EMAIL or DEFAULT_ADMIN_PASSWORD found in .env");
      return;
    }

    const existing = await User.findOne({ email: adminEmail });
    if (!existing) {
      const hash = await bcrypt.hash(adminPass, 10);
      await User.create({
        name: adminName,
        email: adminEmail,
        password: hash,
        role: "Admin",
        durationWorkHours: 8,
        durationBreakMinutes: 60,
        createdAt: new Date()
      });
      console.log(`✅ Default admin created: ${adminEmail}`);
    } else {
      console.log(`ℹ️ Default admin already exists: ${adminEmail}`);
    }
  } catch (err) {
    console.error("❌ Failed to ensure default admin:", err);
  }
}

// Start server
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
  console.log("✅ MongoDB connected");
  await ensureDefaultAdmin();
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}).catch(err => console.error("MongoDB connection error:", err));
