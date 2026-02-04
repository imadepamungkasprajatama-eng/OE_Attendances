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
const SystemSettings = require('./models/SystemSettings');

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

    // Check if role is an array of allowed roles
    if (Array.isArray(role)) {
      if (role.includes(req.user.role) || req.user.role === 'Admin') return next();
    } else {
      // Single role check
      if (req.user.role === role || req.user.role === 'Admin') return next();
    }

    return res.status(403).send('Forbidden');
  };
}

// Middleware specifically for User Management (Admin or HR Supervisor)
function checkUserManagement(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/login');

  if (req.user.role === 'Admin') return next();

  // Check for Supervisor/GM with HR division or All Division
  const allowedRoles = ['Supervisor', 'General Manager'];
  const isHrOrAll = req.user.division === 'HR' ||
    req.user.division === 'All Division' ||
    req.user.secondaryDivision === 'HR' ||
    req.user.secondaryDivision === 'All Division';

  if (allowedRoles.includes(req.user.role) && isHrOrAll) {
    return next();
  }

  return res.status(403).send('Forbidden: HR Access Required');
}

// ====== ROUTES ======

// HOME: Admin -> admin_dashboard, lainnya -> user_home
app.get('/', ensureAuth, async (req, res) => {
  // Admin dashboard
  if (req.user.role === 'Admin') {
    const users = await User.find().sort({ name: 1 });
    const token = await QRToken.getCurrent();
    if (token) {
      token.qrImage = await qrcode.toDataURL(token.token);
    }
    const settings = await SystemSettings.findOne() || {
      officeLat: parseFloat(process.env.OFFICE_LAT || '0'),
      officeLng: parseFloat(process.env.OFFICE_LNG || '0'),
      officeRadius: parseFloat(process.env.OFFICE_RADIUS_METERS || '100')
    };

    // --- SATURDAY ATTENDANCE LOGIC ---
    // 1. Determine Month
    const currentMonth = moment().format('YYYY-MM');
    const selectedMonth = req.query.month || currentMonth;

    const startOfMonth = moment(selectedMonth, 'YYYY-MM').startOf('month').toDate();
    const endOfMonth = moment(selectedMonth, 'YYYY-MM').endOf('month').toDate();

    // 2. Fetch Attendance for Duration Calculation
    const allAtt = await Attendance.find({
      time: { $gte: startOfMonth, $lte: endOfMonth }
    }).sort({ time: 1 });

    const attByUser = new Map();
    allAtt.forEach(a => {
      const uid = a.user.toString();
      if (!attByUser.has(uid)) attByUser.set(uid, []);
      attByUser.get(uid).push(a);
    });

    // 3. Calculate Hours
    users.forEach(u => {
      const userLogs = attByUser.get(u._id.toString()) || [];
      let satSeconds = 0;

      // Group by day
      const logsByDay = new Map();
      userLogs.forEach(l => {
        const d = moment(l.time).format('YYYY-MM-DD');
        if (!logsByDay.has(d)) logsByDay.set(d, []);
        logsByDay.get(d).push(l);
      });

      for (const [day, dayLogs] of logsByDay) {
        if (moment(day).isoWeekday() === 6) { // Saturday
          // Fix: Support both 'action' (lowercase) and legacy 'type' (uppercase)
          const ci = dayLogs.find(x => x.action === 'check-in' || x.type === 'CHECK_IN');
          const co = dayLogs.find(x => x.action === 'check-out' || x.type === 'CHECK_OUT');
          if (ci && co) {
            satSeconds += (new Date(co.time) - new Date(ci.time)) / 1000;
          }
        }
      }

      if (satSeconds > 0) {
        const h = Math.floor(satSeconds / 3600);
        const m = Math.floor((satSeconds % 3600) / 60);
        const s = Math.floor(satSeconds % 60);
        u.saturdayHoursStr = `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
        u.hasSaturdayAttendance = true;
      } else {
        u.saturdayHoursStr = "00:00:00";
        u.hasSaturdayAttendance = false;
      }
    });

    return res.render('admin_dashboard', {
      user: req.user,
      users,
      token, // Kept token name as per original
      settings,
      moment,
      selectedMonth, // Pass filter
      query: req.query // Kept query
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

  const settings = await SystemSettings.findOne(); // Fetch latest settings

  return res.render('user_home', {
    user: req.user,
    token,
    moment,
    office: {
      lat: settings ? settings.officeLat : parseFloat(process.env.OFFICE_LAT || '0'),
      lng: settings ? settings.officeLng : parseFloat(process.env.OFFICE_LNG || '0'),
      radius: settings ? settings.officeRadius : parseFloat(process.env.OFFICE_RADIUS_METERS || '100')
    },
    attendanceSummary,
    divisionMembers
  });
});

// SUPERVISOR / OM / GM DASHBOARD (bulanan + multi-divisi)
app.get('/supervisor', ensureAuth, async (req, res) => {
  try {
    const settings = await SystemSettings.findOne(); // Ensure settings are fetched

    const allowedRoles = ['Supervisor', 'Operational Manager', 'General Manager', 'Admin'];
    // Allow if role is in allowedRoles OR if user has explicit access
    if (!allowedRoles.includes(req.user.role) && !req.user.canAccessSupervisorDashboard) {
      return res.status(403).send('Forbidden');
    }

    // Permission to manage users: Admin OR Supervisor with 'HR'/'All Division'
    const isHrOrAll = req.user.division === 'HR' ||
      req.user.division === 'All Division' ||
      req.user.secondaryDivision === 'HR' ||
      req.user.secondaryDivision === 'All Division';

    const canManageUsers = req.user.role === 'Admin' ||
      ((req.user.role === 'Supervisor' || req.user.role === 'General Manager') && isHrOrAll);

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

    // Fetch all members for Saturday Report (ignoring activeDivision filter)
    const saturdayMembers = (managedDivisions.length > 0)
      ? await User.find({ division: { $in: managedDivisions } }).sort({ name: 1 })
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

    // 1. Dashboard List (Filtered by activeDivision)
    const memberSummaries = [];
    for (const m of members) {
      const records = await Attendance.find({
        user: m._id,
        time: { $gte: startOfMonth.toDate(), $lte: endOfMonth.toDate() }
      }).sort({ time: 1 });

      const workSeconds = computeWorkSeconds(records);

      const lastRecord = await Attendance.findOne({ user: m._id }).sort({ time: -1 });
      let currentStatus = 'Idle';
      if (lastRecord) {
        if (lastRecord.action === 'check-in' || lastRecord.action === 'break-end') currentStatus = 'Working';
        else if (lastRecord.action === 'break-start') currentStatus = 'Break';
        else if (lastRecord.action === 'check-out') currentStatus = 'Idle';
      }

      memberSummaries.push({
        user: m,
        workSeconds,
        workText: formatDuration(workSeconds),
        status: currentStatus
      });
    }

    // 2. Saturday Summaries (All Managed Divisions)
    const saturdaySummaries = [];
    const satQueryEnd = endOfMonth.clone().add(2, 'days');

    for (const m of saturdayMembers) {
      const satRecords = await Attendance.find({
        user: m._id,
        time: { $gte: startOfMonth.toDate(), $lte: satQueryEnd.toDate() }
      }).sort({ time: 1 });

      let satSeconds = 0;
      let lastIn = null;

      satRecords.forEach(r => {
        const d = moment(r.time);
        if (r.action === 'check-in') {
          if (d.day() === 6) {
            lastIn = r.time;
          } else {
            lastIn = null;
          }
        } else if (r.action === 'check-out') {
          if (lastIn) {
            const dur = (r.time - lastIn) / 1000;
            if (dur > 0) satSeconds += dur;
            lastIn = null;
          }
        }
      });

      const hasSaturdayAttendance = satSeconds > 0;
      let saturdayHoursStr = "00:00:00";
      if (hasSaturdayAttendance) {
        const h = Math.floor(satSeconds / 3600);
        const min = Math.floor((satSeconds % 3600) / 60);
        const s = Math.floor(satSeconds % 60);
        const pad = n => n.toString().padStart(2, '0');
        saturdayHoursStr = `${pad(h)}:${pad(min)}:${pad(s)}`;
      }

      saturdaySummaries.push({
        user: m,
        saturdayHoursStr,
        hasSaturdayAttendance
      });
      saturdaySummaries.push({
        user: m,
        saturdayHoursStr,
        hasSaturdayAttendance
      });
    }

    // 3. Real-Time Daily Stats (For "Today's Overview" Modal) - Grouped by Division
    // reusing saturdayMembers because it contains ALL members of valid divisions
    const dailyStats = await Promise.all(saturdayMembers.map(async (m) => {
      const stats = await getDailyStats(m._id);
      return {
        user: m,
        division: m.division,
        workSeconds: stats.workSeconds,
        breakSeconds: stats.breakSeconds,
        status: stats.status,
        currentWorkStart: stats.currentWorkStart,
        currentBreakStart: stats.currentBreakStart,
        // formatted for static display (JS will handle ticking)
        workText: formatDuration(stats.workSeconds),
        breakText: formatDuration(stats.breakSeconds)
      };
    }));

    const statusObj = await getUserStatus(req.user._id);

    return res.render('supervisor_dashboard', {
      user: req.user,
      divisionMembers: members,
      division: activeDivision, // Used by view for dropdown
      managedDivisions,
      monthParam,
      monthLabel: startOfMonth.format('MMMM YYYY'),
      memberSummaries,
      saturdaySummaries, // Pass Saturday data
      dailyStats, // Pass Real-Time Daily Stats
      canManageUsers: (req.user.role === 'Admin' || req.user.role === 'General Manager' || ((req.user.role === 'Supervisor' || req.user.role === 'Operational Manager') && (req.user.division === 'HR' || req.user.secondaryDivision === 'HR'))),
      settings,
      query: req.query,
      isBusy: (statusObj.status === 'working' || statusObj.status === 'break'),
      statusText: statusObj.label
    });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Error loading supervisor dashboard');
  }
});

// ADMIN DASHBOARD
app.get('/admin', ensureRole('Admin'), async (req, res) => {
  try {
    const settings = await SystemSettings.findOne() || {
      officeLat: parseFloat(process.env.OFFICE_LAT || '0'),
      officeLng: parseFloat(process.env.OFFICE_LNG || '0'),
      officeRadius: parseFloat(process.env.OFFICE_RADIUS_METERS || '100')
    };
    const selectedMonth = req.query.month || moment().format('YYYY-MM');
    const startOfMonth = moment(selectedMonth + '-01', 'YYYY-MM').startOf('month');
    const endOfMonth = startOfMonth.clone().endOf('month');
    const satQueryEnd = endOfMonth.clone().add(2, 'days');

    // QR Token for Admin View
    const qrDoc = await QRToken.getCurrent();
    let tokenData = null;
    if (qrDoc) {
      const qrImage = await qrcode.toDataURL(qrDoc.token);
      tokenData = { ...qrDoc.toObject(), qrImage };
    }

    const allUsers = await User.find({}).sort({ name: 1 });

    const users = await Promise.all(allUsers.map(async (u) => {
      // Robust Saturday Calculation (Same as Supervisor)
      const satRecords = await Attendance.find({
        user: u._id,
        time: { $gte: startOfMonth.toDate(), $lte: satQueryEnd.toDate() }
      }).sort({ time: 1 });

      let satSeconds = 0;
      let lastIn = null;

      satRecords.forEach(r => {
        const d = moment(r.time);
        if (r.action === 'check-in') {
          if (d.day() === 6) {
            lastIn = r.time;
          } else {
            lastIn = null;
          }
        } else if (r.action === 'check-out') {
          if (lastIn) {
            const dur = (r.time - lastIn) / 1000;
            if (dur > 0) satSeconds += dur;
            lastIn = null;
          }
        }
      });

      let saturdayHoursStr = "00:00:00";
      if (satSeconds > 0) {
        const h = Math.floor(satSeconds / 3600);
        const m = Math.floor((satSeconds % 3600) / 60);
        const s = Math.floor(satSeconds % 60);
        const pad = n => n.toString().padStart(2, '0');
        saturdayHoursStr = `${pad(h)}:${pad(m)}:${pad(s)}`;
      }

      return {
        ...u.toObject(),
        saturdayHoursStr,
        hasSaturdayAttendance: satSeconds > 0
      };
    }));

    res.render('admin_dashboard', {
      user: req.user,
      users,
      settings,
      selectedMonth,
      token: tokenData,
      query: req.query
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading admin dashboard');
  }
});

// STAFF: My History
app.get('/my-history', ensureAuth, async (req, res) => {
  try {
    // Fetch last 100 records
    const records = await Attendance.find({ user: req.user._id })
      .sort({ time: -1 })
      .limit(100);

    const statusObj = await getUserStatus(req.user._id);

    res.render('my_history', {
      user: req.user,
      records,
      moment,
      isBusy: (statusObj.status === 'working' || statusObj.status === 'break'),
      statusText: statusObj.label
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading history');
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

// ADMIN: export ALL Data (Excel) - Supports Date Range
app.get('/admin/attendance/export-all-xlsx', ensureRole('Admin'), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = {};

    // Date Range Filter
    if (startDate && endDate) {
      query.time = {
        $gte: moment(startDate).startOf('day').toDate(),
        $lte: moment(endDate).endOf('day').toDate()
      };
    }

    const records = await Attendance.find(query).populate('user', 'name email division role').sort({ time: 1 });

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Attendance Log');

    sheet.columns = [
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Time', key: 'time', width: 10 },
      { header: 'Name', key: 'name', width: 20 },
      { header: 'Email', key: 'email', width: 25 },
      { header: 'Division', key: 'division', width: 15 },
      { header: 'Role', key: 'role', width: 15 },
      { header: 'Action', key: 'action', width: 15 },
      { header: 'Lat', key: 'lat', width: 15 },
      { header: 'Lng', key: 'lng', width: 15 },
      { header: 'Distance (m)', key: 'dist', width: 15 },
      { header: 'QR Token', key: 'qr', width: 20 },
    ];

    // Helper for Distance
    const settings = await SystemSettings.findOne();
    const officeLat = settings ? settings.officeLat : 0;
    const officeLng = settings ? settings.officeLng : 0;

    function getDistance(lat, lon) {
      if (!lat || !lon) return 0;
      const R = 6371000;
      const toRad = v => v * Math.PI / 180;
      const dLat = toRad(lat - officeLat);
      const dLon = toRad(lon - officeLng);
      const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(toRad(officeLat)) * Math.cos(toRad(lat)) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      return Math.round(R * c);
    }

    records.forEach(r => {
      const u = r.user || {};
      const meta = r.meta || {};
      const dist = getDistance(meta.lat, meta.lng);

      sheet.addRow({
        date: moment(r.time).format('YYYY-MM-DD'),
        time: moment(r.time).format('HH:mm:ss'),
        name: u.name || 'Unknown',
        email: u.email || '-',
        division: u.division || '-',
        role: u.role || '-',
        action: r.action,
        lat: meta.lat || 0,
        lng: meta.lng || 0,
        dist: dist,
        qr: meta.qrToken || '-'
      });
    });

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename=attendance_export_${moment().format('YYYYMMDD_HHmm')}.xlsx`);

    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error exporting data');
  }
});

// ADMIN: export User Detail (Excel with Daily, Weekly, Monthly tabs)
app.get('/admin/attendance/export-by-user', ensureRole('Admin'), async (req, res) => {
  try {
    const { userId } = req.query;
    const yearParam = req.query.year || moment().format('YYYY');

    if (!userId) {
      return res.status(400).send('userId is required');
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found');
    }

    const startOfYear = moment(yearParam + '-01-01', 'YYYY-MM-DD').startOf('year');
    const endOfYear = startOfYear.clone().endOf('year');

    const records = await Attendance.find({
      user: userId,
      time: { $gte: startOfYear.toDate(), $lte: endOfYear.toDate() }
    }).sort({ time: 1 });

    // --- Process Data ---
    const dailyStats = new Map();   // "YYYY-MM-DD" -> { ... }
    const weeklyStats = new Map();  // "WeekNum" -> { workMs, weekStart }
    const monthlyStats = new Map(); // "MonthStr" -> { workMs }

    // Initialize Daily Stats for every day (optional, but good for completeness? Or just populated days)
    // Let's just do populated days + sparse logic for easier implementation first, 
    // or iterate full year if requested. Supervisor export does full month. 
    // For a full year, sparse is better to save empty rows, but "Daily Report" usually expects 365 rows? 
    // Let's stick to "days with activity" for now to avoid massive empty files, unless critical.

    let lastCheckIn = null;
    let lastBreakStart = null;

    // Helper to add duration to aggregates
    function addToAggregates(dateObj, ms) {
      if (ms <= 0) return;

      // Monthly
      const monthKey = moment(dateObj).format('MMMM');
      if (!monthlyStats.has(monthKey)) monthlyStats.set(monthKey, { month: monthKey, workMs: 0 });
      monthlyStats.get(monthKey).workMs += ms;

      // Weekly
      const weekNum = moment(dateObj).isoWeek();
      if (!weeklyStats.has(weekNum)) {
        const weekStart = moment(dateObj).startOf('isoWeek').format('YYYY-MM-DD');
        weeklyStats.set(weekNum, { week: weekNum, weekStart, workMs: 0 });
      }
      weeklyStats.get(weekNum).workMs += ms;
    }

    records.forEach(r => {
      const dayKey = moment(r.time).format('YYYY-MM-DD');
      if (!dailyStats.has(dayKey)) {
        dailyStats.set(dayKey, {
          dateObj: moment(r.time),
          in: null,
          out: null,
          workMs: 0,
          breakMs: 0
        });
      }
      const day = dailyStats.get(dayKey);
      const t = r.time.getTime();

      if (r.action === 'check-in') {
        if (!day.in) day.in = r.time;
        lastCheckIn = t;
        lastBreakStart = null;
      } else if (r.action === 'check-out') {
        if (!day.out || r.time > day.out) day.out = r.time;
        if (lastCheckIn) {
          const dur = t - lastCheckIn;
          day.workMs += dur;
          addToAggregates(r.time, dur);
          lastCheckIn = null;
        }
      } else if (r.action === 'break-start') {
        if (lastCheckIn) {
          const dur = t - lastCheckIn;
          day.workMs += dur;
          addToAggregates(r.time, dur);
          lastCheckIn = null;
        }
        lastBreakStart = t;
      } else if (r.action === 'break-end') {
        if (lastBreakStart) {
          day.breakMs += (t - lastBreakStart);
          lastBreakStart = null;
        }
        lastCheckIn = t;
      }
    });

    // --- Generate Excel ---
    const workbook = new ExcelJS.Workbook();

    // 1. Monthly Summary
    const wsMonth = workbook.addWorksheet('Monthly Summary');
    wsMonth.columns = [
      { header: 'Month', key: 'month', width: 20 },
      { header: 'Total Work Hours', key: 'hours', width: 20 },
    ];
    wsMonth.getRow(1).font = { bold: true };

    for (const [key, val] of monthlyStats) {
      wsMonth.addRow({
        month: val.month,
        hours: (val.workMs / (1000 * 3600)).toFixed(2)
      });
    }

    // 2. Weekly Summary
    const wsWeek = workbook.addWorksheet('Weekly Summary');
    wsWeek.columns = [
      { header: 'Week #', key: 'week', width: 10 },
      { header: 'Start Date', key: 'start', width: 15 },
      { header: 'Total Work Hours', key: 'hours', width: 20 },
      { header: 'Status', key: 'status', width: 15 },
    ];
    wsWeek.getRow(1).font = { bold: true };

    for (const [key, val] of weeklyStats) {
      const hours = val.workMs / (1000 * 3600);
      let status = 'Normal';
      if (hours > 40) status = 'Overtime';
      else if (hours < 40) status = 'Under Target';

      const row = wsWeek.addRow({
        week: val.week,
        start: val.weekStart,
        hours: hours.toFixed(2),
        status: status
      });

      if (status === 'Overtime') row.getCell('status').font = { color: { argb: 'FF0000FF' } };
      if (status === 'Under Target') row.getCell('status').font = { color: { argb: 'FFFF0000' } };
    }

    // 3. Daily Details
    const wsDaily = workbook.addWorksheet('Daily Report');
    wsDaily.columns = [
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Day', key: 'day', width: 15 },
      { header: 'Check In', key: 'in', width: 10 },
      { header: 'Check Out', key: 'out', width: 10 },
      { header: 'Work (Hrs)', key: 'work', width: 15 },
      { header: 'Break (Hrs)', key: 'break', width: 15 },
      { header: 'Status', key: 'status', width: 15 },
    ];
    wsDaily.getRow(1).font = { bold: true };

    // Sort days chronologically
    const sortedDays = [...dailyStats.values()].sort((a, b) => a.dateObj - b.dateObj);

    // Format helper
    const fmtTime = (d) => d ? moment(d).format('HH:mm') : '-';
    const fmtDur = (ms) => {
      if (!ms) return '00:00:00';
      const h = Math.floor(ms / 3600000);
      const m = Math.floor((ms % 3600000) / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    sortedDays.forEach(d => {
      const workHrs = d.workMs / (1000 * 3600);
      const dayName = d.dateObj.format('dddd');

      const row = wsDaily.addRow({
        date: d.dateObj.format('YYYY-MM-DD'),
        day: dayName,
        in: fmtTime(d.in),
        out: fmtTime(d.out),
        work: fmtDur(d.workMs),
        break: fmtDur(d.breakMs),
        status: workHrs >= 8 ? 'Ok' : 'Under'
      });

      if (workHrs < 8 && dayName !== 'Saturday' && dayName !== 'Sunday') {
        row.getCell('work').font = { color: { argb: 'FFFF0000' } };
      } else {
        row.getCell('work').font = { color: { argb: 'FF008000' } };
      }
    });

    // Filename
    const safeName = (user.name || 'user').replace(/[^a-zA-Z0-9]/g, '_');
    const fileName = `attendance-${safeName}-${yearParam}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating CSV/Excel');
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
    // Allow if role is in allowedRoles OR if user has explicit access
    if (!allowedRoles.includes(req.user.role) && !req.user.canAccessSupervisorDashboard) {
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

    // FIX: Check if they have "All Division" access
    const hasAllDivision = managedDivisions.includes('All Division');

    managedDivisions = [...new Set(managedDivisions)];

    // Security check
    if (supervisor.role !== 'Admin') {
      // If supervisor has "All Division", they manage everyone. 
      // Otherwise, check if user's division is in managedDivisions.
      if (!hasAllDivision) {
        const userDivs = [user.division, user.secondaryDivision].filter(Boolean);
        // If user has no division set, or one of their divisions is managed by this supervisor
        const ok = userDivs.some(d => managedDivisions.includes(d));

        if (!ok) return res.status(403).send('Forbidden: You do not manage this user\'s division.');
      }
    }

    const settings = await SystemSettings.findOne() || { holidays: [], saturdayWorkHours: 4 };

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
      // CHECK: is this day a working day for this user?
      // val.dayName is eg 'Monday'. We need 0-6 index.
      // JS getDay(): Sun=0, Mon=1...
      const dateDayIndex = moment(key).day();

      // Default [1..5] if not set
      const userWorkDays = user.workingDays && user.workingDays.length > 0 ? user.workingDays : [1, 2, 3, 4, 5];
      const isDayOfWeekWork = userWorkDays.includes(dateDayIndex);

      // Check Holiday
      // 'key' is YYYY-MM-DD
      const isHoliday = settings.holidays && settings.holidays.includes(key);

      const isWorkingDay = isDayOfWeekWork && !isHoliday;

      if (!isWorkingDay) {
        // If NOT a working day (or it IS a holiday)
        if (workHours > 0) {
          row.getCell('status').value = 'Overtime/Extra';
        } else {
          row.getCell('work').value = '-';
          if (isHoliday) {
            row.getCell('status').value = 'Holiday';
            row.getCell('status').font = { color: { argb: 'FF9977' } }; // Light Orange
          } else {
            row.getCell('status').value = 'Off Day';
            row.getCell('status').font = { color: { argb: 'FF999999' } }; // Grey
          }
        }
      } else {
        // Is a working day
        if (workHours < 8) {
          row.getCell('work').font = { color: { argb: 'FFFF0000' } }; // Red
          row.getCell('status').font = { color: { argb: 'FFFF0000' } };
        } else if (workHours >= 8) {
          row.getCell('work').font = { color: { argb: 'FF008000' } }; // Green
          row.getCell('status').font = { color: { argb: 'FF008000' } };
        }
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

// ADMIN/HR: create user
app.post('/admin/create-user', checkUserManagement, async (req, res) => {
  const {
    name, email, role, division, secondaryDivision,
    password, canAccessSupervisorDashboard,
    durationWorkHours, durationBreakMinutes, shiftGroup
  } = req.body;

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
    durationWorkHours: durationWorkHours ? parseInt(durationWorkHours) : 8,
    durationBreakMinutes: durationBreakMinutes ? parseInt(durationBreakMinutes) : 60,
    shiftGroup: shiftGroup || undefined,
    password: hashed
  });

  await u.save();
  await u.save();

  const referer = req.get('Referer');
  if (referer && referer.includes('/supervisor')) {
    return res.redirect('/supervisor?msg=userCreated');
  }
  res.redirect('/?msg=userCreated');
});

// ADMIN/HR: update user
app.post('/admin/update-user', checkUserManagement, async (req, res) => {
  try {
    const {
      userId, name, email, role, division, secondaryDivision,
      password, canAccessSupervisorDashboard,
      durationWorkHours, durationBreakMinutes, shiftGroup
    } = req.body;

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
    user.durationWorkHours = durationWorkHours ? parseInt(durationWorkHours) : 8;
    user.durationBreakMinutes = durationBreakMinutes ? parseInt(durationBreakMinutes) : 60;
    user.shiftGroup = shiftGroup || undefined;

    if (password && password.trim()) {
      user.password = await bcrypt.hash(password, 10);
    }

    await user.save();
    await user.save();

    // Redirect based on Referer or Origin
    const referer = req.get('Referer');
    if (referer && referer.includes('/supervisor')) {
      return res.redirect('/supervisor?msg=userUpdated');
    }
    res.redirect('/?msg=userUpdated');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

// ADMIN/HR: delete user + history
app.post('/admin/delete-user', checkUserManagement, async (req, res) => {
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
    // If accuracy is provided and > 500 meters, reject (Relaxed from 100m)
    // Note: Some browsers might not send accuracy, or send 0 if unknown. 
    // We only reject if it's explicitly bad.
    if (accuracy && acc > 500) {
      return res.status(400).json({
        error: `Location accuracy too low (${Math.round(acc)}m). Please wait for better GPS signal.`
      });
    }

    // Validasi Geofence (Server-side check)
    // -------------------------------------
    const settings = await SystemSettings.findOne();
    const officeLat = settings ? settings.officeLat : Number(process.env.OFFICE_LAT || 0);
    const officeLng = settings ? settings.officeLng : Number(process.env.OFFICE_LNG || 0);
    const radius = settings ? settings.officeRadius : Number(process.env.OFFICE_RADIUS_METERS || 100);

    console.log(`[Check-In Debug] Settings -> Lat: ${officeLat}, Lng: ${officeLng}, Radius: ${radius}m`);
    console.log(`[Check-In Debug] User -> Lat: ${lat}, Lng: ${lng}`);

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
    console.log(`[Check-In Debug] Calculated Distance: ${Math.round(dist)}m`);

    // Strict for Check-In/Break-Start, Relaxed for Check-Out/Break-End
    let allowedRadius = radius;
    if (action === 'check-out' || action === 'break-end') {
      // Allow up to 200m OR 5x radius for checking out (handles GPS drift or walking to parking lot)
      allowedRadius = Math.max(radius * 5, 200);
    }

    if (dist > allowedRadius) {
      return res.status(400).json({
        error: `Out of allowed location. Distance: ${Math.round(dist)}m (Allowed: ${allowedRadius}m)`
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

// ADMIN/HR: Update Saturday Shifts (Bulk)
app.post('/admin/update-saturday-shifts', checkUserManagement, async (req, res) => {
  try {
    const { saturdayUsers } = req.body;
    // saturdayUsers is array of IDs (or single ID string, or undefined if none)

    let shiftIds = [];
    if (saturdayUsers) {
      if (Array.isArray(saturdayUsers)) shiftIds = saturdayUsers;
      else shiftIds = [saturdayUsers];
    }

    // 1. Determine Scope (Admin vs HR)
    let query = {};
    if (req.user.role !== 'Admin') {
      const divs = [];
      // If "All Division", they effectively have global scope for this (or at least all staff)
      const hasAll = req.user.division === 'All Division' || req.user.secondaryDivision === 'All Division';

      if (!hasAll) {
        if (req.user.division) divs.push(req.user.division);
        if (req.user.secondaryDivision) divs.push(req.user.secondaryDivision);
        query = { division: { $in: divs } };
      }
    }

    const usersToUpdate = await User.find(query);

    // 2. Iterate and update ONLY scoped users
    const updates = usersToUpdate.map(async (u) => {
      const worksSat = shiftIds.includes(u._id.toString());

      // Base days: Mon(1) - Fri(5)
      let newDays = [1, 2, 3, 4, 5];

      if (worksSat) {
        newDays.push(6); // Add Saturday
      }

      u.workingDays = newDays;
      return u.save();
    });

    await Promise.all(updates);

    // Redirect back to referring page if possible, or dashboard
    const isSupervisor = req.user.role !== 'Admin';
    // If user has 'All' check -> 'All'
    // But actually, 'All' is a property of the USER not the selection.
    // The selection UI helps setting the DB.
    // Wait, the UI logic in 'selectShiftGroup' is purely client-side helper.
    // The actual submission sends 'saturdayUsers' array.
    // So we don't need to change anything here regarding logic, just the redirect.

    const referer = req.get('Referer');
    if (referer && referer.includes('/supervisor')) {
      return res.redirect('/supervisor?msg=shiftsUpdated');
    }
    return res.redirect('/?msg=shiftsUpdated');

  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

// --- HOLIDAY ROUTES ---
app.post('/admin/holidays/add', ensureAuth, ensureRole(['Admin', 'HR']), async (req, res) => {
  try {
    const { date } = req.body; // YYYY-MM-DD
    if (date) {
      let settings = await SystemSettings.findOne();
      if (!settings) settings = new SystemSettings();
      if (!settings.holidays) settings.holidays = [];

      // Prevent duplicates
      if (!settings.holidays.includes(date)) {
        settings.holidays.push(date);
        settings.holidays.sort(); // Keep sorted
        await settings.save();
      }
    }
    const referer = req.get('Referer');
    res.redirect(referer || '/?msg=holidayAdded');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

app.post('/admin/holidays/remove', ensureAuth, ensureRole(['Admin', 'HR']), async (req, res) => {
  try {
    const { date } = req.body;
    if (date) {
      let settings = await SystemSettings.findOne();
      if (settings) {
        if (!settings.holidays) settings.holidays = [];
        settings.holidays = settings.holidays.filter(h => h !== date);
        await settings.save();
      }
    }
    const referer = req.get('Referer');
    res.redirect(referer || '/?msg=holidayRemoved');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

// Export Saturday History (User specific)
app.get('/admin/attendance/export-saturday', ensureAuth, ensureRole(['Admin', 'HR', 'Supervisor']), async (req, res) => {
  try {
    const { userId, month } = req.query;
    const user = await User.findById(userId);
    if (!user) return res.status(404).send('User not found');

    let query = { user: userId };
    let monthLabel = "All Time";

    // Filter by month if provided
    if (month) {
      const startOfMonth = moment(month, 'YYYY-MM').startOf('month').toDate();
      const endOfMonth = moment(month, 'YYYY-MM').endOf('month').toDate();
      query.time = { $gte: startOfMonth, $lte: endOfMonth };
      monthLabel = moment(month, 'YYYY-MM').format('MMMM YYYY');
    }

    const records = await Attendance.find(query).sort({ time: 1 });

    // FIX: Use ExcelJS, not excel
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Saturday Attendance');

    // New Columns per request
    worksheet.columns = [
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Day', key: 'day', width: 12 },
      { header: 'Check In', key: 'checkIn', width: 10 },
      { header: 'Check Out', key: 'checkOut', width: 10 },
      { header: 'Work (Hrs)', key: 'work', width: 15 },
      { header: 'Break (Hrs)', key: 'break', width: 15 },
      { header: 'Status', key: 'status', width: 12 }
    ];

    // Style the header
    worksheet.getRow(1).font = { bold: true };

    const recordsByDate = new Map();
    records.forEach(r => {
      const d = moment(r.time).format('YYYY-MM-DD');
      if (!recordsByDate.has(d)) recordsByDate.set(d, []);
      recordsByDate.get(d).push(r);
    });

    // Helper
    const formatDuration = (sec) => {
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);
      return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    const indonesianDays = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];

    for (const [dateStr, recs] of recordsByDate) {
      const dateObj = moment(dateStr);
      if (dateObj.isoWeekday() !== 6) continue;

      // Logic: Find events
      const checkIn = recs.find(r => r.action === 'check-in' || r.type === 'CHECK_IN');
      const checkOut = recs.find(r => r.action === 'check-out' || r.type === 'CHECK_OUT');

      // Break calculation
      let breakSeconds = 0;
      const breakStarts = recs.filter(r => r.action === 'break-start');
      const breakEnds = recs.filter(r => r.action === 'break-end');
      // Simple pair matching (assuming orderly data for export)
      for (let i = 0; i < Math.min(breakStarts.length, breakEnds.length); i++) {
        breakSeconds += (new Date(breakEnds[i].time) - new Date(breakStarts[i].time)) / 1000;
      }

      let workStr = '-';
      let breakStr = formatDuration(breakSeconds);
      let status = 'Absent'; // Default
      let isUnder = false;

      if (checkIn) {
        status = 'Working...';
        if (checkOut) {
          const grossDiff = (new Date(checkOut.time) - new Date(checkIn.time)) / 1000;
          const netWork = grossDiff - breakSeconds; // Subtract break? Or just use gross? Adopting gross per previous logic usually.
          // Actually User Image: Work 1:00:00, Break 00:00:00. 
          // Work 00:23:35, Break 00:09:45.
          // This implies Work is Net or Gross? Usually Net.
          // I'll display Net Work.

          workStr = formatDuration(netWork);

          // Status Logic: e.g. < 4 hours on Saturday = Under?
          // Using 4 hours (14400 sec) as hypothetical threshold
          if (netWork < 14400) {
            status = 'Under';
            isUnder = true;
          } else {
            status = 'Present';
          }
        }
      }

      const row = worksheet.addRow({
        date: dateStr,
        day: indonesianDays[dateObj.day()],
        checkIn: checkIn ? moment(checkIn.time).format('HH:mm') : '-',
        checkOut: checkOut ? moment(checkOut.time).format('HH:mm') : '-',
        work: workStr,
        break: breakStr,
        status: status
      });

      // Styling 'Work (Hrs)'
      if (isUnder) {
        row.getCell('work').font = { color: { argb: 'FFFF0000' } }; // Red
      }
    }

    const safeName = user.name.replace(/[^a-zA-Z0-9]/g, '_');
    const fileName = `saturday_attendance_${safeName}_${month || 'all'}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating export');
  }
});

// Update System Settings (Holidays, etc)
app.post('/admin/update-settings', ensureRole('Admin'), async (req, res) => {
  try {
    const { saturdayWorkHours, officeRadiusMeters, holidayDates } = req.body;

    let settings = await SystemSettings.findOne();
    if (!settings) settings = new SystemSettings();

    if (saturdayWorkHours) settings.saturdayWorkHours = parseFloat(saturdayWorkHours);
    if (officeRadiusMeters) settings.officeRadius = parseFloat(officeRadiusMeters);

    if (typeof holidayDates === 'string') {
      // Expect format "YYYY-MM-DD, YYYY-MM-DD" or similar
      // Split by comma or newline
      const dates = holidayDates.split(/[\n,]+/).map(s => s.trim()).filter(s => s.match(/^\d{4}-\d{2}-\d{2}$/));
      // Unique
      settings.holidays = [...new Set(dates)].sort();
    }

    await settings.save();
    res.redirect('/?msg=settingsUpdated');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

// Update Office Location Settings
app.post('/admin/settings/update', ensureAuth, ensureRole('Admin'), async (req, res) => {
  try {
    const { officeLat, officeLng, officeRadius } = req.body;
    let settings = await SystemSettings.findOne();
    if (!settings) settings = new SystemSettings();

    if (officeLat) settings.officeLat = parseFloat(officeLat);
    if (officeLng) settings.officeLng = parseFloat(officeLng);
    if (officeRadius) settings.officeRadius = parseFloat(officeRadius);

    await settings.save();

    // Sync with .env
    try {
      const fs = require('fs');
      const envPath = path.join(__dirname, '.env');
      if (fs.existsSync(envPath)) {
        let envContent = fs.readFileSync(envPath, 'utf8');

        const updateKey = (key, val) => {
          const regex = new RegExp(`^${key}=.*`, 'm');
          if (regex.test(envContent)) {
            envContent = envContent.replace(regex, `${key}=${val}`);
          } else {
            envContent += `\n${key}=${val}`;
          }
        };

        if (officeLat) updateKey('OFFICE_LAT', officeLat);
        if (officeLng) updateKey('OFFICE_LNG', officeLng);
        if (officeRadius) updateKey('OFFICE_RADIUS_METERS', officeRadius);

        fs.writeFileSync(envPath, envContent);
      }
    } catch (envErr) {
      console.error('Failed to update .env file:', envErr);
    }

    res.redirect('/admin?msg=settingsUpdated');
  } catch (err) {
    console.error(err);
    res.redirect('/admin?msg=error');
  }
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
// Helper: Get User Status (Working/Break/Idle)
async function getUserStatus(userId) {
  const today = moment();
  const startOfDay = today.clone().startOf('day').toDate();
  const endOfDay = today.clone().endOf('day').toDate();

  const records = await Attendance.find({
    user: userId,
    time: { $gte: startOfDay, $lte: endOfDay }
  }).sort({ time: 1 });

  let lastCheckIn = null;
  let lastBreakStart = null;

  records.forEach(r => {
    const t = r.time;
    if (r.action === 'check-in') {
      lastCheckIn = t;
    } else if (r.action === 'check-out') {
      if (lastCheckIn) lastCheckIn = null;
    } else if (r.action === 'break-start') {
      if (lastCheckIn) lastCheckIn = null;
      lastBreakStart = t;
    } else if (r.action === 'break-end') {
      if (lastBreakStart) lastBreakStart = null;
      lastCheckIn = t;
    }
  });

  if (lastCheckIn) return { status: 'working', label: 'Working...' };
  if (lastBreakStart) return { status: 'break', label: 'On Break...' };
  return { status: 'idle', label: '' };
}

// Helper: Get Daily Stats for a User (for Real-time monitoring)
async function getDailyStats(userId, dateObj = moment()) {
  const startOfDay = dateObj.clone().startOf('day').toDate();
  const endOfDay = dateObj.clone().endOf('day').toDate();

  const records = await Attendance.find({
    user: userId,
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

  return {
    workSeconds,
    breakSeconds,
    status,
    currentWorkStart: currentWorkStart ? currentWorkStart.getTime() : null,
    currentBreakStart: currentBreakStart ? currentBreakStart.getTime() : null
  };
}



// Start server
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
  console.log("✅ MongoDB connected");
  await ensureDefaultAdmin();
  // Start server
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

}).catch(err => console.error("MongoDB connection error:", err));
