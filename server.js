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
const moment = require('moment-timezone'); // Check-In Timezone Fix
moment.locale('id');
moment.tz.setDefault("Asia/Makassar"); // UTC+8
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
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    autoRemove: 'native' // Fix for "Unable to find the session to touch"
  })
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
  const allowedRoles = ['Supervisor', 'General Manager', 'Operational Manager'];
  const isHrOrAll = req.user.division === 'HR' ||
    req.user.division === 'All Division' ||
    req.user.secondaryDivision === 'HR' ||
    req.user.secondaryDivision === 'All Division';

  if (allowedRoles.includes(req.user.role) && isHrOrAll) {
    return next();
  }

  return res.status(403).send('Forbidden: HR Access Required');
}

// Middleware to check pending logout
app.use((req, res, next) => {
  if (req.session && req.session.logoutScheduledAt) {
    if (Date.now() > req.session.logoutScheduledAt) {
      console.log(`[Auto-Logout] Scheduled logout executed for ${req.user ? req.user.email : 'Unknown'}`);
      req.logout((err) => {
        req.session.destroy();
        res.redirect('/login');
      });
      return;
    } else {
      // User is back! Cancel scheduled logout
      console.log(`[Auto-Logout] User returned. Cancelled scheduled logout.`);
      delete req.session.logoutScheduledAt;
      req.session.save();
    }
  }
  next();
});

// Logout Routes
app.get('/logout', (req, res) => {
  console.log(`[Logout] User ${req.user ? req.user.email : 'Unknown'} manually logging out.`);
  req.logout((err) => {
    if (err) console.error(err);
    req.session.destroy(); // Explicitly destroy session
    res.redirect('/login');
  });
});

app.post('/auth/logout', (req, res) => {
  console.log(`[Auto-Logout] Beacon received for ${req.user ? req.user.email : 'Unknown'}`);
  req.logout((err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error');
    }
    req.session.destroy(); // Explicitly destroy session
    // sendBeacon expects no response, but we send 200 OK
    res.status(200).send('Logged out');
  });
});

app.post('/auth/logout-delayed', (req, res) => {
  if (req.session) {
    console.log(`[Auto-Logout] Scheduling logout in 1 minute for ${req.user ? req.user.email : 'Unknown'}`);
    req.session.logoutScheduledAt = Date.now() + 60000; // 1 minute
    req.session.save();
  }
  res.status(200).send('Scheduled');
});

// Helper: Format Seconds to HH:mm:ss
function formatDuration(sec) {
  sec = Math.floor(sec);
  if (sec < 0) sec = 0;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const pad = n => n.toString().padStart(2, '0');
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

// Helper: Get Real-Time Daily Stats
async function getDailyStats(userId) {
  const today = moment();
  const startOfDay = today.clone().startOf('day').toDate();
  const endOfDay = today.clone().endOf('day').toDate();

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
    workText: formatDuration(workSeconds),
    breakText: formatDuration(breakSeconds),
    workIntervals,
    breakIntervals,
    status,
    currentWorkStart,
    currentBreakStart
  };
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

    // --- TODAY'S OVERVIEW LOGIC (Admin sees all, but can filter) ---
    // 1. Managed Divisions (Admin manages everything)
    const managedDivisions = ['OC', 'N1', 'SnG', 'e1', 'CE', 'EC', 'PX', 'FN', 'HR', 'GM'];

    // 2. Active Division (Filter)
    let activeDivision = req.query.division;
    if (!activeDivision || !managedDivisions.includes(activeDivision)) {
      activeDivision = 'OC'; // Default to OC if not specified
    }

    // 3. Fetch Members of Active Division
    const divisionMembers = await User.find({ division: activeDivision }).sort({ name: 1 });

    // 4. Calculate Daily Stats
    const memberSummaries = [];
    for (const member of divisionMembers) {
      const stats = await getDailyStats(member._id);
      memberSummaries.push({
        user: member,
        todayStats: stats
      });
    }

    return res.render('admin_dashboard', {
      user: req.user,
      users,
      token,
      settings,
      moment,
      selectedMonth,
      query: req.query,
      // New Data for Today's Overview
      managedDivisions,
      division: activeDivision,
      memberSummaries
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

  // Attendance hari ini (Using Helper)
  const stats = await getDailyStats(req.user._id);

  const attendanceSummary = {
    dateLabel: today.format('dddd, DD MMMM YYYY'),
    workText: stats.workText,
    breakText: stats.breakText,
    workIntervals: stats.workIntervals.map(i => ({
      start: moment(i.start).format('HH:mm:ss'),
      end: moment(i.end).format('HH:mm:ss')
    })),
    breakIntervals: stats.breakIntervals.map(i => ({
      start: moment(i.start).format('HH:mm:ss'),
      end: moment(i.end).format('HH:mm:ss')
    })),
    status: stats.status,
    baseWorkSeconds: stats.workSeconds,
    baseBreakSeconds: stats.breakSeconds,
    currentWorkStart: stats.currentWorkStart ? stats.currentWorkStart.getTime() : null,
    currentBreakStart: stats.currentBreakStart ? stats.currentBreakStart.getTime() : null
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
      managedDivisions = ['OC', 'N1', 'SnG', 'e1', 'CE', 'EC', 'PX', 'FN', 'HR', 'GM'];
    }

    managedDivisions = [...new Set(managedDivisions)];

    // divisi aktif (dipilih dari query ?division=)
    let activeDivision = null;
    if (managedDivisions.length) {
      const requested = req.query.division;
      activeDivision = managedDivisions.includes(requested) ? requested : managedDivisions[0];
    }

    console.log(`[Supervisor Debug] User: ${req.user.email}, Role: ${req.user.role}, Div: ${req.user.division}`);
    console.log(`[Supervisor Debug] Managed: ${JSON.stringify(managedDivisions)}`);
    console.log(`[Supervisor Debug] Active Division: ${activeDivision}`);

    const startOfMonth = moment(monthParam + '-01', 'YYYY-MM-DD').startOf('month');
    const endOfMonth = startOfMonth.clone().endOf('month');

    const members = activeDivision
      ? await User.find({ division: activeDivision }).sort({ name: 1 })
      : [];

    console.log(`[Supervisor Debug] Members found in ${activeDivision}: ${members.length}`);

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

      // Get Today's Real-Time Stats
      const todayStats = await getDailyStats(m._id);

      memberSummaries.push({
        user: m,
        workSeconds,
        workText: formatDuration(workSeconds), // Fix: Add formatted duration
        todayStats, // New realtime data
        saturdayHoursStr: m.saturdayHoursStr,
        hasSaturdayAttendance: m.hasSaturdayAttendance
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
    }

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

    // Logic for "Today's Overview" Tab (Admin sees all divisions)
    const managedDivisions = ['GM', 'OC', 'N1', 'SnG', 'e1', 'CE', 'EC', 'PX', 'FN', 'HR'];
    const division = req.query.division || 'GM'; // Default Division

    const divisionMembers = await User.find({ division }).sort({ name: 1 });
    const memberSummaries = [];

    for (const m of divisionMembers) {
      const todayStats = await getDailyStats(m._id);
      memberSummaries.push({
        user: m,
        todayStats
      });
    }

    res.render('admin_dashboard', {
      user: req.user,
      users,
      settings,
      selectedMonth,
      token: tokenData,
      query: req.query,
      // New variables for Today's Overview
      managedDivisions,
      division,
      memberSummaries,
      divisionMembers
    });
  } catch (err) {
    console.error('[ADMIN DASHBOARD ERROR]', err);
    try {
      require('fs').appendFileSync('debug_error.log', `[${new Date().toISOString()}] Admin Dashboard Error: ${err.message}\n${err.stack}\n\n`);
    } catch (e) { console.error('Failed to write log:', e); }
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



// ADMIN: export User History (Yearly)
app.get('/admin/attendance/export-yearly-final', ensureRole('Admin'), async (req, res) => {
  console.log('[DEBUG] Hit export-yearly-final');
  try {
    const { userId } = req.query;
    let yearParam = req.query.year;
    if (!yearParam || !/^\d{4}$/.test(yearParam)) {
      yearParam = moment().format('YYYY');
    }

    console.log(`[DEBUG] Exporting for Year: ${yearParam}, User: ${userId}`);

    if (!userId) {
      return res.status(400).send('userId is required');
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send('User not found');
    }

    const startOfYear = moment(`${yearParam}-01-01`, 'YYYY-MM-DD').startOf('year');
    const endOfYear = startOfYear.clone().endOf('year');

    if (!startOfYear.isValid() || !endOfYear.isValid()) {
      console.error('[ERROR] Invalid Date Calculation');
      return res.status(400).send('Invalid Year');
    }

    // --- Stream Data via Cursor (Memory Efficient) ---
    console.time('DB_Stream');
    const cursor = Attendance.find({
      user: userId,
      time: { $gte: startOfYear.toDate(), $lte: endOfYear.toDate() },
      action: { $in: ['check-in', 'check-out', 'break-start', 'break-end'] }
    })
      .select('user time action')
      .sort({ time: 1 })
      .lean()
      .cursor({ batchSize: 1000 });

    const settings = await SystemSettings.findOne() || { holidays: [], saturdayWorkHours: 4 };

    // --- Process Data (Unified dayMap) ---
    const dayMap = new Map();
    // Initialize empty days first
    const curr = startOfYear.clone();
    let safeGuard = 0;
    while ((curr.isBefore(endOfYear) || curr.isSame(endOfYear, 'day')) && safeGuard < 400) {
      const dKey = curr.format('YYYY-MM-DD');
      dayMap.set(dKey, {
        dateObj: curr.clone(),
        dayName: curr.locale('id').format('dddd'),
        in: null, out: null, workMs: 0, breakMs: 0,
        checkIn: null, checkOut: null,
        lastCheckIn: null, lastBreakStart: null
      });
      curr.add(1, 'days');
      safeGuard++;
    }

    // Process cursor with caching
    let count = 0;

    // Optimization: Cache date string to avoid moment() on every record
    // Records are sorted by time, so we often hit the same day multiple times in a row.
    let cachedDayKey = null;
    let cachedDayStart = 0;
    let cachedDayEnd = 0;

    for (let r = await cursor.next(); r != null; r = await cursor.next()) {
      count++;
      const t = r.time.getTime(); // Raw MS

      // Determine dKey efficiently
      let dKey;
      if (t >= cachedDayStart && t <= cachedDayEnd && cachedDayKey) {
        dKey = cachedDayKey;
      } else {
        // New day detected (or first run)
        const m = moment(r.time);
        dKey = m.format('YYYY-MM-DD');
        cachedDayKey = dKey;
        cachedDayStart = m.startOf('day').valueOf();
        cachedDayEnd = m.endOf('day').valueOf();
      }

      if (dayMap.has(dKey)) {
        const day = dayMap.get(dKey);

        // logic...
        if (r.action === 'check-in') {
          if (!day.checkIn) day.checkIn = r.time;
          if (!day.in) day.in = r.time;
          day.lastCheckIn = t;
          day.lastBreakStart = null;
        } else if (r.action === 'check-out') {
          if (!day.checkOut || r.time > day.checkOut) day.checkOut = r.time;
          if (!day.out || r.time > day.out) day.out = r.time;
          if (day.lastCheckIn) {
            day.workMs += (t - day.lastCheckIn);
            day.lastCheckIn = null;
          }
        } else if (r.action === 'break-start') {
          if (day.lastCheckIn) {
            day.workMs += (t - day.lastCheckIn);
            day.lastCheckIn = null;
          }
          day.lastBreakStart = t;
        } else if (r.action === 'break-end') {
          if (day.lastBreakStart) {
            day.breakMs += (t - day.lastBreakStart);
            day.lastBreakStart = null;
          }
          day.lastCheckIn = t;
        }
      }
    }
    console.timeEnd('DB_Stream');
    console.log(`[DEBUG] Processed ${count} records via stream`);

    // --- Generate Excel ---
    const workbook = new ExcelJS.Workbook();

    // Defined Styles (Code only, no template load for memory safety)
    const headerStyle = { font: { bold: true, color: { argb: 'FFFFFFFF' } }, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } }, border: null };
    const dataStyle = { font: {}, border: null };
    const weeklyStyle = { font: { bold: true }, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEEEEEE' } }, border: null };

    // Helper formatters
    const formatDur = (ms) => {
      if (!ms) return "00:00:00";
      const h = Math.floor(ms / 3600000);
      const m = Math.floor((ms % 3600000) / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    console.log('[DEBUG] Workbook created. Generating Sheet 1...');
    // --- SHEET 1: Yearly Summary (Dashboard Style - Week 1-5) ---
    const wsYear = workbook.addWorksheet('Yearly Summary');
    try {
      wsYear.getColumn(1).width = 8; wsYear.getColumn(6).width = 8;
      wsYear.getColumn(2).width = 15; wsYear.getColumn(7).width = 15;
      wsYear.getColumn(3).width = 15; wsYear.getColumn(8).width = 15;
      wsYear.getColumn(4).width = 15; wsYear.getColumn(9).width = 15;
      wsYear.getColumn(5).width = 2;

      const renderMonthBlock = (monthIndex, startRow, startCol) => {
        // ... (same logic, just inside try/log if needed) ...
        const mObj = moment(yearParam + '-01-01', 'YYYY-MM-DD').month(monthIndex);
        const mName = mObj.format('MMMM YYYY');

        const hCell = wsYear.getCell(startRow, startCol);
        hCell.value = mName;
        hCell.font = headerStyle.font;
        hCell.fill = headerStyle.fill;
        try { wsYear.mergeCells(startRow, startCol, startRow, startCol + 3); } catch (e) { }

        const subRow = startRow + 1;
        ['Week', 'Total Work', 'Total Break', 'Status'].forEach((h, i) => {
          const cell = wsYear.getCell(subRow, startCol + i);
          cell.value = h;
          cell.font = headerStyle.font;
          cell.fill = headerStyle.fill;
        });

        // Filter days
        const daysInMonth = Array.from(dayMap.values()).filter(d => d.dateObj.month() === monthIndex);

        // Group by Week 1-5
        const weekMap = new Map();
        daysInMonth.forEach(d => {
          const iso = d.dateObj.isoWeek();
          if (!weekMap.has(iso)) weekMap.set(iso, { work: 0, break: 0 });
          const w = weekMap.get(iso);
          w.work += d.workMs;
          w.break += d.breakMs;
        });
        const sortedIsos = [...weekMap.keys()].sort((a, b) => a - b);

        let rOffset = 2;
        sortedIsos.forEach((iso, idx) => {
          const wData = weekMap.get(iso);
          const wNum = idx + 1;
          const r = startRow + rOffset;

          wsYear.getCell(r, startCol).value = wNum;
          wsYear.getCell(r, startCol + 1).value = formatDur(wData.work);
          wsYear.getCell(r, startCol + 2).value = formatDur(wData.break);

          const msg = (wData.work >= (40 * 3600000)) ? 'Target Met' : 'Under Target';
          const sCell = wsYear.getCell(r, startCol + 3);
          sCell.value = msg;
          if (msg === 'Under Target') sCell.font = { color: { argb: 'FFFF0000' } };
          else sCell.font = { color: { argb: 'FF000000' } };
          rOffset++;
        });

        // Fill empty to 5 rows
        for (let k = sortedIsos.length; k < 5; k++) {
          const r = startRow + rOffset;
          wsYear.getCell(r, startCol).value = k + 1;
          wsYear.getCell(r, startCol + 1).value = "00:00:00";
          wsYear.getCell(r, startCol + 2).value = "00:00:00";
          const sCell = wsYear.getCell(r, startCol + 3);
          sCell.value = "Under Target";
          sCell.font = { color: { argb: 'FFFF0000' } };
          rOffset++;
        }
        return 9;
      };

      let leftR = 1; let rightR = 1;
      for (let m = 0; m < 12; m++) {
        if (m < 6) { renderMonthBlock(m, leftR, 1); leftR += 10; }
        else { renderMonthBlock(m, rightR, 6); rightR += 10; }
      }
    } catch (s1Err) { console.error('Sheet 1 Error:', s1Err); throw s1Err; }


    // --- SHARED HELPER FROM DIVISION EXPORT ---
    const addDataRow = (sheet, key, val, wNum) => {
      const workHours = val.workMs / 3600000;
      const breakHours = val.breakMs / 3600000;

      let status = 'Off Day';
      const dayIdx = val.dateObj.day();
      // user.workingDays might be undefined if not populated or set? 
      // Safe default: 1-5
      const userWorkDays = (user.workingDays && user.workingDays.length > 0) ? user.workingDays : [1, 2, 3, 4, 5];

      const isWeekend = (dayIdx === 0 || dayIdx === 6);
      const isDayOfWeekWork = userWorkDays.includes(dayIdx);
      const isHoliday = settings.holidays && settings.holidays.includes(key);
      const isWorkingDay = isDayOfWeekWork && !isHoliday;

      if (val.checkIn) {
        status = (workHours >= 8) ? 'Target Met' : 'Under Target';
        if (isWeekend || !isWorkingDay) status += ' (Overtime)';
        if (isHoliday) status = 'Holiday (Worked)';
      } else {
        if (isHoliday) status = 'Holiday';
        else status = isWorkingDay ? 'Absent' : 'Off Day';
      }

      const row = sheet.addRow([
        wNum, key, val.dayName,
        val.checkIn ? moment(val.checkIn).format('HH:mm') : '-',
        val.checkOut ? moment(val.checkOut).format('HH:mm') : '-',
        formatDur(val.workMs),
        formatDur(val.breakMs),
        status
      ]);

      row.font = dataStyle.font;

      const statusCell = row.getCell(8);
      const breakCell = row.getCell(7);

      if (status.includes('Target Met')) statusCell.font = { color: { argb: 'FF008000' } };
      else if (status.includes('Under Target') || status === 'Absent') statusCell.font = { color: { argb: 'FFFF0000' } };
      else if (status.includes('Holiday')) statusCell.font = { color: { argb: 'FFEB5E28' } };
      else statusCell.font = { color: { argb: 'FF999999' } };

      if (breakHours > 1) breakCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFCCCC' } };
    };


    console.log('[DEBUG] Generating Sheet 2...');
    // --- SHEET 2: Monthly Summary (CURRENT MONTH ONLY) ---
    const wsMonth = workbook.addWorksheet('Monthly Summary');
    try {
      const hRow1 = wsMonth.addRow(['Week', 'Date', 'Day', 'Clock In', 'Clock Out', 'Total Work', 'Total Break', 'Status']);
      hRow1.eachCell(c => {
        c.font = headerStyle.font; c.fill = headerStyle.fill;
      });
      wsMonth.getColumn(1).width = 8; wsMonth.getColumn(2).width = 15; wsMonth.getColumn(3).width = 15;
      wsMonth.getColumn(4).width = 12; wsMonth.getColumn(5).width = 12; wsMonth.getColumn(6).width = 15;
      wsMonth.getColumn(7).width = 15; wsMonth.getColumn(8).width = 20;

      const sortedDays = Array.from(dayMap.values()).sort((a, b) => a.dateObj - b.dateObj);
      let currentWeek = null;
      let weekWorkMs = 0;

      // Filter for Current Month
      const now = moment();
      const currentMonthStr = now.format('YYYY-MM');
      const currentMonthDays = sortedDays.filter(d => d.dateObj.format('YYYY-MM') === currentMonthStr);

      currentMonthDays.forEach(val => {
        const key = val.dateObj.format('YYYY-MM-DD');
        const weekNum = val.dateObj.isoWeek();

        if (currentWeek !== null && weekNum !== currentWeek) {
          const wRow = wsMonth.addRow([null, null, null, 'Weekly Total', null, null, formatDur(weekWorkMs), null]);
          wRow.font = weeklyStyle.font;
          wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
          weekWorkMs = 0;
        }
        currentWeek = weekNum;
        weekWorkMs += val.workMs;
        addDataRow(wsMonth, key, val, weekNum);
      });
      // Final total
      if (weekWorkMs > 0) {
        const wRow = wsMonth.addRow([null, null, null, 'Weekly Total', null, null, formatDur(weekWorkMs), null]);
        wRow.font = weeklyStyle.font;
        wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
      }
    } catch (s2Err) { console.error('Sheet 2 Error:', s2Err); throw s2Err; }


    console.log('[DEBUG] Generating Sheet 3...');
    // --- SHEET 3: Weekly Summary (CURRENT WEEK ONLY) ---
    const wsWeek = workbook.addWorksheet('Weekly Summary');
    try {
      const hRowS3 = wsWeek.addRow(['Week', 'Date', 'Day', 'Clock In', 'Clock Out', 'Total Work', 'Total Break', 'Status']);
      hRowS3.eachCell(c => {
        c.font = headerStyle.font; c.fill = headerStyle.fill;
      });
      wsWeek.getColumn(1).width = 8; wsWeek.getColumn(2).width = 15; wsWeek.getColumn(3).width = 15;
      wsWeek.getColumn(4).width = 12; wsWeek.getColumn(5).width = 12; wsWeek.getColumn(6).width = 15;
      wsWeek.getColumn(7).width = 15; wsWeek.getColumn(8).width = 20;

      const now = moment();
      const targetWeek = now.isoWeek();
      let wSum = 0;

      // sortDays is already available from Sheet 2 scope? Yes, defined above.
      // But let's re-use sortedDays
      const sortedDays = Array.from(dayMap.values()).sort((a, b) => a.dateObj - b.dateObj);

      // Yes, just filter records for that week.
      sortedDays.forEach(val => {
        if (val.dateObj.isoWeek() === targetWeek) {
          const key = val.dateObj.format('YYYY-MM-DD');
          addDataRow(wsWeek, key, val, targetWeek);
          wSum += val.workMs;
        }
      });

      if (wSum > 0 || sortedDays.some(d => d.dateObj.isoWeek() === targetWeek)) {
        const wRow = wsWeek.addRow([null, null, null, 'Weekly Total', null, null, formatDur(wSum), null]);
        wRow.font = weeklyStyle.font;
        wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
      }
    } catch (s3Err) { console.error('Sheet 3 Error:', s3Err); throw s3Err; }


    console.log('[DEBUG] Generating Sheet 4...');
    // --- SHEET 4: Daily Report (Today Only) ---
    const wsDaily = workbook.addWorksheet('Daily Report');
    try {
      const todayStr = moment().format('YYYY-MM-DD');
      wsDaily.addRow([`Daily Report: ${todayStr}`]).font = { bold: true, size: 12 };

      const hRow3 = wsDaily.addRow(['Name', 'Email', 'Time', 'Action']);
      hRow3.eachCell(c => { c.font = headerStyle.font; c.fill = headerStyle.fill; });

      wsDaily.getColumn(1).width = 25; wsDaily.getColumn(2).width = 30;
      wsDaily.getColumn(3).width = 15; wsDaily.getColumn(4).width = 15;

      // Fetch Today's records specifically (small query)
      const startOfToday = moment().startOf('day').toDate();
      const endOfToday = moment().endOf('day').toDate();
      const todayRecords = await Attendance.find({
        user: userId,
        time: { $gte: startOfToday, $lte: endOfToday }
      }).sort({ time: 1 }).lean();

      if (todayRecords.length === 0) {
        wsDaily.addRow(['No attendance records found for today.']);
      } else {
        todayRecords.forEach(r => {
          const rRow = wsDaily.addRow([
            user.name, user.email,
            moment(r.time).format('HH:mm:ss'),
            r.action
          ]);
          const actCell = rRow.getCell(4);
          if (r.action === 'check-in') actCell.font = { color: { argb: 'FF008000' } };
          else if (r.action === 'check-out') actCell.font = { color: { argb: 'FFFF0000' } };
        });
      }
    } catch (s4Err) { console.error('Sheet 4 Error:', s4Err); throw s4Err; }

    // Filename
    const safeName = (user.name || 'user').replace(/[^a-zA-Z0-9]/g, '_');
    const fileName = `history-${safeName}-${yearParam}.xlsx`;
    console.log('[DEBUG] Writing Xlsx...');

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();
    console.log('[DEBUG] Done.');

  } catch (err) {
    console.error('FINAL ERROR:', err);
    res.status(500).send('Error generating History Excel: ' + (err.message || err));
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
    }).sort({ time: 1 }); // Sort by time globally for the list

    const users = await User.find({});
    const userMap = new Map(users.map(u => [u._id.toString(), u]));

    // FIX: Clean Export - Copy styles from template logic
    const workbook = new ExcelJS.Workbook();
    const templatePath = path.join(__dirname, 'MasterFile', 'Export All Attendances.xlsx');

    // Style placeholders (Default)
    let headerRowFont = { bold: true };
    let headerRowFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } };
    let headerRowBorder = null;

    // Try to read template styles
    try {
      const templateWorkbook = new ExcelJS.Workbook();
      await templateWorkbook.xlsx.readFile(templatePath);
      const templateSheet = templateWorkbook.getWorksheet(1);
      if (templateSheet) {
        const r2 = templateSheet.getRow(2);
        if (r2.font) headerRowFont = r2.font;
        if (r2.getCell(2).fill) headerRowFill = r2.getCell(2).fill;
        if (r2.getCell(2).border) headerRowBorder = r2.getCell(2).border;
      }
    } catch (readErr) {
      console.warn("Template not found, using defaults.", readErr);
    }

    // Group records by User
    const recordsByUser = new Map();
    records.forEach(r => {
      const uid = r.user ? r.user.toString() : 'unknown';
      if (!recordsByUser.has(uid)) recordsByUser.set(uid, []);
      recordsByUser.get(uid).push(r);
    });

    // Sort users alphabetically for sheet order
    const sortedUserIds = [...recordsByUser.keys()].sort((a, b) => {
      const nameA = userMap.get(a)?.name || 'Unknown';
      const nameB = userMap.get(b)?.name || 'Unknown';
      return nameA.localeCompare(nameB);
    });

    // Create a sheet for each user
    for (const uid of sortedUserIds) {
      const userRecs = recordsByUser.get(uid);
      const u = userMap.get(uid) || { name: 'Unknown User' };

      // Sheet Name (sanitize, max 31 chars for Excel)
      let sheetName = u.name.replace(/[*?\/\[\]\\]/g, '').substring(0, 30) || 'User';

      // Ensure unique sheet names
      let counter = 1;
      let originalName = sheetName;
      while (workbook.getWorksheet(sheetName)) {
        sheetName = `${originalName.substring(0, 25)}_${counter++}`;
      }

      const worksheet = workbook.addWorksheet(sheetName);

      // Headers
      const headers = ['Date', 'Time', 'Name', 'Email', 'Division', 'Role', 'Action', 'Lat', 'Lng', 'Radius', 'Hash'];
      const headerRow = worksheet.addRow(headers);

      // Apply Styles to Header
      headerRow.font = headerRowFont;
      headerRow.eachCell((cell) => {
        if (headerRowFill) cell.fill = headerRowFill;
        if (headerRowBorder) cell.border = headerRowBorder;
      });

      // Widths
      worksheet.getColumn(1).width = 15; // Date
      worksheet.getColumn(2).width = 15; // Time
      worksheet.getColumn(3).width = 25; // Name
      worksheet.getColumn(4).width = 30; // Email
      worksheet.getColumn(5).width = 10; // Div
      worksheet.getColumn(6).width = 15; // Role
      worksheet.getColumn(7).width = 15; // Action
      worksheet.getColumn(8).width = 15; // Lat
      worksheet.getColumn(9).width = 15; // Lng
      worksheet.getColumn(10).width = 10; // Radius
      worksheet.getColumn(11).width = 30; // Hash

      // Data
      userRecs.forEach(r => {
        const meta = r.meta || {};

        const row = worksheet.addRow([
          moment(r.time).format('YYYY-MM-DD'),
          moment(r.time).format('HH:mm:ss'),
          u.name || '',
          u.email || '',
          u.division || '',
          u.role || '',
          r.action,
          meta.lat || '-',
          meta.lng || '-',
          meta.accuracy || '-',
          meta.qrToken || '-'
        ]);

        // Style Action
        const actionCell = row.getCell(7);
        if (r.action === 'check-in') actionCell.font = { color: { argb: 'FF008000' } };
        else if (r.action === 'check-out') actionCell.font = { color: { argb: 'FFFF0000' } };


      });
    }

    const fileName = `attendance-all-${yearParam}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating Excel file');
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

    // FIX: Clean Export - Copy styles from template logic
    const workbook = new ExcelJS.Workbook();
    const templatePath = path.join(__dirname, 'MasterFile', 'Export All Attendances.xlsx');

    // Style placeholders (Default)
    let headerRowFont = { bold: true };
    let headerRowFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } }; // Default Blue
    let headerRowBorder = null;

    // Try to read template styles
    try {
      const templateWorkbook = new ExcelJS.Workbook();
      await templateWorkbook.xlsx.readFile(templatePath);
      const templateSheet = templateWorkbook.getWorksheet(1);
      if (templateSheet) {
        // Assume Row 2 is Header in "Export All" per check_export_all_template.js output? 
        // Wait, check_export_all_template.js output at Step 3486:
        // Row 2: [null,"Date","Time","Name","Email","Division","Role","Action","Lat","Lng","Radius","Hash"]
        // So Row 2 is headers!
        const r2 = templateSheet.getRow(2);
        if (r2.font) headerRowFont = r2.font;
        if (r2.getCell(2).fill) headerRowFill = r2.getCell(2).fill; // Use cell 2 as sample
        if (r2.getCell(2).border) headerRowBorder = r2.getCell(2).border;
      }
    } catch (readErr) {
      console.warn("Template not found, using defaults.", readErr);
    }

    // Group records by User
    const recordsByUser = new Map();
    records.forEach(r => {
      const uid = r.user ? r.user.toString() : 'unknown';
      if (!recordsByUser.has(uid)) recordsByUser.set(uid, []);
      recordsByUser.get(uid).push(r);
    });

    // Sort users alphabetically for sheet order
    const sortedUserIds = [...recordsByUser.keys()].sort((a, b) => {
      const nameA = userMap.get(a)?.name || 'Unknown';
      const nameB = userMap.get(b)?.name || 'Unknown';
      return nameA.localeCompare(nameB);
    });

    // Create a sheet for each user
    for (const uid of sortedUserIds) {
      const userRecs = recordsByUser.get(uid);
      const u = userMap.get(uid) || { name: 'Unknown User' };

      // Sheet Name (sanitize, max 31 chars for Excel)
      let sheetName = u.name.replace(/[*?\/\[\]\\]/g, '').substring(0, 30) || 'User';

      // Ensure unique sheet names
      let counter = 1;
      let originalName = sheetName;
      while (workbook.getWorksheet(sheetName)) {
        sheetName = `${originalName.substring(0, 25)}_${counter++}`;
      }

      const worksheet = workbook.addWorksheet(sheetName);

      // Headers
      const headers = ['Date', 'Time', 'Name', 'Email', 'Division', 'Role', 'Action', 'Lat', 'Lng', 'Radius', 'Hash'];
      const headerRow = worksheet.addRow(headers);

      // Apply Styles to Header
      headerRow.font = headerRowFont;
      headerRow.eachCell((cell) => {
        if (headerRowFill) cell.fill = headerRowFill;
        if (headerRowBorder) cell.border = headerRowBorder;
      });

      // Widths
      worksheet.getColumn(1).width = 15; // Date
      worksheet.getColumn(2).width = 15; // Time
      worksheet.getColumn(3).width = 25; // Name
      worksheet.getColumn(4).width = 30; // Email
      worksheet.getColumn(5).width = 10; // Div
      worksheet.getColumn(6).width = 15; // Role
      worksheet.getColumn(7).width = 15; // Action
      worksheet.getColumn(8).width = 15; // Lat
      worksheet.getColumn(9).width = 15; // Lng
      worksheet.getColumn(10).width = 10; // Radius
      worksheet.getColumn(11).width = 30; // Hash

      // Data
      userRecs.forEach(r => {
        const meta = r.meta || {};

        const row = worksheet.addRow([
          moment(r.time).format('YYYY-MM-DD'),
          moment(r.time).format('HH:mm:ss'),
          u.name || '',
          u.email || '',
          u.division || '',
          u.role || '',
          r.action,
          meta.lat || '-',
          meta.lng || '-',
          meta.accuracy || '-',
          meta.qrToken || '-'
        ]);

        // Style Action (Green/Red)
        const actionCell = row.getCell(7); // Column 7
        if (r.action === 'check-in') actionCell.font = { color: { argb: 'FF008000' } };
        else if (r.action === 'check-out') actionCell.font = { color: { argb: 'FFFF0000' } };

        // Borders
        row.eachCell(cell => {
          cell.border = { top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' } };
        });
      });
    }

    const fileName = `attendance-range-${startDate}_to_${endDate}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();

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

    // --- Clean Export with Template ---
    const workbook = new ExcelJS.Workbook();
    const templatePath = path.join(__dirname, 'MasterFile', 'Individual Attendance Detail.xlsx');

    // Default Styles
    let headerStyle = { font: { bold: true }, fill: null, border: null };
    let dataStyle = { font: {}, border: null }; // No border
    let weeklyStyle = { font: { bold: true }, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEEEEEE' } }, border: null };

    // Load Template Styles
    try {
      const tempWb = new ExcelJS.Workbook();
      await tempWb.xlsx.readFile(templatePath);
      const tempSheet = tempWb.getWorksheet(1);
      if (tempSheet) {
        // Row 1: Header
        const r1 = tempSheet.getRow(1);
        if (r1.font) headerStyle.font = r1.font;
        if (r1.getCell(1).fill) headerStyle.fill = r1.getCell(1).fill;
        // if (r1.getCell(1).border) headerStyle.border = r1.getCell(1).border; // Disabled

        // Row 2: Data Example
        const r2 = tempSheet.getRow(2);
        if (r2.font) dataStyle.font = r2.font;
        // if (r2.getCell(1).border) dataStyle.border = r2.getCell(1).border; // Disabled

        // Row 3: Weekly Total
        const r3 = tempSheet.getRow(3);
        if (r3.font) weeklyStyle.font = r3.font;
        if (r3.getCell(1).fill) weeklyStyle.fill = r3.getCell(1).fill;
        // if (r3.getCell(1).border) weeklyStyle.border = r3.getCell(1).border; // Disabled
      }
    } catch (e) {
      console.warn("Individual Template not found, using defaults", e);
    }

    // --- SHEET 1: Monthly Summary ---
    const sheet1 = workbook.addWorksheet('Monthly Summary');
    const headers1 = ['Week', 'Date', 'Day', 'Clock In', 'Clock Out', 'Total Work', 'Total Break', 'Status'];
    const hRow1 = sheet1.addRow(headers1);

    // Force Blue Header if template fails or just always use blue for consistency
    if (!headerStyle.fill) {
      headerStyle.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } };
      headerStyle.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    }

    hRow1.font = headerStyle.font;
    hRow1.eachCell(c => {
      if (headerStyle.fill) c.fill = headerStyle.fill;
      if (headerStyle.border) c.border = headerStyle.border;
    });

    sheet1.getColumn(1).width = 8;
    sheet1.getColumn(2).width = 15;
    sheet1.getColumn(3).width = 15;
    sheet1.getColumn(4).width = 12;
    sheet1.getColumn(5).width = 12;
    sheet1.getColumn(6).width = 15;
    sheet1.getColumn(7).width = 15;
    sheet1.getColumn(8).width = 20;

    let currentWeek = null;
    let weekWorkMs = 0;
    const formatDur = (ms) => {
      if (!ms) return "00:00:00";
      const h = Math.floor(ms / 3600000);
      const m = Math.floor((ms % 3600000) / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    const addDataRow = (sheet, key, val, wNum, isFilteredWeek = false) => {
      const workHours = val.workMs / 3600000;
      const breakHours = val.breakMs / 3600000;

      let status = 'Off Day';
      const dayIdx = val.dateObj.day();
      const isWeekend = (dayIdx === 0 || dayIdx === 6);
      const userWorkDays = user.workingDays && user.workingDays.length > 0 ? user.workingDays : [1, 2, 3, 4, 5];
      const isDayOfWeekWork = userWorkDays.includes(dayIdx);
      const isHoliday = settings.holidays && settings.holidays.includes(key);
      const isWorkingDay = isDayOfWeekWork && !isHoliday;

      if (val.checkIn) {
        status = (workHours >= 8) ? 'Target Met' : 'Under Target';
        if (isWeekend || !isWorkingDay) status += ' (Overtime)';
        if (isHoliday) status = 'Holiday (Worked)';
      } else {
        if (isHoliday) status = 'Holiday';
        else status = isWorkingDay ? 'Absent' : 'Off Day';
      }

      const row = sheet.addRow([
        wNum, key, val.dayName,
        val.checkIn ? moment(val.checkIn).format('HH:mm') : '-',
        val.checkOut ? moment(val.checkOut).format('HH:mm') : '-',
        formatDur(val.workMs),
        formatDur(val.breakMs),
        status
      ]);

      row.font = dataStyle.font;
      row.eachCell(c => { if (dataStyle.border) c.border = dataStyle.border; });

      const statusCell = row.getCell(8);
      const breakCell = row.getCell(7);

      if (status.includes('Target Met')) statusCell.font = { color: { argb: 'FF008000' } };
      else if (status.includes('Under Target') || status === 'Absent') statusCell.font = { color: { argb: 'FFFF0000' } };
      else if (status.includes('Holiday')) statusCell.font = { color: { argb: 'FFEB5E28' } };
      else statusCell.font = { color: { argb: 'FF999999' } };

      if (breakHours > 1) breakCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFCCCC' } };
    };

    // Populate Sheet 1 (Monthly)
    for (const [key, val] of dayMap) {
      const weekNum = val.dateObj.isoWeek();
      if (currentWeek !== null && weekNum !== currentWeek) {
        const wRow = sheet1.addRow([null, null, null, 'Weekly Total', null, null, formatDur(weekWorkMs), null]);
        wRow.font = weeklyStyle.font;
        wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; if (weeklyStyle.border) c.border = weeklyStyle.border; });
        weekWorkMs = 0;
      }
      currentWeek = weekNum;
      weekWorkMs += val.workMs;
      addDataRow(sheet1, key, val, weekNum);
    }
    if (weekWorkMs > 0) {
      const wRow = sheet1.addRow([null, null, null, 'Weekly Total', null, null, formatDur(weekWorkMs), null]);
      wRow.font = weeklyStyle.font;
      wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
    }

    // --- SHEET 2: Weekly Summary ---
    const sheet2 = workbook.addWorksheet('Weekly Summary');
    const hRow2 = sheet2.addRow(headers1);
    hRow2.font = headerStyle.font;
    hRow2.eachCell(c => { if (headerStyle.fill) c.fill = headerStyle.fill; if (headerStyle.border) c.border = headerStyle.border; });

    sheet2.getColumn(1).width = 8; sheet2.getColumn(2).width = 15; sheet2.getColumn(3).width = 15;
    sheet2.getColumn(4).width = 12; sheet2.getColumn(5).width = 12; sheet2.getColumn(6).width = 15;
    sheet2.getColumn(7).width = 15; sheet2.getColumn(8).width = 20;

    const now = moment();
    let targetWeek = now.isoWeek();

    // Check if "now" is in the selected month
    const isCurrentMonth = now.format('YYYY-MM') === `${yearStr}-${monthStr}`;
    if (!isCurrentMonth) {
      targetWeek = endOfMonth.isoWeek();
    }

    let wSummaryWorkMs = 0;
    let hasWData = false;

    for (const [key, val] of dayMap) {
      const weekNum = val.dateObj.isoWeek();
      if (weekNum === targetWeek) {
        addDataRow(sheet2, key, val, weekNum);
        wSummaryWorkMs += val.workMs;
        hasWData = true;
      }
    }
    if (hasWData) {
      const wRow = sheet2.addRow([null, null, null, 'Weekly Total', null, null, formatDur(wSummaryWorkMs), null]);
      wRow.font = weeklyStyle.font;
      wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
    }

    // --- SHEET 3: Daily Report (TODAY ONLY) ---
    const sheet3 = workbook.addWorksheet('Daily Report');
    const todayStr = moment().format('YYYY-MM-DD');

    const titleRow = sheet3.addRow([`Daily Report: ${todayStr}`]);
    titleRow.font = { bold: true, size: 12 };

    const headers3 = ['Name', 'Email', 'Time', 'Action'];
    const hRow3 = sheet3.addRow(headers3);

    hRow3.font = headerStyle.font;
    hRow3.eachCell(c => { if (headerStyle.fill) c.fill = headerStyle.fill; });

    sheet3.getColumn(1).width = 25;
    sheet3.getColumn(2).width = 30;
    sheet3.getColumn(3).width = 15;
    sheet3.getColumn(4).width = 15;

    // Filter records for TODAY ONLY
    const todayRecords = records.filter(r => moment(r.time).format('YYYY-MM-DD') === todayStr);

    if (todayRecords.length === 0) {
      sheet3.addRow(['No attendance records found for today.']);
    } else {
      todayRecords.forEach(r => {
        const rRow = sheet3.addRow([
          user.name,
          user.email,
          moment(r.time).format('HH:mm:ss'),
          r.action
        ]);

        const actCell = rRow.getCell(4);
        if (r.action === 'check-in') actCell.font = { color: { argb: 'FF008000' } };
        else if (r.action === 'check-out') actCell.font = { color: { argb: 'FFFF0000' } };

        rRow.eachCell(c => { if (dataStyle.border) c.border = dataStyle.border; });
      });
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

  const referer = req.get('Referer');
  const isSupervisor = referer && referer.includes('/supervisor');
  const dashboardUrl = isSupervisor ? '/supervisor' : '/';

  let u = await User.findOne({ email });
  if (u) return res.redirect(`${dashboardUrl}?msg=exists`);

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

  res.redirect(`${dashboardUrl}?msg=userCreated`);
});

// ADMIN/HR: update user
app.post('/admin/update-user', checkUserManagement, async (req, res) => {
  try {
    const {
      userId, name, email, role, division, secondaryDivision,
      password, canAccessSupervisorDashboard,
      durationWorkHours, durationBreakMinutes, shiftGroup
    } = req.body;

    const referer = req.get('Referer');
    const isSupervisor = referer && referer.includes('/supervisor');
    const dashboardUrl = isSupervisor ? '/supervisor' : '/';

    const user = await User.findById(userId);
    if (!user) {
      return res.redirect(`${dashboardUrl}?msg=userNotFound`);
    }

    // Check for duplicate email if email is being changed
    if (email !== user.email) {
      const existing = await User.findOne({ email });
      if (existing) {
        return res.redirect(`${dashboardUrl}?msg=exists`);
      }
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

    res.redirect(`${dashboardUrl}?msg=userUpdated`);
  } catch (err) {
    console.error(err);
    const referer = req.get('Referer');
    const isSupervisor = referer && referer.includes('/supervisor');
    const dashboardUrl = isSupervisor ? '/supervisor' : '/';
    res.redirect(`${dashboardUrl}?msg=error`);
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
  let { action, qrToken, lat, lng, accuracy } = req.body;
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

    // Check last status for Auto-Stop Break or Logic Correction
    const lastAtt = await Attendance.findOne({ user: req.user._id }).sort({ time: -1 });

    if (lastAtt) {
      if (action === 'check-out' && lastAtt.action === 'break-start') {
        console.log(`[Auto-Stop Break] User ${req.user.email} checking out while on break. Inserting break-end.`);
        const breakEnd = new Attendance({
          user: req.user._id,
          action: 'break-end',
          time: new Date(),
          meta: { auto: true, lat, lng, qrToken, accuracy }
        });
        await breakEnd.save();
      }

      // Fix: If user mistakenly clicks "Check In" while on Break, treat it as "Break End"
      if (action === 'check-in' && lastAtt.action === 'break-start') {
        console.log(`[Logic Fix] User ${req.user.email} sent 'check-in' while on Break. Converting to 'break-end'.`);
        action = 'break-end';
      }
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
app.post('/admin/holidays/add', ensureAuth, checkUserManagement, async (req, res) => {
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
    if (referer && referer.includes('/supervisor')) {
      return res.redirect('/supervisor?openModal=true&activeTab=holidays&msg=holidayAdded');
    }
    res.redirect(referer || '/?msg=holidayAdded');
  } catch (err) {
    console.error(err);
    res.redirect('/?msg=error');
  }
});

app.post('/admin/holidays/remove', ensureAuth, checkUserManagement, async (req, res) => {
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
    if (referer && referer.includes('/supervisor')) {
      return res.redirect('/supervisor?openModal=true&activeTab=holidays&msg=holidayRemoved');
    }
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

    // FIX: Clean Export - Copy styles from template to NEW workbook
    const templateWorkbook = new ExcelJS.Workbook();
    const templatePath = path.join(__dirname, 'MasterFile', 'Saturday Attendances.xlsx');

    // Style placeholders
    let dateRowFont = { bold: true, size: 14 };
    let dateRowFill = null;
    let headerRowFont = { bold: true };
    let headerRowFill = null;
    let headerRowBorder = null;

    try {
      await templateWorkbook.xlsx.readFile(templatePath);
      const templateSheet = templateWorkbook.getWorksheet(1);
      if (templateSheet) {
        const r1 = templateSheet.getRow(1);
        const r2 = templateSheet.getRow(2);

        if (r1.font) dateRowFont = r1.font;
        if (r1.fill) dateRowFill = r1.fill;

        if (r2.font) headerRowFont = r2.font;
        if (r2.getCell(1).fill) headerRowFill = r2.getCell(1).fill;
        if (r2.getCell(1).border) headerRowBorder = r2.getCell(1).border;
      }
    } catch (readErr) {
      console.warn("Template not found, using defaults.", readErr);
    }

    // CREATE FRESH WORKBOOK FOR OUTPUT
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Saturday Attendance');

    // 1. ADD MAIN HEADER ONCE (Row 1)
    const tableHeaderRow = worksheet.addRow(['Name', 'Email', 'Time', 'Action']);
    tableHeaderRow.font = headerRowFont;
    tableHeaderRow.eachCell((cell) => {
      if (headerRowFill) cell.fill = headerRowFill;
      if (headerRowBorder) cell.border = headerRowBorder;
    });

    // Reset columns widths
    worksheet.getColumn(1).width = 20; // Name
    worksheet.getColumn(2).width = 30; // Email
    worksheet.getColumn(3).width = 15; // Time
    worksheet.getColumn(4).width = 15; // Action

    const recordsByDate = new Map();
    records.forEach(r => {
      const d = moment(r.time).format('YYYY-MM-DD');
      if (!recordsByDate.has(d)) recordsByDate.set(d, []);
      recordsByDate.get(d).push(r);
    });

    const indonesianDays = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];

    // Iterate dates
    for (const [dateStr, recs] of recordsByDate) {
      const dateObj = moment(dateStr);
      if (dateObj.isoWeekday() !== 6) continue;

      // 2. Date Header (Separator)
      const dateRow = worksheet.addRow([dateStr]);
      dateRow.font = dateRowFont;
      if (dateRowFill) dateRow.fill = dateRowFill;

      // Optional: Merge across columns for better visibility?
      // worksheet.mergeCells(`A${dateRow.number}:D${dateRow.number}`);

      // 3. Data Rows (No repeated headers)
      recs.forEach(r => {
        const row = worksheet.addRow([
          user.name,
          user.email,
          moment(r.time).format('HH:mm:ss'),
          r.action
        ]);

        // Style data
        row.getCell(4).font = {
          color: { argb: r.action === 'check-in' ? 'FF008000' : (r.action === 'check-out' ? 'FFFF0000' : 'FF000000') }
        };

        row.eachCell(cell => {
          cell.border = {
            top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' }
          };
        });
      });

      // Spacer
      worksheet.addRow([]);
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

    const lat = parseFloat(officeLat);
    const lng = parseFloat(officeLng);
    const rad = parseFloat(officeRadius);

    if (!isNaN(lat)) settings.officeLat = lat;
    if (!isNaN(lng)) settings.officeLng = lng;
    if (!isNaN(rad)) settings.officeRadius = rad;

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

        if (!isNaN(lat)) updateKey('OFFICE_LAT', lat);
        if (!isNaN(lng)) updateKey('OFFICE_LNG', lng);
        if (!isNaN(rad)) updateKey('OFFICE_RADIUS_METERS', rad);

        fs.writeFileSync(envPath, envContent);
      }
    } catch (envErr) {
      console.error('Failed to update .env file:', envErr);
    }

    res.redirect('/admin?msg=settingsUpdated');
  } catch (err) {
    console.error('[SETTINGS UPDATE ERROR]', err);
    // Try to write to a log file for debugging
    try {
      require('fs').appendFileSync('debug_error.log', `[${new Date().toISOString()}] Settings Update Error: ${err.message}\n${err.stack}\n\n`);
    } catch (e) { console.error('Failed to write log:', e); }

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

// Start server
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
  console.log("✅ MongoDB connected");
  await ensureDefaultAdmin();
  // Start Server
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}).catch(err => console.error("MongoDB connection error:", err));

// USER: Download My History (Excel)
app.get('/attendance/export-my-history', ensureAuth, async (req, res) => {
  try {
    const { month } = req.query; // "YYYY-MM" (Optional, defaults to current)

    let targetDate = moment();
    if (month) {
      targetDate = moment(month, 'YYYY-MM');
      if (!targetDate.isValid()) targetDate = moment();
    }

    const yearStr = targetDate.format('YYYY');
    const monthStr = targetDate.format('MM');
    // For filename
    const monthName = targetDate.format('MMMM_YYYY');

    const startOfMonth = targetDate.clone().startOf('month');
    const endOfMonth = targetDate.clone().endOf('month');

    const userId = req.user._id;
    const user = req.user; // already populated by passport

    const settings = await SystemSettings.findOne() || { holidays: [], saturdayWorkHours: 4 };

    const records = await Attendance.find({
      user: userId,
      time: { $gte: startOfMonth.toDate(), $lte: endOfMonth.toDate() }
    }).sort({ time: 1 });

    // --- Aggregation Logic (Same as Supervisor) ---
    const dayMap = new Map();
    const daysInMonth = startOfMonth.daysInMonth();
    for (let i = 1; i <= daysInMonth; i++) {
      const d = startOfMonth.clone().date(i);
      const dayKey = d.format('YYYY-MM-DD');
      dayMap.set(dayKey, {
        dateObj: d,
        dayName: d.format('dddd'),
        checkIn: null, checkOut: null,
        workMs: 0, breakMs: 0,
        lastCheckIn: null, lastBreakStart: null
      });
    }

    records.forEach(r => {
      const dayKey = moment(r.time).format('YYYY-MM-DD');
      const data = dayMap.get(dayKey);
      if (!data) return;
      const t = r.time.getTime();

      if (r.action === 'check-in') {
        if (!data.checkIn) data.checkIn = r.time;
        data.lastCheckIn = t;
      } else if (r.action === 'check-out') {
        if (!data.checkOut || r.time > data.checkOut) data.checkOut = r.time;
        if (data.lastCheckIn) { data.workMs += (t - data.lastCheckIn); data.lastCheckIn = null; }
      } else if (r.action === 'break-start') {
        if (data.lastCheckIn) { data.workMs += (t - data.lastCheckIn); data.lastCheckIn = null; }
        data.lastBreakStart = t;
      } else if (r.action === 'break-end') {
        if (data.lastBreakStart) { data.breakMs += (t - data.lastBreakStart); data.lastBreakStart = null; }
        data.lastCheckIn = t;
      }
    });

    // --- Generate Excel (Same as Supervisor) ---
    const workbook = new ExcelJS.Workbook();
    // No template load here -> consistent style definitions
    const headerStyle = { font: { bold: true, color: { argb: 'FFFFFFFF' } }, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF4F46E5' } } };
    const dataStyle = { font: {}, border: null };
    const weeklyStyle = { font: { bold: true }, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFEEEEEE' } } };

    // Helper
    const formatDur = (ms) => {
      if (!ms) return "00:00:00";
      const h = Math.floor(ms / 3600000);
      const m = Math.floor((ms % 3600000) / 60000);
      const s = Math.floor((ms % 60000) / 1000);
      return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    };

    const addDataRow = (sheet, key, val, wNum) => {
      const workHours = val.workMs / 3600000;
      const breakHours = val.breakMs / 3600000;
      let status = 'Off Day';
      const dayIdx = val.dateObj.day();
      const isWeekend = (dayIdx === 0 || dayIdx === 6);
      const userWorkDays = user.workingDays && user.workingDays.length > 0 ? user.workingDays : [1, 2, 3, 4, 5];
      const isDayOfWeekWork = userWorkDays.includes(dayIdx);
      const isHoliday = settings.holidays && settings.holidays.includes(key);
      const isWorkingDay = isDayOfWeekWork && !isHoliday;

      if (val.checkIn) {
        status = (workHours >= 8) ? 'Target Met' : 'Under Target';
        if (isWeekend || !isWorkingDay) status += ' (Overtime)';
        if (isHoliday) status = 'Holiday (Worked)';
      } else {
        if (isHoliday) status = 'Holiday';
        else status = isWorkingDay ? 'Absent' : 'Off Day';
      }

      const row = sheet.addRow([
        wNum, key, val.dayName,
        val.checkIn ? moment(val.checkIn).format('HH:mm') : '-',
        val.checkOut ? moment(val.checkOut).format('HH:mm') : '-',
        formatDur(val.workMs),
        formatDur(val.breakMs),
        status
      ]);
      row.font = dataStyle.font;
      row.eachCell(c => { if (dataStyle.border) c.border = dataStyle.border; });

      const statusCell = row.getCell(8);
      const breakCell = row.getCell(7);

      if (status.includes('Target Met')) statusCell.font = { color: { argb: 'FF008000' } };
      else if (status.includes('Under Target') || status === 'Absent') statusCell.font = { color: { argb: 'FFFF0000' } };
      else if (status.includes('Holiday')) statusCell.font = { color: { argb: 'FFEB5E28' } };
      else statusCell.font = { color: { argb: 'FF999999' } };

      if (breakHours > 1) breakCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFCCCC' } };
    };

    // SHEET 1 (Monthly)
    const sheet1 = workbook.addWorksheet('Monthly Summary');
    const hRow1 = sheet1.addRow(['Week', 'Date', 'Day', 'Clock In', 'Clock Out', 'Total Work', 'Total Break', 'Status']);
    hRow1.eachCell(c => { c.font = headerStyle.font; c.fill = headerStyle.fill; });
    sheet1.getColumn(1).width = 8; sheet1.getColumn(2).width = 15; sheet1.getColumn(3).width = 15;
    sheet1.columns.slice(3).forEach((c, i) => c.width = (i === 4) ? 20 : 15); // approx

    let currentWeek = null;
    let weekWorkMs = 0;
    for (const [key, val] of dayMap) {
      const weekNum = val.dateObj.isoWeek();
      if (currentWeek !== null && weekNum !== currentWeek) {
        const wRow = sheet1.addRow([null, null, null, 'Weekly Total', null, null, formatDur(weekWorkMs), null]);
        wRow.font = weeklyStyle.font;
        wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
        weekWorkMs = 0;
      }
      currentWeek = weekNum;
      weekWorkMs += val.workMs;
      addDataRow(sheet1, key, val, weekNum);
    }
    if (weekWorkMs > 0) {
      const wRow = sheet1.addRow([null, null, null, 'Weekly Total', null, null, formatDur(weekWorkMs), null]);
      wRow.font = weeklyStyle.font;
      wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
    }

    // SHEET 2 (Weekly)
    const sheet2 = workbook.addWorksheet('Weekly Summary');
    const hRow2 = sheet2.addRow(['Week', 'Date', 'Day', 'Clock In', 'Clock Out', 'Total Work', 'Total Break', 'Status']);
    hRow2.eachCell(c => { c.font = headerStyle.font; c.fill = headerStyle.fill; });

    // Default show "Current Week" relative to Real Time? OR relative to the selected Month?
    // Supervisor logic: "If now is in selected month, show current week. Else show last week of month."
    const now = moment();
    let targetWeek = now.isoWeek();
    const isCurrentMonth = now.format('YYYY-MM') === `${yearStr}-${monthStr}`;
    if (!isCurrentMonth) targetWeek = endOfMonth.isoWeek();

    let wSummaryWorkMs = 0;
    let hasWData = false;
    for (const [key, val] of dayMap) {
      if (val.dateObj.isoWeek() === targetWeek) {
        addDataRow(sheet2, key, val, val.dateObj.isoWeek());
        wSummaryWorkMs += val.workMs;
        hasWData = true;
      }
    }
    if (hasWData) {
      const wRow = sheet2.addRow([null, null, null, 'Weekly Total', null, null, formatDur(wSummaryWorkMs), null]);
      wRow.font = weeklyStyle.font;
      wRow.eachCell(c => { if (weeklyStyle.fill) c.fill = weeklyStyle.fill; });
    }

    // SHEET 3 (Daily - Today)
    const sheet3 = workbook.addWorksheet('Daily Report');
    const todayStr = moment().format('YYYY-MM-DD');
    sheet3.addRow([`Daily Report: ${todayStr}`]).font = { bold: true };
    const hRow3 = sheet3.addRow(['Name', 'Email', 'Time', 'Action']);
    hRow3.eachCell(c => { c.font = headerStyle.font; c.fill = headerStyle.fill; });
    sheet3.getColumn(1).width = 25; sheet3.getColumn(2).width = 30;

    const todayRecords = await Attendance.find({
      user: userId,
      time: { $gte: moment().startOf('day').toDate(), $lte: moment().endOf('day').toDate() }
    }).sort({ time: 1 });

    if (todayRecords.length === 0) {
      sheet3.addRow(['No attendance records found for today.']);
    } else {
      todayRecords.forEach(r => {
        const rRow = sheet3.addRow([user.name, user.email, moment(r.time).format('HH:mm:ss'), r.action]);
        const actCell = rRow.getCell(4);
        if (r.action === 'check-in') actCell.font = { color: { argb: 'FF008000' } };
        else if (r.action === 'check-out') actCell.font = { color: { argb: 'FFFF0000' } };
        rRow.eachCell(c => { if (dataStyle.border) c.border = dataStyle.border; });
      });
    }

    const safeName = (user.name || 'user').replace(/[^a-zA-Z0-9]/g, '_');
    const fileName = `my_attendance_${safeName}_${monthName}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    await workbook.xlsx.write(res);
    res.end();

  } catch (err) {
    console.error(err);
    res.status(500).send('Error generating My History Excel: ' + err.message);
  }
});
