const mongoose = require('mongoose');
const moment = require('moment');
const ExcelJS = require('exceljs');
const path = require('path');
const fs = require('fs');

// Connect to DB (adjust URI if needed)
mongoose.connect('mongodb://127.0.0.1:27017/attendance-db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('DB Connected')).catch(err => console.error(err));

const userSchema = new mongoose.Schema({
    name: String, email: String, role: String, division: String
}, { strict: false });
const User = mongoose.model('User', userSchema);

const attendanceSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    time: Date,
    action: String
}, { strict: false });
const Attendance = mongoose.model('Attendance', attendanceSchema);

async function testExport() {
    try {
        // Find a user with attendance
        const record = await Attendance.findOne().sort({ time: -1 });
        if (!record) {
            console.log("No attendance records found.");
            process.exit(0);
        }
        const userId = record.user;
        console.log(`Testing export for user: ${userId}`);

        const yearParam = moment().format('YYYY');
        const startOfYear = moment(yearParam + '-01-01', 'YYYY-MM-DD').startOf('year');
        const endOfYear = startOfYear.clone().endOf('year');

        const records = await Attendance.find({
            user: userId,
            time: { $gte: startOfYear.toDate(), $lte: endOfYear.toDate() }
        }).sort({ time: 1 });

        console.log(`Found ${records.length} records.`);

        // --- Logic Copy-Paste from Server.js ---
        const dailyStats = new Map();   // "YYYY-MM-DD" -> { dateObj, in, out, workMs, breakMs }
        const weeklyStats = new Map();  // "WeekNum" -> { week, weekStart, workMs }
        const monthlyStats = new Map(); // "MonthStr" -> { month, workMs }

        // Pre-fill months to ensure Jan-Dec order
        for (let i = 0; i < 12; i++) {
            const mStr = moment().month(i).format('MMMM');
            monthlyStats.set(mStr, { month: mStr, workMs: 0 });
        }

        let lastCheckIn = null;
        let lastBreakStart = null;

        // Helper to add duration to aggregates
        function addToAggregates(dateObj, ms) {
            if (ms <= 0) return;

            // Monthly
            const monthKey = moment(dateObj).format('MMMM');
            if (monthlyStats.has(monthKey)) {
                monthlyStats.get(monthKey).workMs += ms;
            }

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

        console.log("Stats compiled.");

        const workbook = new ExcelJS.Workbook();

        // 1. Yearly Summary
        const wsYear = workbook.addWorksheet('Yearly Summary');
        // ... (Simulated logic)

        // 2. Monthly Summary
        const wsMonth = workbook.addWorksheet('Monthly Summary');

        // 3. Weekly Summary
        const wsWeek = workbook.addWorksheet('Weekly Summary');

        // 4. Daily Report
        const wsDaily = workbook.addWorksheet('Daily Report');

        console.log("Sheets created:");
        workbook.eachSheet((sheet, id) => {
            console.log(`Sheet ${id}: ${sheet.name}`);
        });

        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

testExport();
