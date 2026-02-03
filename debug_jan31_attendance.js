const mongoose = require('mongoose');
const moment = require('moment');
const User = require('./models/User');
const Attendance = require('./models/Attendance');

// Connect to DB
mongoose.connect('mongodb://127.0.0.1:27017/attendance-db', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error(err));

async function debug() {
    const name = "I Made Pamungkas Prajatama";
    const user = await User.findOne({ name: { $regex: new RegExp(name, 'i') } });

    if (!user) {
        console.log("User not found!");
        process.exit();
    }
    console.log("Found User:", user.name, user._id);

    // Jan 2026
    const start = moment('2026-01-01');
    const end = moment('2026-01-31').endOf('day');

    console.log("Querying records from", start.format(), "to", end.format());

    const records = await Attendance.find({
        user: user._id,
        time: { $gte: start.toDate(), $lte: end.toDate() }
    }).sort({ time: 1 });

    console.log(`Found ${records.length} records.`);

    let satSeconds = 0;
    let lastIn = null;

    records.forEach(r => {
        const d = moment(r.time);
        const day = d.day();
        const isSat = day === 6;

        // Check local time string
        console.log(
            `Record: ${r.action} at ${d.format('YYYY-MM-DD HH:mm:ss')} (Day ${day}) [IsSat: ${isSat}]`
        );

        if (day === 6) {
            if (r.action === 'check-in') {
                lastIn = r.time;
                console.log("  -> Check In Set");
            } else if (r.action === 'check-out' && lastIn) {
                const dur = (r.time - lastIn) / 1000;
                console.log("  -> Adding duration:", dur, "seconds");
                satSeconds += dur;
                lastIn = null;
            } else if (r.action === 'check-out') {
                console.log("  -> Check Out without Check In (or Check In was not Sat?)");
            }
        } else {
            // If it's not Saturday, but we have a lastIn from Saturday?
            if (lastIn && r.action === 'check-out') {
                console.log("  -> Check Out on Non-Saturday for a Saturday Check In!");
                // The bug might be here: logic ignores check-out if it's not Saturday Day.
            }
        }
    });

    const h = Math.floor(satSeconds / 3600);
    const m = Math.floor((satSeconds % 3600) / 60);
    const s = Math.floor(satSeconds % 60);
    const str = `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;

    console.log("Calculated Saturday Hours:", str);

    process.exit();
}

debug();
