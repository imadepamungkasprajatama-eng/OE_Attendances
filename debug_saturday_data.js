require('dotenv').config();
const mongoose = require('mongoose');
const moment = require('moment');
const User = require('./models/User');
const Attendance = require('./models/Attendance');

async function run() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);

        const nameTarget = "I Made Pamungkas Prajatama";
        const user = await User.findOne({ name: nameTarget });
        if (!user) {
            console.log("User not found");
            return;
        }

        console.log(`User ID: ${user._id}`);

        // Check Jan 2026
        const start = moment("2026-01-01").startOf('month').toDate();
        const end = moment("2026-01-01").endOf('month').toDate();

        console.log(`Querying between ${start} and ${end}`);

        const atts = await Attendance.find({
            user: user._id,
            time: { $gte: start, $lte: end }
        });

        console.log(`Found ${atts.length} records.`);

        atts.forEach(a => {
            const m = moment(a.time);
            console.log(`- Time: ${a.time.toISOString()} | Local: ${m.format('YYYY-MM-DD HH:mm')} | Weekday: ${m.isoWeekday()} (${m.format('dddd')}) | Type: ${a.action}`);
        });

    } catch (e) {
        console.error(e);
    } finally {
        await mongoose.disconnect();
    }
}

run();
