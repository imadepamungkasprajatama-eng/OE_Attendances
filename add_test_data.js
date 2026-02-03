require('dotenv').config();
const mongoose = require('mongoose');

// Define simplified Schemas just for insertion if models are not easily exportable, 
// OR better yet, require the models if they are exported.
// Based on file list, models are in ./models/
const User = require('./models/User');
const Attendance = require('./models/Attendance');

async function run() {
    try {
        console.log("Connecting to DB...");
        await mongoose.connect(process.env.MONGODB_URI);
        console.log("Connected.");

        const nameTarget = "I Made Pamungkas Prajatama";
        const user = await User.findOne({ name: nameTarget });

        if (!user) {
            console.error(`User "${nameTarget}" not found! Listing all users:`);
            const all = await User.find({}, 'name');
            console.log(all.map(u => u.name));
            process.exit(1);
        }

        console.log(`Found User: ${user.name} (${user._id})`);

        // Date: Jan 31, 2026 (Saturday)
        // Time: 09:00 - 10:00 (1 hour)
        const dateStr = "2026-01-31";

        const checkIn = new Attendance({
            user: user._id,
            action: 'check-in',
            time: new Date(`${dateStr}T09:00:00`),
            meta: { manual: true, note: 'Test Data' }
        });

        const checkOut = new Attendance({
            user: user._id,
            action: 'check-out',
            time: new Date(`${dateStr}T10:00:00`),
            meta: { manual: true, note: 'Test Data' }
        });

        await checkIn.save();
        await checkOut.save();

        console.log("Successfully added Check-In (9:00) and Check-Out (10:00) for Jan 31.");

    } catch (e) {
        console.error(e);
    } finally {
        await mongoose.disconnect();
    }
}

run();
