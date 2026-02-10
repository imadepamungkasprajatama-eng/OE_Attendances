const mongoose = require('mongoose');
const Attendance = require('./models/Attendance');
require('dotenv').config();

async function checkMeta() {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to DB');

        const record = await Attendance.findOne().sort({ time: -1 });
        if (record) {
            console.log('--- Record ---');
            console.log('Action:', record.action);
            console.log('Meta:', JSON.stringify(record.meta, null, 2));
            console.log('Full:', record);
        } else {
            console.log('No records found.');
        }
    } catch (err) {
        console.error(err);
    } finally {
        mongoose.disconnect();
    }
}

checkMeta();
