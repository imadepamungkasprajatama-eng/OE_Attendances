const mongoose = require('mongoose');
require('dotenv').config();
const SystemSettings = require('./models/SystemSettings');

const uri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://localhost:27017/attendance-geospatial';
console.log('Connecting to:', uri.substring(0, 20) + '...');

mongoose.connect(uri)
    .then(async () => {
        const settings = await SystemSettings.find(); // Find ALL
        console.log(`Found ${settings.length} SystemSettings documents.`);
        settings.forEach((s, i) => {
            console.log(`[${i}] ID: ${s._id}`);
            console.log(`    Lat: ${s.officeLat}, Lng: ${s.officeLng}, Radius: ${s.officeRadius}`);
        });
        process.exit();
    })
    .catch(err => {
        console.error('Connection error:', err);
        process.exit(1);
    });
