const mongoose = require('mongoose');
require('dotenv').config();
const SystemSettings = require('./models/SystemSettings');

const uri = process.env.MONGODB_URI || process.env.MONGO_URI || 'mongodb://localhost:27017/attendance-geospatial';

mongoose.connect(uri)
    .then(async () => {
        console.log('Connected to DB...');

        const envLat = Number(process.env.OFFICE_LAT);
        const envLng = Number(process.env.OFFICE_LNG);
        const envRad = Number(process.env.OFFICE_RADIUS_METERS);

        if (!envLat || !envLng) {
            console.error('Missing OFFICE_LAT or OFFICE_LNG in .env');
            process.exit(1);
        }

        console.log(`Resetting DB settings to match .env:`);
        console.log(`Lat: ${envLat}, Lng: ${envLng}, Radius: ${envRad}`);

        let settings = await SystemSettings.findOne();
        if (!settings) {
            settings = new SystemSettings();
        }

        settings.officeLat = envLat;
        settings.officeLng = envLng;
        settings.officeRadius = envRad;

        await settings.save();
        console.log('Successfully updated SystemSettings inside Database.');
        process.exit();
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
