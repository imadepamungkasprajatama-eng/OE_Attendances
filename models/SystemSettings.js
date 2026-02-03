const mongoose = require('mongoose');

const SystemSettingsSchema = new mongoose.Schema({
    officeLat: { type: Number, default: 0 },
    officeLng: { type: Number, default: 0 },
    officeRadius: { type: Number, default: 100 }, // in meters
    saturdayWorkHours: { type: Number, default: 4 },
    holidays: { type: [String], default: [] },
    updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('SystemSettings', SystemSettingsSchema);
