const mongoose = require('mongoose');
const crypto = require('crypto');
const Schema = mongoose.Schema;
const QRTokenSchema = new Schema({
  token: String,
  date: String, // ISO date string yyyy-mm-dd (Asia/Makassar, UTC+8)
  createdAt: { type: Date, default: Date.now }
});

// Helper: get today's date string in Asia/Makassar timezone (UTC+8)
// Using a fixed offset to avoid timezone library dependency
function getTodayMakassar() {
  // UTC+8 = UTC + 8 hours
  return new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

QRTokenSchema.statics.generateDaily = async function () {
  const today = getTodayMakassar();

  // 1. Cek dulu apakah sudah ada token untuk hari ini
  let doc = await this.findOne({ date: today });

  // 2. Jika sudah ada, kembalikan yang lama (jangan overwrite!)
  if (doc) {
    return doc;
  }

  // 3. Jika belum ada, baru buat baru
  const token = crypto.randomBytes(16).toString('hex') + ':' + today;
  doc = new this({ token, date: today });
  await doc.save();
  return doc;
};
QRTokenSchema.statics.getCurrent = async function () {
  const today = getTodayMakassar();
  let doc = await this.findOne({ date: today });
  if (!doc) doc = await this.generateDaily();
  return doc;
};
QRTokenSchema.statics.validate = async function (token) {
  const today = getTodayMakassar();
  const doc = await this.findOne({ date: today });
  if (!doc) return false;
  return doc.token === token;
};
module.exports = mongoose.model('QRToken', QRTokenSchema);
