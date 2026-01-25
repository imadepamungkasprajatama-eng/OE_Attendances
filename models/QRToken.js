const mongoose = require('mongoose');
const crypto = require('crypto');
const Schema = mongoose.Schema;
const QRTokenSchema = new Schema({
  token: String,
  date: String, // ISO date string yyyy-mm-dd
  createdAt: { type: Date, default: Date.now }
});
QRTokenSchema.statics.generateDaily = async function () {
  const today = new Date().toISOString().slice(0, 10);

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
  const today = new Date().toISOString().slice(0, 10);
  let doc = await this.findOne({ date: today });
  if (!doc) doc = await this.generateDaily();
  return doc;
};
QRTokenSchema.statics.validate = async function (token) {
  const today = new Date().toISOString().slice(0, 10);
  const doc = await this.findOne({ date: today });
  if (!doc) return false;
  return doc.token === token;
};
module.exports = mongoose.model('QRToken', QRTokenSchema);
