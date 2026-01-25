const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const AttendanceSchema = new Schema({
  user: {type:Schema.Types.ObjectId, ref:'User'},
  action: {type:String, enum:['check-in','check-out','break-start','break-end']},
  time: Date,
  meta: Schema.Types.Mixed
});
module.exports = mongoose.model('Attendance', AttendanceSchema);
