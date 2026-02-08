// const mongoose = require('mongoose');
// const Schema = mongoose.Schema;
// const UserSchema = new Schema({
//   googleId: String,
//   email: {type:String, index:true},
//   name: String,
//   role: {type:String, enum:['Admin','Supervisor','HR','Staff'], default:'Staff'},
//   durationWorkHours: {type:Number, default:8},
//   durationBreakMinutes: {type:Number, default:60},
//   createdAt: {type:Date, default: Date.now}
// });
// module.exports = mongoose.model('User', UserSchema);

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Schema = mongoose.Schema;

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  role: {
    type: String,
    enum: ['Admin', 'Supervisor', 'Operational Manager', 'General Manager', 'Staff'],
    default: 'Staff'
  },

  division: {
    type: String,
    enum: ['Admin', 'GM', 'OC', 'N1', 'SnG', 'e1', 'CE', 'EC', 'PX', 'FN', 'HR', 'All Division'],
    default: 'OC'
  },

  secondaryDivision: {
    type: String,
    enum: ['Admin', 'GM', 'OC', 'N1', 'SnG', 'e1', 'CE', 'EC', 'PX', 'FN', 'HR', 'All Division'],
    default: undefined
  },

  canAccessSupervisorDashboard: {
    type: Boolean,
    default: false
  },

  durationWorkHours: {
    type: Number,
    default: 8
  },
  durationBreakMinutes: {
    type: Number,
    default: 60
  },

  // 0=Sun, 1=Mon, ..., 6=Sat
  workingDays: {
    type: [Number],
    default: [1, 2, 3, 4, 5] // Mon-Fri
  },

  shiftGroup: { type: String, enum: ['A', 'B', 'C', 'All'], default: undefined },

  password: String,
  // ... field lain kalau ada
});


// helper method
UserSchema.methods.validatePassword = async function (plain) {
  return bcrypt.compare(plain, this.password || '');
};

module.exports = mongoose.model('User', UserSchema);
