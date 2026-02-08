const moment = require('moment-timezone');
moment.locale('id');
moment.tz.setDefault("Asia/Makassar");

console.log("Current Time (Asia/Makassar):", moment().format('YYYY-MM-DD HH:mm:ss'));
console.log("Current Time (Offset):", moment().format('Z'));
