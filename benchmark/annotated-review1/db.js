const mysql = require("mysql");

const conn = mysql.createConnection({ host: "localhost" });

function runQuery(userName) {
  return conn.query("SELECT * FROM users WHERE name = '" + userName + "'");  // VULN:sqli
}

module.exports = { runQuery };
