// Download format lookup.
const express = require("express");
const db = require("./db");

const app = express();
const MIME = { csv: "text/csv", json: "application/json" };

app.get("/downloads", (req, res) => {
  const mime = MIME[req.query.f] || "text/csv";
  res.json(db.query("SELECT * FROM downloads WHERE mime = '" + mime + "'"));  // AI:safe
});

module.exports = app;
