// Express routes where user input travels through helper functions, plus look-alike safe code.
const express = require("express");
const fs = require("fs");
const path = require("path");
const db = require("./db");

const app = express();
const ORDERS_TABLE = "orders";

// ---- real: user input reaches the sink inside a helper ----

function readUpload(uploadName) {
  return fs.readFileSync(path.join("/srv/uploads", uploadName));
}

app.get("/upload", (req, res) => {
  res.send(readUpload(req.query.name));
});

function findCustomer(customerName) {
  return db.query("SELECT * FROM customers WHERE name = '" + customerName + "'");
}

app.get("/customer", (req, res) => {
  res.json(findCustomer(req.query.name));
});

// ---- safe: constants and sanitized input ----

app.get("/count", (req, res) => {
  res.json(db.query("SELECT COUNT(*) FROM " + ORDERS_TABLE));
});

app.get("/order", (req, res) => {
  const orderId = parseInt(req.query.id, 10);
  res.json(db.query(`SELECT * FROM orders WHERE id = ${orderId}`));
});

app.get("/public", (req, res) => {
  const base = path.basename(req.query.file);
  res.sendFile(path.join("/srv/public", base));
});

app.get("/recent", (req, res) => {
  const dir = req.query.asc ? "ASC" : "DESC";
  res.json(db.query("SELECT * FROM orders ORDER BY created " + dir));
});

module.exports = app;
