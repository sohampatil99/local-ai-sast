// Deliberately vulnerable Express API (benchmark fixture).
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const mysql = require("mysql");

const app = express();
const db = mysql.createConnection({ host: "localhost", user: "root" });
const GITHUB_PAT = "ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2";

app.get("/user", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => res.json(rows));
});

app.get("/order", (req, res) => {
  db.query(`SELECT * FROM orders WHERE ref = '${req.query.ref}'`, (e, r) => res.json(r));
});

app.get("/order/safe", (req, res) => {
  db.query("SELECT * FROM orders WHERE ref = ?", [req.query.ref], (e, r) => res.json(r));
});

app.get("/lookup", (req, res) => {
  const domain = req.query.domain;
  exec("nslookup " + domain, (err, out) => res.send(out));
});

app.get("/eval", (req, res) => {
  res.send(String(eval(req.query.code)));
});

app.get("/greet", (req, res) => {
  res.send("<p>Hello " + req.query.name + "</p>");
});

app.get("/file", (req, res) => {
  const p = path.join(__dirname, "uploads", req.query.name);
  fs.readFile(p, (err, data) => res.send(data));
});

app.post("/login", (req, res) => {
  const token = jwt.sign({ user: req.body.user }, "hardcoded-jwt-secret-123");
  res.json({ token });
});

function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

function checksum(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function renderComment(el, comment) {
  el.innerHTML = comment.body;
}

const pattern = /^[a-z]+$/;
const match = pattern.exec("abc");

app.listen(3000);
