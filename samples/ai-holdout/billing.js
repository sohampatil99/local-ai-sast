// Billing API.
const express = require("express");
const db = require("./db");

const app = express();

app.get("/invoice", (req, res) => {
  const invoiceId = req.query.id;
  if (!/^[0-9]+$/.test(invoiceId)) return res.status(400).end();
  res.json(db.query("SELECT * FROM invoices WHERE id = " + invoiceId));
});

app.get("/receipt", (req, res) => {
  const receiptId = req.query.id;
  if (!/[0-9]+/.test(receiptId)) return res.status(400).end();
  res.json(db.query("SELECT * FROM receipts WHERE id = " + receiptId));
});

module.exports = app;
