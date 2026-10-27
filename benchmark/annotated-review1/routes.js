// Express routes that hand user input to helpers in other files.
const express = require("express");
const files = require("./files");
const { runQuery } = require("./db");

const app = express();

app.get("/file", (req, res) => res.send(files.readUpload(req.query.name)));
app.get("/user", (req, res) => res.json(runQuery(req.query.name)));

module.exports = app;
