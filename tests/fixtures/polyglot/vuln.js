const express = require('express');
const { exec } = require('child_process');
const apiKey = "sk-test-abcdef123456";
const app = express();
app.get('/run', (req, res) => {
  exec('ping ' + req.query.host, (e, out) => res.send(out));
});
app.get('/hello', (req, res) => {
  document.body.innerHTML = req.query.name;
  res.send(eval(req.query.expr));
});
