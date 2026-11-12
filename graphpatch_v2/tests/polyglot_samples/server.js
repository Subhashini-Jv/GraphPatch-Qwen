const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const app = express();

app.get('/file', (req, res) => {
  const name = req.query.name;
  const p = path.join(__dirname, 'public', name);
  res.sendFile(p);
});

app.get('/safe', (req, res) => {
  const p = path.resolve('public', req.query.name);
  if (!p.startsWith(path.resolve('public'))) return res.status(403).end();
  fs.readFile(p, (e, d) => res.end(d));
});

app.post('/run', (req, res) => {
  const { cmd } = req.body;
  exec('ls ' + cmd, (err, out) => res.send(out));
});

app.get('/greet', (req, res) => {
  res.send(`<p>Hi ${req.query.user}</p>`);
});

function render(el, location) {
  el.innerHTML = location.hash.slice(1);
}

app.get('/calc', function calc(req, res) {
  res.json({ v: eval(req.query.expr) });
});
