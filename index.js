const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World');
});

// Fixed: escape user input to prevent reflected XSS
app.get('/greet', (req, res) => {
  const name = req.query.name || '';
  res.send(`<h1>Hello ${escapeHtml(name)}</h1>`);
});

// Intentional: prototype pollution via merge
app.post('/config', express.json(), (req, res) => {
  const config = {};
  Object.assign(config, req.body);
  res.json(config);
});

app.listen(3000);
