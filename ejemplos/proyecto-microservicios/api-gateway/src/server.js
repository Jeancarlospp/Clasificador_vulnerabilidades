const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
app.use(helmet());
app.use(morgan('combined'));
app.use(cors({ origin: true, credentials: true }));

const routes = {
  '/api/users': process.env.USERS_URL,
  '/api/products': process.env.PRODUCTS_URL,
  '/api/orders': process.env.ORDERS_URL,
};

Object.entries(routes).forEach(([prefix, target]) => {
  app.use(prefix, createProxyMiddleware({ target, changeOrigin: true }));
});

app.get('/health', (req, res) => {
  res.json({ status: 'up', uptime: process.uptime() });
});

app.listen(8080, () => console.log('gateway listening on 8080'));
