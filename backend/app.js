const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const scanRoutes = require('./routes/scanRoutes');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');

const app = express();

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many scan requests. Please try again shortly.'
  }
});

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '100kb' }));

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.use('/scan', scanLimiter, scanRoutes);
app.use('/api/scan', scanLimiter, scanRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
