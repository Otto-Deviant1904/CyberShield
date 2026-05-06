const express = require('express');
const cors = require('cors');

const scanRoutes = require('./routes/scanRoutes');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandler');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.use('/scan', scanRoutes);
app.use('/api/scan', scanRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
