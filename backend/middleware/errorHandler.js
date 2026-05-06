function notFoundHandler(req, res) {
  res.status(404).json({
    error: 'Route not found'
  });
}

function errorHandler(err, req, res, _next) {
  const isCorsError = err.message === 'CORS policy blocked this origin';
  const status = err.status || (isCorsError ? 403 : 500);

  if (status >= 500) {
    console.error('[CyberShield] Unhandled error:', err);
  }

  res.status(status).json({
    error: err.message || 'Internal server error',
    code: err.code || null
  });
}

module.exports = {
  notFoundHandler,
  errorHandler
};
