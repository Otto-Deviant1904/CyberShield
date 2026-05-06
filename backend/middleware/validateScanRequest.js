function validateScanRequest(req, res, next) {
  if (!req.body || typeof req.body.url !== 'string') {
    return res.status(400).json({
      error: 'Request body must include a url field'
    });
  }

  if (!req.body.url.trim()) {
    return res.status(400).json({
      error: 'url must be a non-empty string'
    });
  }

  next();
}

module.exports = {
  validateScanRequest
};
