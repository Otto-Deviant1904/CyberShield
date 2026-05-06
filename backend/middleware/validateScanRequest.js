function validateScanRequest(req, res, next) {
  if (!req.body || typeof req.body.url !== 'string') {
    return res.status(400).json({
      error: 'Request body must include a url field'
    });
  }

  next();
}

module.exports = {
  validateScanRequest
};
