const { scanUrl } = require('../services/scanService');

async function handleScan(req, res, next) {
  try {
    const report = await scanUrl(req.body.url);
    res.status(200).json(report);
  } catch (error) {
    next(error);
  }
}

module.exports = {
  handleScan
};
