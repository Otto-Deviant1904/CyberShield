const analysisService = require('../services/analysisService');
const virusTotalService = require('../services/virusTotalService');
const { normalizeUrl } = require('../utils/urlParser');

const scanUrl = async (req, res, next) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const normalized = normalizeUrl(url);
    if (!normalized) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Run checks in parallel
    const [basicReport, vtReport] = await Promise.all([
      analysisService.performBasicChecks(normalized),
      virusTotalService.scanUrl(normalized)
    ]);

    const result = {
      url: normalized,
      timestamp: new Date().toISOString(),
      basicReport,
      vtReport,
      summary: {
        riskLevel: basicReport.riskLevel,
        isMalicious: vtReport.malicious > 0 || basicReport.riskLevel === 'Dangerous'
      }
    };

    res.json(result);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  scanUrl
};
