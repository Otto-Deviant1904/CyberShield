const { normalizeUrl } = require('../utils/urlUtils');
const { scanUrl: vtScan } = require('./virusTotalService');
const { analyze: heuristicAnalyze } = require('./heuristicService');
const { analyze: domainSslAnalyze } = require('./domainSslService');
const { calculateScore } = require('./riskScoringService');

async function scanUrl(rawUrl) {
  const normalizedUrl = normalizeUrl(rawUrl);
  if (!normalizedUrl) {
    const error = new Error('Invalid URL provided');
    error.status = 400;
    throw error;
  }

  const [threatIntel, heuristics, domainSsl] = await Promise.allSettled([
    vtScan(normalizedUrl),
    Promise.resolve(heuristicAnalyze(normalizedUrl)),
    domainSslAnalyze(normalizedUrl)
  ]);

  const domainSslResult = domainSsl.status === 'fulfilled' ? domainSsl.value : {};
  const sslFallback = {
    https: normalizedUrl.startsWith('https:'),
    valid: null,
    issuer: null,
    expiresAt: null,
    subject: null,
    warning: null,
    error: {
      type: 'analysis_error',
      code: null,
      message: domainSsl.reason?.message || 'SSL analysis unavailable'
    }
  };

  const result = {
    url: normalizedUrl,
    timestamp: new Date().toISOString(),
    threatIntel: {
      virustotal: threatIntel.status === 'fulfilled' ? threatIntel.value : { status: 'error', message: threatIntel.reason?.message || 'scan failed' }
    },
    heuristics: heuristics.status === 'fulfilled' ? heuristics.value : {},
    ssl: domainSslResult.ssl || sslFallback,
    domain: {
      age: domainSslResult.domainAge || {},
      redirects: domainSslResult.redirects || {}
    }
  };

  const risk = calculateScore(result);
  result.risk = risk;
  result.indicators = risk.indicators;
  result.reasons = risk.reasons;

  return result;
}

module.exports = {
  scanUrl
};
