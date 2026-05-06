const { calculateEntropy } = require('../utils/urlParser');
const axios = require('axios');

class AnalysisService {
  async performBasicChecks(url) {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    const checks = {
      isHttps: urlObj.protocol === 'https:',
      hasIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(domain),
      subdomainCount: domain.split('.').length - 2,
      isPunycode: domain.includes('xn--'),
      entropy: calculateEntropy(domain),
      suspiciousKeywords: this.checkKeywords(domain),
    };

    return {
      ...checks,
      riskLevel: this.calculateRisk(checks)
    };
  }

  checkKeywords(domain) {
    const keywords = ['login', 'verify', 'bank', 'secure', 'update', 'account', 'signin', 'phish'];
    return keywords.filter(kw => domain.toLowerCase().includes(kw));
  }

  calculateRisk(checks) {
    let score = 0;
    if (!checks.isHttps) score += 30;
    if (checks.hasIpAddress) score += 50;
    if (checks.subdomainCount > 3) score += 20;
    if (checks.isPunycode) score += 40;
    if (checks.entropy > 4.5) score += 25;
    if (checks.suspiciousKeywords.length > 0) score += 35;

    if (score > 70) return 'Dangerous';
    if (score > 30) return 'Suspicious';
    return 'Safe';
  }
}

module.exports = new AnalysisService();
