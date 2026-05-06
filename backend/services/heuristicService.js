const {
  getHostname,
  isIpHost,
  getSubdomainCount,
  getEntropy,
  isPunycode,
  getTld,
  isSuspiciousTld
} = require('../utils/urlUtils');

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'free', 'secure', 'bonus', 'update', 'account', 'bank'
];

const EXCESSIVE_SUBDOMAIN_THRESHOLD = 3;
const ENTROPY_THRESHOLD = 4.2;
const LONG_URL_LENGTH = 120;

function analyze(url) {
  const normalized = url;
  let hostname = getHostname(normalized);
  if (!hostname) hostname = '';
  const hostnameLower = hostname.toLowerCase();
  const fullLower = normalized.toLowerCase();

  const keywordMatches = SUSPICIOUS_KEYWORDS.filter(kw => fullLower.includes(kw));
  const hasIpAddress = isIpHost(hostname);
  const subdomainCount = getSubdomainCount(hostname);
  const excessiveSubdomains = subdomainCount > EXCESSIVE_SUBDOMAIN_THRESHOLD;
  const punycode = isPunycode(hostname);
  const tld = getTld(hostname);
  const suspiciousTld = isSuspiciousTld(tld);
  const entropy = getEntropy(hostname);
  const highEntropy = entropy > ENTROPY_THRESHOLD;
  const longUrl = normalized.length > LONG_URL_LENGTH;

  const triggered = [];

  if (hasIpAddress) triggered.push('IP-address URL');
  if (excessiveSubdomains) triggered.push('Excessive subdomains');
  if (punycode) triggered.push('Punycode domain');
  if (suspiciousTld) triggered.push(`Suspicious TLD .${tld}`);
  if (highEntropy) triggered.push('High URL entropy');
  if (longUrl) triggered.push('Excessively long URL');
  if (keywordMatches.length > 0) {
    triggered.push(`Suspicious keywords: ${keywordMatches.join(', ')}`);
  }

  return {
    hasIpAddress,
    subdomainCount,
    excessiveSubdomains,
    punycode,
    tld,
    suspiciousTld,
    entropy: +entropy.toFixed(2),
    highEntropy,
    longUrl,
    suspiciousKeywords: keywordMatches,
    triggered
  };
}

module.exports = { analyze };
