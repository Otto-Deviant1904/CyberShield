function normalizeUrl(input) {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(withProtocol);
    return parsed.toString();
  } catch {
    return null;
  }
}

function getHostname(urlStr) {
  try { return new URL(urlStr).hostname; } catch { return ''; }
}

function isIpHost(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function getSubdomainCount(hostname) {
  const parts = hostname.split('.');
  return parts.length > 2 ? parts.length - 2 : 0;
}

function getEntropy(str) {
  const len = str.length;
  if (len === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isPunycode(hostname) {
  return hostname.includes('xn--');
}

function getTld(hostname) {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts[parts.length - 1].toLowerCase() : '';
}

function isSuspiciousTld(tld) {
  const suspicious = ['ru', 'xyz', 'top', 'gq', 'tk'];
  return suspicious.includes(tld);
}

module.exports = {
  normalizeUrl,
  getHostname,
  isIpHost,
  getSubdomainCount,
  getEntropy,
  isPunycode,
  getTld,
  isSuspiciousTld
};
