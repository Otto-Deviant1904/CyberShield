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
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return false;
  return hostname
    .split('.')
    .map(Number)
    .every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255);
}

function isPrivateOrLocalIpv4(hostname) {
  if (!isIpHost(hostname)) return false;

  const octets = hostname.split('.').map(Number);
  const [a, b] = octets;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateOrLocalIpv6(hostname) {
  const lower = hostname.toLowerCase();
  return (
    lower === '::1' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe80:')
  );
}

function isPrivateOrLocalHost(hostname) {
  if (!hostname) return false;
  const lower = hostname.toLowerCase();

  return (
    lower === 'localhost' ||
    lower.endsWith('.localhost') ||
    isPrivateOrLocalIpv4(lower) ||
    isPrivateOrLocalIpv6(lower)
  );
}

function getSubdomainCount(hostname) {
  if (isIpHost(hostname)) return 0;
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
  if (isIpHost(hostname)) return '';
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
  isPrivateOrLocalHost,
  getSubdomainCount,
  getEntropy,
  isPunycode,
  getTld,
  isSuspiciousTld
};
