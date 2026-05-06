const https = require('https');
const http = require('http');
const { getHostname, isIpHost } = require('../utils/urlUtils');

async function getRedirectChain(url) {
  const maxRedirects = 10;
  const chain = [];
  let current = url;
  let count = 0;

  while (count < maxRedirects) {
    const result = await new Promise((resolve) => {
      const lib = current.startsWith('https') ? https : http;
      const req = lib.request(current, { method: 'HEAD', timeout: 8000 }, (res) => {
        const status = res.statusCode;
        if (status >= 300 && status < 400 && res.headers.location) {
          resolve({ redirect: true, location: res.headers.location });
        } else {
          resolve({ redirect: false, finalUrl: current });
        }
      });
      req.on('timeout', () => { req.destroy(); resolve({ redirect: false, finalUrl: current }); });
      req.on('error', () => { resolve({ redirect: false, finalUrl: current }); });
      req.end();
    });

    chain.push(current);
    if (!result.redirect) break;
    const next = result.location;
    current = next.startsWith('http') ? next : new URL(next, current).toString();
    count++;
  }

  return { chain, count: chain.length - 1, finalUrl: current };
}

async function checkSslCertificate(url) {
  const hostname = getHostname(url);
  if (!hostname) return { valid: false, issuer: null, error: 'Invalid URL' };
  if (!url.startsWith('https')) {
    return { valid: false, issuer: null, error: 'Not HTTPS' };
  }

  return new Promise((resolve) => {
    const req = https.get(url, { timeout: 8000 }, (res) => {
      const cert = res.socket?.getPeerCertificate?.();
      resolve({
        valid: !!cert?.subject,
        issuer: cert?.issuer?.O || cert?.issuer?.CN || null,
        subject: cert?.subject?.CN || null
      });
      res.destroy();
    });
    req.on('timeout', () => { req.destroy(); resolve({ valid: false, issuer: null, error: 'Timeout' }); });
    req.on('error', () => resolve({ valid: false, issuer: null, error: 'Connection error' }));
    req.end();
  });
}

async function getDomainAge(url) {
  const hostname = getHostname(url);
  if (!hostname || isIpHost(hostname)) {
    return { ageDays: null, registrationDate: null, error: 'Not a domain' };
  }

  try {
    const rdapUrl = `https://rdap.org/domain/${hostname}`;
    const axios = require('axios');
    const resp = await axios.get(rdapUrl, { timeout: 8000 });
    const events = resp.data?.events || [];
    const regEvent = events.find(e => e.eventAction === 'registration');
    if (regEvent?.eventDate) {
      const regDate = new Date(regEvent.eventDate);
      const now = new Date();
      const ageDays = Math.floor((now - regDate) / (1000 * 60 * 60 * 24));
      return { ageDays, registrationDate: regEvent.eventDate, error: null };
    }
    return { ageDays: null, registrationDate: null, error: 'No registration event' };
  } catch {
    return { ageDays: null, registrationDate: null, error: 'RDAP lookup failed' };
  }
}

async function analyze(url) {
  const [redirects, ssl, domainAge] = await Promise.all([
    getRedirectChain(url),
    checkSslCertificate(url),
    getDomainAge(url)
  ]);

  const hasHttps = url.startsWith('https:');
  const excessiveRedirects = redirects.count > 3;

  return {
    hasHttps,
    ssl,
    redirects: {
      chain: redirects.chain,
      count: redirects.count,
      excessive: excessiveRedirects
    },
    domainAge
  };
}

module.exports = { analyze };
