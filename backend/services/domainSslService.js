const https = require('https');
const http = require('http');
const tls = require('tls');
const axios = require('axios');

const { getHostname, isIpHost, isPrivateOrLocalHost } = require('../utils/urlUtils');

const REDIRECT_TIMEOUT_MS = 8000;
const SSL_TIMEOUT_MS = 10000;

const SSL_ERROR_MAP = {
  CERT_HAS_EXPIRED: 'expired_certificate',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'self_signed_certificate',
  SELF_SIGNED_CERT_IN_CHAIN: 'self_signed_certificate',
  ERR_TLS_CERT_ALTNAME_INVALID: 'hostname_mismatch',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'untrusted_certificate',
  CERT_SIGNATURE_FAILURE: 'invalid_certificate_signature',
  CERT_REVOKED: 'revoked_certificate',
  CERT_UNTRUSTED: 'untrusted_certificate'
};

const NETWORK_ERROR_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ENETUNREACH']);
const HANDSHAKE_ERROR_CODES = new Set(['EPROTO', 'ECONNRESET']);
const DEFINITIVE_CERT_FAILURES = new Set([
  'expired_certificate',
  'self_signed_certificate',
  'hostname_mismatch',
  'revoked_certificate',
  'invalid_certificate_signature'
]);

function formatSslError(type, code, message) {
  return {
    type,
    code: code || null,
    message: message || null
  };
}

function sanitizeIssuer(issuer) {
  if (!issuer) return null;
  if (typeof issuer === 'string') return issuer;
  return issuer.O || issuer.CN || issuer.OU || null;
}

function buildCertDetails(cert) {
  if (!cert || Object.keys(cert).length === 0) {
    return {
      issuer: null,
      expiresAt: null,
      subject: null
    };
  }

  const expirationDate = cert.valid_to ? new Date(cert.valid_to) : null;

  return {
    issuer: sanitizeIssuer(cert.issuer),
    expiresAt: expirationDate && Number.isFinite(expirationDate.getTime())
      ? expirationDate.toISOString()
      : null,
    subject: cert.subject?.CN || null
  };
}

function classifySocketError(err) {
  if (!err) return formatSslError('unknown', null, 'Unknown TLS error');

  if (err.code === 'ETIMEDOUT') {
    return formatSslError('timeout', err.code, 'TLS handshake timed out');
  }

  if (NETWORK_ERROR_CODES.has(err.code)) {
    return formatSslError('network_error', err.code, err.message);
  }

  if (HANDSHAKE_ERROR_CODES.has(err.code) || String(err.code || '').startsWith('ERR_SSL')) {
    return formatSslError('tls_handshake_failure', err.code, err.message);
  }

  const mapped = SSL_ERROR_MAP[err.code];
  if (mapped) {
    return formatSslError(mapped, err.code, err.message);
  }

  return formatSslError('tls_error', err.code, err.message);
}

async function getRedirectChain(url) {
  const maxRedirects = 10;
  const chain = [];
  let current = url;
  let count = 0;
  let error = null;

  while (count < maxRedirects) {
    const currentHost = getHostname(current);
    if (isPrivateOrLocalHost(currentHost)) {
      error = {
        type: 'blocked_target',
        message: 'Redirect target resolves to private or local network host'
      };
      break;
    }

    const result = await new Promise((resolve) => {
      const lib = current.startsWith('https') ? https : http;
      const req = lib.request(current, { method: 'HEAD', timeout: REDIRECT_TIMEOUT_MS }, (res) => {
        const status = res.statusCode;
        if (status >= 300 && status < 400 && res.headers.location) {
          resolve({ redirect: true, location: res.headers.location });
        } else {
          resolve({ redirect: false, finalUrl: current });
        }
      });
      req.on('timeout', () => {
        req.destroy();
        resolve({
          redirect: false,
          finalUrl: current,
          error: { type: 'timeout', message: 'Redirect check timed out' }
        });
      });
      req.on('error', (err) => {
        resolve({
          redirect: false,
          finalUrl: current,
          error: { type: 'network_error', code: err.code || null, message: err.message }
        });
      });
      req.end();
    });

    chain.push(current);

    if (result.error) {
      error = result.error;
      break;
    }

    if (!result.redirect) break;

    const next = result.location;
    current = next.startsWith('http') ? next : new URL(next, current).toString();

    const nextHost = getHostname(current);
    if (isPrivateOrLocalHost(nextHost)) {
      chain.push(current);
      error = {
        type: 'blocked_target',
        message: 'Redirect target resolves to private or local network host'
      };
      break;
    }

    count++;
  }

  return {
    chain,
    count: Math.max(0, chain.length - 1),
    finalUrl: current,
    error
  };
}

async function checkSslCertificate(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return {
      https: false,
      valid: null,
      issuer: null,
      expiresAt: null,
      subject: null,
      error: formatSslError('invalid_url', null, 'Invalid URL'),
      warning: null
    };
  }

  if (parsed.protocol !== 'https:') {
    return {
      https: false,
      valid: null,
      issuer: null,
      expiresAt: null,
      subject: null,
      error: null,
      warning: null
    };
  }

  return new Promise((resolve) => {
    const hostname = parsed.hostname;
    const port = Number(parsed.port || 443);
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false
    });

    let settled = false;

    function finalize(payload) {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(payload);
    }

    socket.setTimeout(SSL_TIMEOUT_MS, () => {
      finalize({
        https: true,
        valid: null,
        issuer: null,
        expiresAt: null,
        subject: null,
        error: formatSslError('timeout', 'ETIMEDOUT', 'TLS handshake timed out'),
        warning: null
      });
    });

    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate(true);
      const details = buildCertDetails(cert);
      const hasCertificate = cert && Object.keys(cert).length > 0;
      if (!hasCertificate) {
        finalize({
          https: true,
          valid: false,
          ...details,
          error: formatSslError('invalid_certificate', 'NO_CERTIFICATE', 'Server did not provide a TLS certificate'),
          warning: null
        });
        return;
      }

      const hostnameErr = tls.checkServerIdentity(hostname, cert);

      if (hostnameErr) {
        finalize({
          https: true,
          valid: false,
          ...details,
          error: formatSslError('hostname_mismatch', hostnameErr.code || 'ERR_TLS_CERT_ALTNAME_INVALID', hostnameErr.message),
          warning: null
        });
        return;
      }

      if (socket.authorizationError) {
        const mappedType = SSL_ERROR_MAP[socket.authorizationError] || 'invalid_certificate';
        const isDefinitiveInvalid = DEFINITIVE_CERT_FAILURES.has(mappedType);
        finalize({
          https: true,
          valid: isDefinitiveInvalid ? false : true,
          ...details,
          error: isDefinitiveInvalid
            ? formatSslError(mappedType, socket.authorizationError, socket.authorizationError)
            : null,
          warning: isDefinitiveInvalid
            ? null
            : formatSslError('ca_validation_warning', socket.authorizationError, 'Certificate chain validation differs by runtime CA bundle')
        });
        return;
      }

      const expiresAt = details.expiresAt ? new Date(details.expiresAt) : null;
      if (expiresAt && Number.isFinite(expiresAt.getTime()) && expiresAt.getTime() < Date.now()) {
        finalize({
          https: true,
          valid: false,
          ...details,
          error: formatSslError('expired_certificate', 'CERT_HAS_EXPIRED', 'Certificate is expired'),
          warning: null
        });
        return;
      }

      finalize({
        https: true,
        valid: true,
        ...details,
        error: null,
        warning: null
      });
    });

    socket.on('error', (err) => {
      const classified = classifySocketError(err);
      const isNetworkOrTimeout = classified.type === 'network_error' || classified.type === 'timeout';

      finalize({
        https: true,
        valid: isNetworkOrTimeout ? null : false,
        issuer: null,
        expiresAt: null,
        subject: null,
        error: classified,
        warning: null
      });
    });
  });
}

async function getDomainAge(url) {
  const hostname = getHostname(url);
  if (!hostname || isIpHost(hostname)) {
    return { ageDays: null, registrationDate: null, error: 'Not a domain' };
  }

  try {
    const rdapUrl = `https://rdap.org/domain/${hostname}`;
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

  const excessiveRedirects = redirects.count > 3;

  return {
    ssl,
    redirects: {
      chain: redirects.chain,
      count: redirects.count,
      excessive: excessiveRedirects,
      error: redirects.error
    },
    domainAge
  };
}

module.exports = { analyze };
