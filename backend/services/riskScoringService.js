function clampScore(score) {
  return Math.max(0, Math.min(100, score));
}

function scoreToLevel(score) {
  if (score >= 65) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

function addIndicator(indicators, key, weight, message, severity = 'medium') {
  indicators.push({
    key,
    weight,
    severity,
    message
  });
}

function calculateScore(scanResult) {
  const vt = scanResult.threatIntel?.virustotal || {};
  const heuristics = scanResult.heuristics || {};
  const ssl = scanResult.ssl || {};
  const domain = scanResult.domain || {};

  const indicators = [];

  if (vt.status === 'success') {
    if (vt.malicious >= 8) {
      addIndicator(
        indicators,
        'vt_malicious_high',
        55,
        `${vt.malicious} security vendors flagged this URL as malicious`,
        'high'
      );
    } else if (vt.malicious > 0) {
      addIndicator(
        indicators,
        'vt_malicious_present',
        35,
        `${vt.malicious} security vendors flagged this URL as malicious`,
        'high'
      );
    }

    if (vt.suspicious > 0) {
      addIndicator(
        indicators,
        'vt_suspicious_present',
        20,
        `${vt.suspicious} vendors marked this URL as suspicious`
      );
    }

    if (vt.reputation < 0) {
      addIndicator(
        indicators,
        'vt_negative_reputation',
        12,
        `VirusTotal reputation is negative (${vt.reputation})`
      );
    }
  }

  if (ssl.https === false) {
    addIndicator(indicators, 'no_https', 20, 'The URL does not use HTTPS', 'high');
  }

  if (ssl.https === true && ssl.valid === false) {
    const sslReason = ssl.error?.type
      ? `SSL certificate issue detected (${ssl.error.type.replace(/_/g, ' ')})`
      : 'SSL certificate validation failed';
    addIndicator(indicators, 'invalid_ssl', 24, sslReason, 'high');
  }

  if (domain.age?.ageDays !== null && domain.age?.ageDays !== undefined) {
    if (domain.age.ageDays < 7) {
      addIndicator(indicators, 'very_young_domain', 24, 'Domain age is less than 7 days', 'high');
    } else if (domain.age.ageDays < 30) {
      addIndicator(indicators, 'young_domain', 16, 'Domain age is less than 30 days');
    }
  }

  if (heuristics.suspiciousTld) {
    addIndicator(indicators, 'suspicious_tld', 14, `Suspicious TLD detected (.${heuristics.tld})`);
  }

  if (heuristics.punycode) {
    addIndicator(indicators, 'punycode', 18, 'Punycode domain detected (possible homograph attempt)');
  }

  if (heuristics.hasIpAddress) {
    addIndicator(indicators, 'ip_hostname', 14, 'URL uses a direct IP address instead of a hostname');
  }

  if (domain.redirects?.excessive) {
    addIndicator(
      indicators,
      'excessive_redirects',
      12,
      `URL performs excessive redirects (${domain.redirects.count})`
    );
  }

  if (heuristics.highEntropy) {
    addIndicator(
      indicators,
      'high_entropy',
      10,
      `Domain entropy is high (${heuristics.entropy})`
    );
  }

  if (heuristics.suspiciousKeywords?.length > 0) {
    addIndicator(
      indicators,
      'suspicious_keywords',
      8,
      `Suspicious keywords detected (${heuristics.suspiciousKeywords.join(', ')})`
    );
  }

  if (heuristics.excessiveSubdomains) {
    addIndicator(indicators, 'excessive_subdomains', 8, 'Domain has an unusual number of subdomains');
  }

  const rawScore = indicators.reduce((sum, item) => sum + item.weight, 0);
  const score = clampScore(rawScore);
  const level = scoreToLevel(score);
  const reasons = indicators.map((item) => item.message);

  return {
    score,
    level,
    indicators,
    reasons
  };
}

module.exports = {
  calculateScore
};
