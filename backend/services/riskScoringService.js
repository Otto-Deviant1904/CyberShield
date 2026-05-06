function calculateScore(scanResult) {
  let score = 0;
  const reasons = [];

  const vt = scanResult.threatIntel?.virustotal || {};
  const heur = scanResult.heuristics || {};
  const ssl = scanResult.ssl || {};
  const domain = scanResult.domain || {};

  if (vt.status === 'success') {
    if (vt.malicious > 5) {
      score += 60;
      reasons.push(`VirusTotal malicious detections > 5 (+60)`);
    } else if (vt.malicious > 0) {
      score += 30;
      reasons.push(`VirusTotal malicious detections > 0 (+30)`);
    }
    if (vt.suspicious > 0) {
      score += 25;
      reasons.push(`VirusTotal suspicious detections present (+25)`);
    }
  }

  if (domain.age?.ageDays !== null && domain.age.ageDays < 30) {
    score += 25;
    reasons.push(`Domain age < 30 days (+25)`);
  }

  if (!ssl.hasHttps) {
    score += 20;
    reasons.push(`No HTTPS protocol (+20)`);
  }

  if (heur.hasIpAddress) {
    score += 15;
    reasons.push(`IP-address URL (+15)`);
  }

  if (heur.suspiciousKeywords?.length > 0) {
    score += 10;
    reasons.push(`Suspicious keywords detected (+10)`);
  }

  if (heur.punycode) {
    score += 25;
    reasons.push(`Punycode domain (+25)`);
  }

  if (heur.suspiciousTld) {
    score += 15;
    reasons.push(`Suspicious TLD .${heur.tld} (+15)`);
  }

  if (heur.highEntropy) {
    score += 10;
    reasons.push(`High URL entropy (+10)`);
  }

  if (heur.longUrl) {
    score += 5;
    reasons.push(`Excessively long URL (+5)`);
  }

  if (heur.excessiveSubdomains) {
    score += 10;
    reasons.push(`Excessive subdomains (+10)`);
  }

  if (ssl.valid === false && ssl.hasHttps) {
    score += 15;
    reasons.push(`Invalid SSL certificate (+15)`);
  }

  if (domain.redirects?.excessive) {
    score += 15;
    reasons.push(`Excessive redirects (+15)`);
  }

  if (score > 100) score = 100;

  let level = 'LOW';
  if (score > 50) level = 'HIGH';
  else if (score > 20) level = 'MEDIUM';

  return { score, level, reasons };
}

module.exports = { calculateScore };
