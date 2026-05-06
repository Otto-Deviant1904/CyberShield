import React, { useMemo, useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

const RISK_THEME = {
  LOW: { className: 'badge-low', ring: '#19d3a2', glow: 'rgba(25, 211, 162, 0.35)' },
  MEDIUM: { className: 'badge-medium', ring: '#f9b74a', glow: 'rgba(249, 183, 74, 0.35)' },
  HIGH: { className: 'badge-high', ring: '#ff5f73', glow: 'rgba(255, 95, 115, 0.35)' }
};

function RiskRing({ score = 0, level = 'LOW' }) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const theme = RISK_THEME[level] || RISK_THEME.LOW;

  const style = {
    background: `conic-gradient(${theme.ring} ${value * 3.6}deg, rgba(255,255,255,0.12) 0deg)`,
    boxShadow: `0 0 35px ${theme.glow}`
  };

  return (
    <div className="risk-ring" style={style}>
      <div className="risk-ring-inner">
        <span className="risk-score">{value}</span>
        <span className="risk-label">/ 100</span>
      </div>
    </div>
  );
}

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const risk = result?.risk || { score: 0, level: 'LOW' };
  const riskTheme = useMemo(() => RISK_THEME[risk.level] || RISK_THEME.LOW, [risk.level]);
  const vt = result?.threatIntel?.virustotal || {};
  const ssl = result?.ssl || {};
  const domain = result?.domain || {};
  const heuristics = result?.heuristics || {};
  const indicators = result?.indicators || [];
  const reasons = result?.reasons || [];

  const handleScan = async (event) => {
    event.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post(
        `${API_BASE}/api/scan`,
        { url: url.trim() },
        { timeout: 50000 }
      );
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed. Please verify the URL and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <div className="noise-overlay" />

      <main className="dashboard">
        <header className="hero-card reveal">
          <p className="eyebrow">CyberShield Scanner</p>
          <h1>Threat Intelligence Dashboard</h1>
          <p className="subtitle">
            Analyze suspicious URLs with TLS diagnostics, VirusTotal verdicts, and weighted risk modeling.
          </p>

          <form onSubmit={handleScan} className="scan-form">
            <input
              type="text"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://target.example"
              autoComplete="off"
            />
            <button type="submit" disabled={loading}>
              {loading ? 'Scanning...' : 'Scan URL'}
            </button>
          </form>

          {error && <div className="error-banner">{error}</div>}
        </header>

        {loading && (
          <section className="loading-card reveal">
            <div className="scan-pulse" />
            <div>
              <h2>Running active analysis</h2>
              <p>Collecting SSL handshake details, redirect chain behavior, domain age, and VirusTotal signals.</p>
            </div>
            <div className="loading-bars">
              <span />
              <span />
              <span />
            </div>
          </section>
        )}

        {result && (
          <>
            <section className="results-grid reveal">
              <article className="card risk-overview">
                <div className="card-title-row">
                  <h2>Overall Risk</h2>
                  <span className={`risk-badge ${riskTheme.className}`}>{risk.level}</span>
                </div>
                <RiskRing score={risk.score} level={risk.level} />
                <p className="mono">Scanned URL: {result.url}</p>
              </article>

              <article className="card">
                <h2>SSL / TLS Status</h2>
                <div className="metric-list">
                  <div><span>HTTPS</span><strong>{ssl.https ? 'Yes' : 'No'}</strong></div>
                  <div><span>Certificate Valid</span><strong>{ssl.valid === null ? 'Unknown' : ssl.valid ? 'Yes' : 'No'}</strong></div>
                  <div><span>Issuer</span><strong>{ssl.issuer || 'N/A'}</strong></div>
                  <div><span>Expires</span><strong>{ssl.expiresAt ? new Date(ssl.expiresAt).toLocaleString() : 'N/A'}</strong></div>
                  <div><span>Diagnostic</span><strong>{ssl.error?.type || ssl.warning?.type || 'None'}</strong></div>
                </div>
              </article>

              <article className="card">
                <h2>VirusTotal</h2>
                <div className="metric-list">
                  <div><span>Status</span><strong>{vt.status || 'N/A'}</strong></div>
                  <div><span>Malicious</span><strong>{vt.malicious ?? 'N/A'}</strong></div>
                  <div><span>Suspicious</span><strong>{vt.suspicious ?? 'N/A'}</strong></div>
                  <div><span>Harmless</span><strong>{vt.harmless ?? 'N/A'}</strong></div>
                  <div><span>Reputation</span><strong>{vt.reputation ?? 'N/A'}</strong></div>
                </div>
              </article>

              <article className="card">
                <h2>Domain & Behavior</h2>
                <div className="metric-list">
                  <div><span>Domain Age (days)</span><strong>{domain.age?.ageDays ?? 'N/A'}</strong></div>
                  <div><span>Redirect Count</span><strong>{domain.redirects?.count ?? 0}</strong></div>
                  <div><span>Entropy Score</span><strong>{heuristics.entropy ?? 'N/A'}</strong></div>
                  <div><span>Punycode</span><strong>{heuristics.punycode ? 'Yes' : 'No'}</strong></div>
                  <div><span>Suspicious TLD</span><strong>{heuristics.suspiciousTld ? `.${heuristics.tld}` : 'No'}</strong></div>
                </div>
              </article>
            </section>

            <section className="card warnings-card reveal">
              <h2>Triggered Indicators</h2>
              {indicators.length > 0 ? (
                <ul className="pill-list">
                  {indicators.map((indicator) => (
                    <li key={indicator.key} className={`pill ${indicator.severity === 'high' ? 'pill-high' : 'pill-medium'}`}>
                      <span>{indicator.message}</span>
                      <strong>+{indicator.weight}</strong>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No high-risk indicators were triggered.</p>
              )}
            </section>

            <section className="card reveal">
              <h2>Human-readable Explanations</h2>
              {reasons.length > 0 ? (
                <ul className="reason-list">
                  {reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No notable reasons were generated for this URL.</p>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
