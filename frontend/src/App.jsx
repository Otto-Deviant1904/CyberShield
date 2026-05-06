import React, { useState } from 'react';
import axios from 'axios';

const RISK_COLORS = {
  LOW: { bg: '#064e3b', text: '#34d399' },
  MEDIUM: { bg: '#78350f', text: '#fbbf24' },
  HIGH: { bg: '#7f1d1d', text: '#f87171' }
};

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!url) return;
    try {
      setLoading(true);
      const response = await axios.post(
        'http://localhost:5000/scan',
        { url }
      );
      setResult(response.data);
    } catch (error) {
      console.error(error);
      alert('Scan failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        background: '#0f172a',
        color: 'white',
        minHeight: '100vh',
        padding: '2rem',
        fontFamily: 'sans-serif'
      }}
    >
      <h1 style={{ fontSize: '2rem', marginBottom: '2rem' }}>
        CyberShield URL Scanner
      </h1>

      <div style={{ display: 'flex', gap: '1rem' }}>
        <input
          type="text"
          placeholder="Enter URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{
            padding: '1rem',
            width: '400px',
            borderRadius: '8px',
            border: 'none'
          }}
        />
        <button
          onClick={handleScan}
          style={{
            padding: '1rem 2rem',
            borderRadius: '8px',
            border: 'none',
            background: '#06b6d4',
            color: 'white',
            cursor: 'pointer'
          }}
        >
          Scan
        </button>
      </div>

      {loading && (
        <p style={{ marginTop: '2rem' }}>Scanning...</p>
      )}

      {result && (() => {
        const risk = result.risk || {};
        const colors = RISK_COLORS[risk.level] || RISK_COLORS.LOW;
        const vt = result.threatIntel?.virustotal || {};
        const ssl = result.ssl || {};
        const domain = result.domain || {};
        const heuristics = result.heuristics || {};

        return (
          <div
            style={{
              marginTop: '2rem',
              background: '#1e293b',
              padding: '1.5rem',
              borderRadius: '12px'
            }}
          >
            <h2>Scan Result</h2>

            <p><strong>URL:</strong> {result.url}</p>
            <p>
              <strong>Risk Level:</strong>{' '}
              <span style={{ color: colors.text, fontWeight: 'bold' }}>
                {risk.level}
              </span>
            </p>
            <p><strong>Risk Score:</strong> {risk.score}</p>

            {result.reasons?.length > 0 && (
              <>
                <p style={{ marginTop: '0.5rem' }}><strong>Triggered Warnings:</strong></p>
                <ul style={{ margin: '0.25rem 0 0 1.25rem' }}>
                  {result.reasons.map((r, i) => (
                    <li key={i} style={{ fontSize: '0.9rem' }}>{r}</li>
                  ))}
                </ul>
              </>
            )}

            <hr style={{ margin: '1rem 0', borderColor: '#334155' }} />

            <p><strong>VirusTotal</strong></p>
            {vt.status === 'success' ? (
              <ul style={{ margin: '0.25rem 0 0 1.25rem', fontSize: '0.9rem' }}>
                <li>Malicious: {vt.malicious}</li>
                <li>Suspicious: {vt.suspicious}</li>
                <li>Harmless: {vt.harmless}</li>
                <li>Reputation: {vt.reputation}</li>
              </ul>
            ) : (
              <p style={{ fontSize: '0.9rem', color: '#94a3b8' }}>
                {vt.message || 'Not available'}
              </p>
            )}

            <p style={{ marginTop: '0.75rem' }}><strong>SSL / HTTPS</strong></p>
            <ul style={{ margin: '0.25rem 0 0 1.25rem', fontSize: '0.9rem' }}>
              <li>HTTPS: {result.ssl?.hasHttps ? 'Yes' : 'No'}</li>
              <li>Certificate Valid: {ssl.valid ? 'Yes' : 'No'}</li>
              {ssl.issuer && <li>Issuer: {ssl.issuer}</li>}
            </ul>

            <p style={{ marginTop: '0.75rem' }}><strong>Domain</strong></p>
            <ul style={{ margin: '0.25rem 0 0 1.25rem', fontSize: '0.9rem' }}>
              {domain.age?.ageDays !== null && (
                <li>Age (days): {domain.age.ageDays}</li>
              )}
              {domain.redirects && (
                <li>Redirects: {domain.redirects.count}</li>
              )}
              {heuristics.suspiciousKeywords?.length > 0 && (
                <li>Keywords: {heuristics.suspiciousKeywords.join(', ')}</li>
              )}
              {heuristics.entropy !== undefined && (
                <li>Entropy: {heuristics.entropy}</li>
              )}
            </ul>
          </div>
        );
      })()}
    </div>
  );
}

export default App;