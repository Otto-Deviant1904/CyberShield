const axios = require('axios');

const VT_BASE = 'https://www.virustotal.com/api/v3';
const SUBMIT_DELAY_MS = 16000;

function getApiKey() {
  return process.env.VIRUSTOTAL_API_KEY || '';
}

async function submitUrl(url) {
  const apiKey = getApiKey();
  if (!apiKey || apiKey === 'your_api_key_here') {
    return { status: 'skipped', message: 'API key not configured' };
  }

  try {
    const response = await axios.post(
      `${VT_BASE}/urls`,
      new URLSearchParams({ url }),
      {
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 10000
      }
    );

    const analysisId = response.data?.data?.id;
    if (!analysisId) {
      return { status: 'error', message: 'No analysis ID returned' };
    }

    return { status: 'submitted', analysisId };
  } catch (err) {
    if (err.response?.status === 429) {
      return { status: 'rate_limited', message: 'Rate limit exceeded' };
    }
    return { status: 'error', message: err.message };
  }
}

async function pollAnalysis(analysisId) {
  const apiKey = getApiKey();
  const url = `${VT_BASE}/analyses/${analysisId}`;

  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const response = await axios.get(url, {
        headers: { 'x-apikey': apiKey },
        timeout: 10000
      });

      const status = response.data?.data?.attributes?.status;
      if (status === 'completed') {
        return { status: 'completed', data: response.data.data.attributes };
      }
    } catch (err) {
      if (err.response?.status === 429) {
        await new Promise(r => setTimeout(r, SUBMIT_DELAY_MS));
        continue;
      }
    }

    await new Promise(r => setTimeout(r, 3000));
  }

  return { status: 'timeout', message: 'Analysis polling timed out' };
}

function base64UrlEncode(str) {
  return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getUrlReport(url) {
  const apiKey = getApiKey();
  if (!apiKey || apiKey === 'your_api_key_here') {
    return { status: 'skipped', message: 'API key not configured' };
  }

  const urlId = base64UrlEncode(url);
  try {
    const response = await axios.get(`${VT_BASE}/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      timeout: 10000
    });

    const attrs = response.data?.data?.attributes;
    if (!attrs) return { status: 'not_found', message: 'No report available' };

    const stats = attrs.last_analysis_stats || {};
    return {
      status: 'success',
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      reputation: attrs.reputation || 0
    };
  } catch (err) {
    if (err.response?.status === 404) {
      return { status: 'not_found', message: 'URL not in VirusTotal database' };
    }
    if (err.response?.status === 429) {
      return { status: 'rate_limited', message: 'Rate limit exceeded' };
    }
    return { status: 'error', message: err.message };
  }
}

async function scanUrl(url) {
  const submitResult = await submitUrl(url);

  if (submitResult.status === 'submitted') {
    const pollResult = await pollAnalysis(submitResult.analysisId);
    if (pollResult.status === 'completed') {
      const stats = pollResult.data?.last_analysis_stats || {};
      return {
        status: 'success',
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        reputation: pollResult.data?.reputation || 0
      };
    }
    return pollResult;
  }

  if (submitResult.status === 'skipped' || submitResult.status === 'rate_limited') {
    return getUrlReport(url);
  }

  return submitResult;
}

module.exports = { scanUrl, getUrlReport };
