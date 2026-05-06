const axios = require('axios');

const VT_BASE_URL = 'https://www.virustotal.com/api/v3';
const REQUEST_TIMEOUT_MS = 12000;
const POLL_INTERVAL_MS = 2500;
const MAX_POLL_ATTEMPTS = 8;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getApiKey() {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key || key === 'your_api_key_here') return null;
  return key;
}

function createClient(apiKey) {
  return axios.create({
    baseURL: VT_BASE_URL,
    timeout: REQUEST_TIMEOUT_MS,
    headers: {
      'x-apikey': apiKey
    }
  });
}

function encodeUrlId(url) {
  return Buffer.from(url)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function buildError(status, message, meta = {}) {
  return {
    status,
    message,
    ...meta
  };
}

function extractStats(attributes = {}) {
  const stats = attributes.last_analysis_stats || {};
  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    reputation: attributes.reputation || 0,
    lastAnalysisDate: attributes.last_analysis_date
      ? new Date(attributes.last_analysis_date * 1000).toISOString()
      : null
  };
}

function mapAxiosError(err) {
  const statusCode = err.response?.status;

  if (statusCode === 429) {
    return buildError('rate_limited', 'VirusTotal API rate limit reached');
  }

  if (statusCode === 404) {
    return buildError('not_found', 'VirusTotal report not found yet');
  }

  if (statusCode >= 500) {
    return buildError('service_unavailable', 'VirusTotal service is currently unavailable');
  }

  if (err.code === 'ECONNABORTED') {
    return buildError('timeout', 'VirusTotal request timed out');
  }

  return buildError('error', err.message || 'VirusTotal request failed');
}

async function submitUrl(client, url) {
  try {
    const response = await client.post(
      '/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const analysisId = response.data?.data?.id;
    if (!analysisId) {
      return buildError('error', 'VirusTotal did not return an analysis ID');
    }

    return {
      status: 'submitted',
      analysisId
    };
  } catch (err) {
    return mapAxiosError(err);
  }
}

async function pollAnalysis(client, analysisId) {
  for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt += 1) {
    try {
      const response = await client.get(`/analyses/${analysisId}`);
      const attrs = response.data?.data?.attributes || {};

      if (attrs.status === 'completed') {
        return {
          status: 'completed',
          stats: extractStats(attrs)
        };
      }
    } catch (err) {
      const mapped = mapAxiosError(err);
      if (mapped.status === 'rate_limited') {
        await sleep(16000);
        continue;
      }
      if (mapped.status !== 'not_found') {
        return mapped;
      }
    }

    await sleep(POLL_INTERVAL_MS);
  }

  return buildError('report_unavailable', 'VirusTotal analysis is still queued');
}

async function fetchUrlReport(client, url) {
  const urlId = encodeUrlId(url);

  try {
    const response = await client.get(`/urls/${urlId}`);
    const attrs = response.data?.data?.attributes;

    if (!attrs) {
      return buildError('report_unavailable', 'VirusTotal returned an empty URL report');
    }

    return {
      status: 'success',
      ...extractStats(attrs)
    };
  } catch (err) {
    return mapAxiosError(err);
  }
}

function mergeResults(primary, fallback) {
  if (primary.status === 'success') return primary;
  if (fallback.status === 'success') return fallback;

  if (primary.status === 'report_unavailable' && fallback.status === 'not_found') {
    return buildError('report_unavailable', 'VirusTotal does not have a completed report for this URL yet');
  }

  return primary;
}

async function scanUrl(url) {
  const apiKey = getApiKey();
  if (!apiKey) {
    return buildError('skipped', 'VirusTotal API key not configured');
  }

  const client = createClient(apiKey);

  const submitResult = await submitUrl(client, url);
  if (submitResult.status !== 'submitted') {
    if (submitResult.status === 'rate_limited') {
      const reportFallback = await fetchUrlReport(client, url);
      return mergeResults(submitResult, reportFallback);
    }
    return submitResult;
  }

  const pollResult = await pollAnalysis(client, submitResult.analysisId);
  const reportResult = await fetchUrlReport(client, url);

  if (reportResult.status === 'success') {
    return reportResult;
  }

  if (pollResult.status === 'completed') {
    return {
      status: 'success',
      ...pollResult.stats
    };
  }

  return mergeResults(pollResult, reportResult);
}

module.exports = {
  scanUrl
};
