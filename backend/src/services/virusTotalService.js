const axios = require('axios');

class VirusTotalService {
  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    this.baseUrl = 'https://www.virustotal.com/api/v3';
  }

  async scanUrl(url) {
    if (!this.apiKey || this.apiKey === 'your_api_key_here') {
      return { status: 'skipped', message: 'API key missing' };
    }

    try {
      // VT requires URL to be base64 (without padding)
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
      
      const response = await axios.get(`${this.baseUrl}/urls/${urlId}`, {
        headers: { 'x-apikey': this.apiKey }
      });

      const stats = response.data.data.attributes.last_analysis_stats;
      return {
        status: 'success',
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        harmless: stats.harmless,
        undetected: stats.undetected
      };
    } catch (error) {
      if (error.response && error.response.status === 404) {
        return { status: 'not_found', message: 'URL not in VirusTotal database' };
      }
      return { status: 'error', message: error.message };
    }
  }
}

module.exports = new VirusTotalService();
