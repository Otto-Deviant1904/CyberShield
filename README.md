# CyberShield URL Scanner 🛡️

A professional, full-stack cybersecurity tool for real-time URL threat analysis and risk assessment.

##  Features
- **Heuristic Analysis:** Checks for SSL/HTTPS, IP-based domains, Punycode (homograph attacks), and subdomain overflow.
- **Risk Scoring:** Intelligent risk meter categorizing URLs as Safe, Suspicious, or Dangerous.
- **VirusTotal Integration:** Cross-references URLs against 70+ antivirus engines.
- **Entropy Calculation:** Detects programmatically generated or obfuscated domain names.
- **Modern UI:** High-performance dashboard built with React, Tailwind CSS, and Framer Motion.
- **Dark Mode SOC Aesthetic:** Premium cybersecurity-focused design.
- **Export Reports:** Download scan results as JSON for further investigation.

## Tech Stack
- **Frontend:** React, Vite, TailwindCSS, Lucide Icons, Framer Motion.
- **Backend:** Node.js, Express, Axios, Helmet (Security), Express-Rate-Limit.
- **Analysis:** Shannon Entropy, Custom Regex Heuristics, VT API.

## Installation & Setup

### 1) Backend

```bash
cd backend
npm install
cp .env.example .env
```

Set your API key in `backend/.env`:

```env
VIRUSTOTAL_API_KEY=your_key_here
PORT=5000
```

Start backend:

```bash
npm run dev
```

### 2) Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:3000` and calls backend via `/api/scan`.

Optional custom backend base URL:

```env
VITE_API_BASE_URL=http://localhost:5000
```

## API Endpoints
`POST /api/scan`
- **Body:** `{ "url": "https://example.com" }`
- **Response:** Detailed JSON report with basic checks and VirusTotal data.

## License
MIT License.
