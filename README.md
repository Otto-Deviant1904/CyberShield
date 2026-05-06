# CyberShield URL Scanner 

A professional, full-stack cybersecurity tool for real-time URL threat analysis and risk assessment.

## Features
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

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd cybershield
```

### 2. Backend Setup
```bash
cd backend
npm install
cp .env.example .env
# Add your VirusTotal API key to .env
npm start
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

The app will be available at `http://localhost:3000`.

## API Endpoints
`POST /api/scan`
- **Body:** `{ "url": "https://example.com" }`
- **Response:** Detailed JSON report with basic checks and VirusTotal data.

## License
MIT License.
