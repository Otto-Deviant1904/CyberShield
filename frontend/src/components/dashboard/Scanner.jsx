import React, { useState } from 'react';
import { Search, Globe, AlertCircle } from 'lucide-react';
import axios from 'axios';

const Scanner = ({ onScanStart, onScanComplete }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;
    
    setError('');
    onScanStart();

    try {
      const response = await axios.post('/api/scan', { url });
      onScanComplete(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to analyze URL. Please check the format.');
      onScanComplete(null);
    }
  };

  return (
    <div className="glass-card p-6 md:p-8">
      <form onSubmit={handleScan} className="relative">
        <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
          <Globe className="h-5 h-5 text-slate-500" />
        </div>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Paste suspicious URL here (e.g., https://example.com)"
          className="w-full bg-zinc-900 border border-white/10 rounded-xl py-4 pl-12 pr-32 focus:ring-2 focus:ring-cyber-accent focus:border-transparent outline-none transition-all"
        />
        <button
          type="submit"
          className="absolute right-2 top-2 bottom-2 px-6 bg-cyber-accent hover:bg-emerald-500 text-black font-bold rounded-lg transition-all flex items-center gap-2"
        >
          <Search className="w-4 h-4" />
          Scan URL
        </button>
      </form>
      
      {error && (
        <div className="mt-4 flex items-center gap-2 text-cyber-danger text-sm bg-cyber-danger/10 p-3 rounded-lg border border-cyber-danger/20">
          <AlertCircle className="w-4 h-4" />
          {error}
        </div>
      )}
      
      <div className="mt-6 flex flex-wrap gap-4 text-xs text-slate-500">
        <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> Real-time heuristic analysis</span>
        <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> VirusTotal Integration</span>
        <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> Entropy Scoring</span>
      </div>
    </div>
  );
};

export default Scanner;
