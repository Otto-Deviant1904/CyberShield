import React from 'react';
import { 
  CheckCircle2, AlertTriangle, XCircle, 
  ExternalLink, Info, Activity, ShieldCheck, 
  Lock, Unlocked, Hash, Download
} from 'lucide-react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs) {
  return twMerge(clsx(inputs));
}

const Report = ({ result }) => {
  const { basicReport, vtReport, summary, url, timestamp } = result;

  const riskColors = {
    Safe: 'text-cyber-accent bg-cyber-accent/10 border-cyber-accent/20',
    Suspicious: 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/20',
    Dangerous: 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/20',
  };

  const exportToJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", `scan-report-${new URL(url).hostname}.json`);
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Summary Header */}
      <div className="glass-card p-6 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="flex items-center gap-4">
          <div className={cn(
            "p-4 rounded-2xl border flex items-center justify-center",
            riskColors[summary.riskLevel]
          )}>
            {summary.riskLevel === 'Safe' ? <CheckCircle2 className="w-8 h-8" /> : 
             summary.riskLevel === 'Suspicious' ? <AlertTriangle className="w-8 h-8" /> : 
             <XCircle className="w-8 h-8" />}
          </div>
          <div>
            <h3 className="text-2xl font-bold">{summary.riskLevel} Assessment</h3>
            <p className="text-slate-400 text-sm truncate max-w-md">{url}</p>
          </div>
        </div>
        
        <div className="flex gap-3 w-full md:w-auto">
          <button 
            onClick={exportToJson}
            className="flex-1 md:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg border border-white/10 transition-colors text-sm"
          >
            <Download className="w-4 h-4" /> Export Report
          </button>
          <a 
            href={url} target="_blank" rel="noopener noreferrer"
            className="flex-1 md:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-cyber-accent text-black font-bold rounded-lg hover:opacity-90 transition-opacity text-sm"
          >
            <ExternalLink className="w-4 h-4" /> Visit Site
          </a>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* VT Analysis */}
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-2 text-slate-300 font-semibold mb-2">
            <Activity className="w-4 h-4 text-cyber-accent" />
            <span>VirusTotal Intel</span>
          </div>
          
          {vtReport.status === 'success' ? (
            <div className="space-y-3">
              <StatItem label="Malicious" value={vtReport.malicious} color="text-cyber-danger" />
              <StatItem label="Suspicious" value={vtReport.suspicious} color="text-cyber-warning" />
              <StatItem label="Harmless/Undetected" value={vtReport.harmless + vtReport.undetected} color="text-cyber-accent" />
            </div>
          ) : (
            <p className="text-xs text-slate-500 italic">VirusTotal data not available for this URL.</p>
          )}
        </div>

        {/* Security Heuristics */}
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-2 text-slate-300 font-semibold mb-2">
            <ShieldCheck className="w-4 h-4 text-cyber-accent" />
            <span>Connection & Protocol</span>
          </div>
          <div className="space-y-3">
            <CheckItem label="SSL Certificate" status={basicReport.isHttps} />
            <CheckItem label="Hostname Verification" status={!basicReport.hasIpAddress} />
            <CheckItem label="Standard Encoding" status={!basicReport.isPunycode} />
          </div>
        </div>

        {/* Advanced Metrics */}
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-2 text-slate-300 font-semibold mb-2">
            <Hash className="w-4 h-4 text-cyber-accent" />
            <span>Advanced Metadata</span>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">URL Entropy</span>
              <span className={cn("font-mono", basicReport.entropy > 4.5 ? 'text-cyber-warning' : 'text-slate-300')}>
                {basicReport.entropy.toFixed(2)}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">Subdomains</span>
              <span className="text-slate-300">{basicReport.subdomainCount}</span>
            </div>
            <div className="text-sm">
              <span className="text-slate-400 block mb-1">Keywords Detected</span>
              <div className="flex flex-wrap gap-1">
                {basicReport.suspiciousKeywords.length > 0 ? (
                  basicReport.suspiciousKeywords.map(kw => (
                    <span key={kw} className="bg-cyber-danger/20 text-cyber-danger px-2 py-0.5 rounded text-[10px] border border-cyber-danger/30 uppercase font-bold">
                      {kw}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-600 text-xs italic">None</span>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const StatItem = ({ label, value, color }) => (
  <div className="flex justify-between items-center bg-white/5 p-3 rounded-lg border border-white/5">
    <span className="text-sm text-slate-400">{label}</span>
    <span className={cn("font-bold text-lg", color)}>{value}</span>
  </div>
);

const CheckItem = ({ label, status }) => (
  <div className="flex justify-between items-center">
    <span className="text-sm text-slate-400">{label}</span>
    {status ? (
      <div className="flex items-center gap-1 text-cyber-accent text-xs font-medium">
        <Lock className="w-3 h-3" /> SECURE
      </div>
    ) : (
      <div className="flex items-center gap-1 text-cyber-danger text-xs font-medium">
        <Unlocked className="w-3 h-3" /> RISK
      </div>
    )}
  </div>
);

export default Report;
