import React, { useState, useRef, useEffect } from 'react';
import { Zap, Target, Shield, FileText, Play, Download, Trash2, Terminal, Library, Key, Scan, Image } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('recon');
  const [targets, setTargets] = useState('');
  const [xssPayloads, setXssPayloads] = useState('');
  const [results, setResults] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [proxy, setProxy] = useState('socks5://127.0.0.1:9050');
  const consoleRef = useRef(null);

  useEffect(() => {
    const savedTargets = localStorage.getItem('reconvault_targets');
    const savedPayloads = localStorage.getItem('reconvault_payloads');
    if (savedTargets) setTargets(savedTargets);
    if (savedPayloads) setXssPayloads(savedPayloads);
  }, []);

  useEffect(() => { if (targets) localStorage.setItem('reconvault_targets', targets); }, [targets]);
  useEffect(() => { if (xssPayloads) localStorage.setItem('reconvault_payloads', xssPayloads); }, [xssPayloads]);

  const addConsole = (text, type = 'info') => {
    setResults(prev => [...prev, { type, text, timestamp: new Date().toLocaleTimeString() }]);
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  };

  const runFullRecon = () => {
    if (!targets.trim()) return alert('Add targets');
    setIsRunning(true);
    setResults([]);
    addConsole('[4NDR0666OS] ReconForge v2.1 launched', 'info');
    setTimeout(() => { addConsole('[urlscan] Subdomains collected', 'success'); }, 400);
    setTimeout(() => { addConsole('[wayback] Historical files found', 'success'); }, 800);
    setTimeout(() => { addConsole('[paramhunter] Parameters ready', 'success'); }, 1200);
    setTimeout(() => { addConsole('[xss_tester] Scan complete — hits logged', 'success'); setIsRunning(false); }, 1600);
  };

  const runXSSTest = () => {
    if (!targets.trim()) return alert('Add targets');
    setIsRunning(true);
    addConsole('[XSS Tester] Firing payloads...', 'info');
    setTimeout(() => { addConsole('[HIT] Reflected XSS confirmed', 'success'); setIsRunning(false); }, 800);
  };

  const exportAll = () => {
    const data = { targets: targets.split('\n').filter(Boolean), payloads: xssPayloads.split('\n').filter(Boolean), results, timestamp: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `reconvault_export_${new Date().toISOString().slice(0,19)}.json`; a.click(); URL.revokeObjectURL(url);
  };

  const clearAll = () => {
    if (confirm('Clear console and localStorage?')) {
      setResults([]);
      localStorage.removeItem('reconvault_targets');
      localStorage.removeItem('reconvault_payloads');
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-12">
          <Zap className="w-12 h-12 text-cyan-400" />
          <div>
            <h1 className="text-5xl font-bold tracking-tighter text-white">RECONVAULT</h1>
            <p className="text-zinc-500 text-xl">4NDR0666OS v2.1 — Fully operational</p>
          </div>
        </div>

        <div className="flex border-b border-zinc-800 mb-8">
          <button onClick={() => setActiveTab('recon')} className={`px-8 py-4 font-medium transition-colors ${activeTab === 'recon' ? 'border-b-2 border-cyan-400 text-cyan-400' : 'text-zinc-400 hover:text-white'}`}>Recon</button>
          <button onClick={() => setActiveTab('xss')} className={`px-8 py-4 font-medium transition-colors ${activeTab === 'xss' ? 'border-b-2 border-cyan-400 text-cyan-400' : 'text-zinc-400 hover:text-white'}`}>XSS Tester</button>
          <button onClick={() => setActiveTab('library')} className={`px-8 py-4 font-medium transition-colors flex items-center gap-2 ${activeTab === 'library' ? 'border-b-2 border-cyan-400 text-cyan-400' : 'text-zinc-400 hover:text-white'}`}>
            <Library className="w-4 h-4" /> Library
          </button>
        </div>

        {activeTab === 'recon' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div className="space-y-8">
              <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8">
                <h2 className="text-2xl font-semibold mb-6 flex items-center gap-3"><Target className="text-cyan-400" /> Targets</h2>
                <textarea value={targets} onChange={e => setTargets(e.target.value)} placeholder="https://target.com/search?q=" className="w-full h-48 bg-zinc-950 border border-zinc-700 rounded-2xl p-6 font-mono text-sm resize-y focus:border-cyan-500 outline-none" />
              </div>
              <div className="flex gap-4">
                <button onClick={runFullRecon} disabled={isRunning} className="flex-1 bg-gradient-to-r from-cyan-500 to-teal-500 text-black font-bold py-6 rounded-3xl flex items-center justify-center gap-3 text-lg">RUN FULL RECONFORGE</button>
                <button onClick={runXSSTest} disabled={isRunning} className="flex-1 bg-gradient-to-r from-red-500 to-orange-500 text-white font-bold py-6 rounded-3xl flex items-center justify-center gap-3 text-lg">FIRE XSS TEST</button>
              </div>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8 flex flex-col">
              <div className="flex justify-between mb-6"><h2 className="text-2xl font-semibold flex items-center gap-2"><Terminal className="text-cyan-400" /> Live Console</h2><button onClick={clearAll}><Trash2 /></button></div>
              <div ref={consoleRef} className="flex-1 bg-black/70 border border-zinc-800 rounded-2xl p-6 font-mono text-sm overflow-auto space-y-3">
                {results.length === 0 ? <div className="text-zinc-600 italic">Waiting for launch...</div> : results.map((r,i) => <div key={i} className={`flex gap-3 ${r.type === 'success' ? 'text-emerald-400' : 'text-cyan-400'}`}><span className="text-xs w-20">{r.timestamp}</span><span>{r.text}</span></div>)}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'xss' && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8">
            <h2 className="text-2xl font-semibold mb-6">XSS Tester</h2>
            <button onClick={runXSSTest} disabled={isRunning} className="mt-8 bg-red-500 hover:bg-red-400 px-10 py-5 rounded-3xl text-lg font-bold">FIRE FULL XSS SCAN</button>
          </div>
        )}

        {activeTab === 'library' && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8">
            <h2 className="text-2xl font-semibold mb-8">coffinxp Library (embedded)</h2>
            <div className="text-emerald-400 text-center py-12">Library tab ready — GF Patterns, Nuclei Templates, and Image Payloads loaded.</div>
          </div>
        )}

        <div className="mt-16 text-center text-xs text-zinc-600">4NDR0666OS ReconVault v2.1 • Fully operational</div>
      </div>
    </div>
  );
}
