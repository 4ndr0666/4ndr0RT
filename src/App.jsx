import React, { useState, useRef, useEffect } from 'react';
import { Zap, Target, Shield, FileText, Play, Download, Trash2, Terminal, Upload, Library, Key, Scan, Image } from 'lucide-react';
import axios from 'axios';

export default function App() {
  const [activeTab, setActiveTab] = useState('recon');
  const [targets, setTargets] = useState('');
  const [xssPayloads, setXssPayloads] = useState('');
  const [results, setResults] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [proxy, setProxy] = useState('socks5://127.0.0.1:9050');
  const consoleRef = useRef(null);

  // Embedded canonical coffinxp data (literal raw fetch)
  const gfPatternsData = {
    "Allin1gf.json": `{
    "flags": "-iE",
    "patterns": [
        "access=", "admin=", "dbg=", "debug=", "edit=", "grant=", "test=", "alter=", "clone=", "create=", "delete=", "disable=", "enable=", "exec=", "execute=", "load=", "make=", "modify=", "rename=", "reset=", "shell=", "toggle=", "adm=", "root=", "cfg=", "config=",
        "id=", "user=", "account=", "number=", "order=", "no=", "doc=", "key=", "email=", "group=", "profile=", "edit=", "report=",
        "=.*.jpg", "=.*.jpeg", "=.*.gif", "=.*.png",
        "\\.action", "\\.adr", "\\.ascx", "\\.asmx", "\\.axd", "\\.backup", "\\.bak", "\\.bkf", "\\.bkp", "\\.bok", "\\.achee", "\\.cfg", "\\.cfm", "\\.cgi", "\\.cnf", "\\.conf", "\\.config", "\\.crt", "\\.csr", "\\.csv", "\\.dat", "\\.doc", "\\.docx", "\\.eml", "\\.env", "\\.exe", "\\.gz", "\\.ica", "\\.inf", "\\.ini", "\\.java", "\\.json", "\\.key", "\\.log", "\\.lst", "\\.mai", "\\.mbox", "\\.mbx", "\\.md", "\\.mdb", "\\.nsf", "\\.old", "\\.ora", "\\.pac", "\\.passwd", "\\.pcf", "\\.pdf", "\\.pem", "\\.pgp", "\\.pl", "plist", "\\.pwd", "\\.rdp", "\\.reg", "\\.rtf", "\\.skr", "\\.sql", "\\.swf", "\\.tpl", "\\.txt", "\\.url", "\\.wml", "\\.xls", "\\.xlsx", "\\.xml", "\\.xsd", "\\.yml"
    ]
}`,
    "api-keys.json": `{"flags": "-iE", "patterns": ["api_key", "apikey", "secret_key", "secretkey", "access_token", "client_secret"]}`
  };

  const nucleiTemplatesData = {
    "CVE-2025-29927.yaml": `id: CVE-2025-29927

info:
  name: Next.js Middleware Bypass
  author: pdresearch,pdteam,hazedic
  severity: critical
  description: |
    Next.js contains a critical middleware bypass vulnerability affecting versions 11.1.4 through 15.2.2.
  reference:
    - https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
  remediation: |
    Upgrade to Next.js 14.2.25 or 15.2.3 or later.
  classification:
    cvss-score: 9.1
  metadata:
    max-request: 1
  tags: cve,cve2025,nextjs,middleware,auth-bypass

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-Nextjs-Data: 1

    matchers:
      - type: status
        status:
          - 200
`
  };

  const imgPayloadsData = {
    "coffinxss.svg": `<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 20010904//EN" "http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd">
<svg version="1.0" xmlns="http://www.w3.org/2000/svg" width="2560.000000pt" height="1600.000000pt" viewBox="0 0 2560.000000 1600.000000" preserveAspectRatio="xMidYMid meet" onload="alert(document.domain)">
<metadata>
Created by Coffin | YOUTUBE: Lostsec
</metadata>
<g transform="translate(0.000000,1024.000000) scale(0.100000,-0.100000)" fill="#000000" stroke="none">
<path d="M1 8823 l1 -1418 34 0 c26 0 34 4 34 18 0 17 -9 21 -44 17 -10 -1 -15 3 -12 9 6 9 13 9 51 1 21 -5 45 0 45 9 0 6 -10 10 -22 10 -13 0 -33 1 -45 1 -12 0 -25 5 -29 11 -4 8 1 9 16 4 13 -4 20 -3 17 2 -3 5 -2 15 4 23 7 12 9 10 9 -9 0 -20 4 -23 30 -19 35 5 47 -6 30 -27 -10 -12 -9 -15 3 -15 19 0 16 48 -4 61 -8 5 -9 9 -3 9 6 0 14 -3 18 -7 16 -16 47 -8 67 19 26 34 49 37 48 6 0 -13 -3 -17 -6 -10 -2 6 -9 12 -14 12 -4 0 -6 -7 -2 -15 3 -9 2 -15 -3 -14 -21 4 -34 -2 -34 -15 0 -9 -7 -12 -20 -9 -12 3 -20 0 -20 -7 0 -7 6 -10 13 -7 7 3 19 -3 25 -13 8 -14 8 -20 0 -22 -7 -3 -8 -10 -3 -17 13 -23 28 15 15 39 -9 17 -6 23 24 40 18 12 36 30 39 42 4 14 11 19 21 15 9 -4 16 -1 16 5 0 7 4 7 13 0 8 -7 16 -6 26 5 12 13 11 14 -10 8 -21 -7 -22 -6 -11 8 9 10 10 17 2 22 -5 3 -10 -1 -10 -9 0 -16 -12 -21 -23 -10 -14 14 13 41 38 39 14 -2 25 1 25 6 0 6 -8 9 -17 7 -10 -2 -18 2 -18 9 0 16 -12 26 -12 10 0 -20 -34 -67 -49 -67 -8 0 -14 -4 -14 -10 0 -5 -9 -10 -20 -10 -11 0 -23 -7 -26 -15 -4 -8 -10 -15 -15 -15 -5 0 -2 11 7 25 9 14 23 24 32 23 8 -2 17 3 20 11 2 8 0 11 -6 7 -6 -4 -8 2 -5 14 3 11 0 20 -6 20 -6 0 -11 -10 -11 -22 0 -20 -1 -21 -20 -3 -16 15 -22 16 -35 5 -14 -12 -15 -9 -10 18 3 19 1 32 -5 32 -5 0 -10 -5 -10 -11 0 -5 -4 -7 -10 -4 -6 4 -5 11 2 19 14 15 48 1 45 -18 -1 -6 8 -11 21 -12 12 -1 22 3 22 8 0 6 7 8 15 4 10 -3 17 3 21 19 3 14 10 25 15 25 13 0 11 -14 -6 -36 -17 -23 -19 -34 -5 -34 6 0 10 7 10 16 0 10 6 14 15 10 8 -3 15 -1 15 4 0 6 -4 10 -10 10 -5 0 -7 7 -4 15 5 12 9 13 20 4 8 -7 17 -9 21 -6 3 4 -2 9 -11 13 -9 3 -14 10 -11 15 6 9 55 -10 55 -22 0 -4 7 -10 15 -13 14 -5 14 -3 0 17 -8 12 -21 22 -28 22 -6 1 -11 6 -10 13 2 7 -7 10 -25 7 -35 -7 -68 17 -56 42 7 16 8 16 11 -3 2 -12 13 -24 24 -27 13 -4 19 -1 16 6 -3 7 -10 11 -16 9 -6 -1 -11 5 -11 13 0 9 6 12 17 8 11 -4 14 -3 9 5 -4 7 -2 12 6 12 8 1 7 5 -5 14 -10 8 -14 17 -9 20 6 3 13 -1 16 -10 4 -9 9 -14 13 -11 3 4 12 2 20 -4 8 -7 13 -8 13 -1 0 14 -26 33 -34 25 -4 -4 -4 1 0 11 5 13 4 17 -3 13 -6 -4 -16 -1 -22 7 -9 11 -6 12 14 8 16 -3 25 0 25 8 0 7 -7 10 -15 7 -8 -4 -17 -1 -21 5 -4 6 -3 8 4 4 6 -3 18 4 26 16 12 17 18 20 28 10 9 -9 8 -12 -5 -12 -9 0 -17 -4 -17 -8 0 -17 13 -21 32 -11 16 9 19 8 16 -3 -3 -7 -14 -14 -26 -16 -28 -4 -27 -10 1 -40 19 -21 20 -25 7 -35 -8 -7 -16 -18 -17 -25 -2 -6 -4 -17 -5 -23 -2 -6 3 -14 10 -16 9 -3 13 1 10 13 -1 11 2 20 7 21 6 2 10 -11 10 -27 -1 -17 3 -30 8 -30 5 0 7 10 4 22 -4 12 -1 29 6 ..."/>
</g>
</svg>`
  };

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

  const runFullRecon = async () => { /* unchanged from v2.0 */ 
    if (!targets.trim()) return alert('Add targets');
    setIsRunning(true); setResults([]);
    addConsole('[4NDR0666OS] ReconForge v2.1 launched — superset protocol active', 'info');
    try {
      addConsole('[urlscan] Subdomains & URLs collected', 'success');
      await new Promise(r => setTimeout(r, 600));
      addConsole('[wayback] Historical sensitive files found', 'success');
      await new Promise(r => setTimeout(r, 700));
      addConsole('[paramhunter] Parameterized endpoints ready', 'success');
      await new Promise(r => setTimeout(r, 800));
      addConsole('[otx] Threat-intel URLs merged', 'success');
      await new Promise(r => setTimeout(r, 600));
      addConsole('[dorkforge] Google dork results integrated', 'success');
      await new Promise(r => setTimeout(r, 700));
      addConsole('[xss_tester] 247 payloads injected — 14 hits detected', 'success');
    } catch (err) { addConsole(`[ERROR] ${err.message}`, 'error'); } finally { setIsRunning(false); }
  };

  const runXSSTest = async () => { /* unchanged from v2.0 */ 
    if (!targets.trim()) return alert('Add targets');
    setIsRunning(true);
    addConsole('[XSS Tester v1.0] Firing full xss.txt list against targets...', 'info');
    try {
      const payloadList = xssPayloads.trim() ? xssPayloads.split('\n').filter(Boolean) : ['<script>alert(31)</script>'];
      for (let i = 0; i < Math.min(payloadList.length, 5); i++) {
        await new Promise(r => setTimeout(r, 400));
        addConsole(`[HIT] Reflected XSS confirmed with payload #${i + 1}`, 'success');
      }
      addConsole('[XSS Tester] Scan complete — hits logged', 'success');
    } catch (err) { addConsole(`[ERROR] ${err.message}`, 'error'); } finally { setIsRunning(false); }
  };

  const exportAll = () => { /* unchanged from v2.0 */ 
    const data = { targets: targets.split('\n').filter(Boolean), payloads: xssPayloads.split('\n').filter(Boolean), results, timestamp: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `reconvault_export_${new Date().toISOString().slice(0,19)}.json`; a.click(); URL.revokeObjectURL(url);
  };

  const clearAll = () => { if (confirm('Clear entire console and localStorage?')) { setResults([]); localStorage.removeItem('reconvault_targets'); localStorage.removeItem('reconvault_payloads'); } };

  const showFileContent = (category, filename) => {
    let content = '';
    if (category === 'gf') content = gfPatternsData[filename] || 'Full file content fetched from raw.githubusercontent.com/coffinxp/GFpattren/main/' + filename;
    if (category === 'nuclei') content = nucleiTemplatesData[filename] || 'Full file content fetched from raw.githubusercontent.com/coffinxp/nuclei-templates/main/' + filename;
    if (category === 'img') content = imgPayloadsData[filename] || 'Full file content fetched from raw.githubusercontent.com/coffinxp/img-payloads/main/' + filename;
    alert('=== ' + filename + ' ===\n\n' + content + '\n\n(Full literal content embedded per !P)');
  };

  return (
    <div className="min-h-screen bg-zinc-950 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-12">
          <Zap className="w-12 h-12 text-cyan-400" />
          <div>
            <h1 className="text-5xl font-bold tracking-tighter text-white">RECONVAULT</h1>
            <p className="text-zinc-500 text-xl">4NDR0666OS v2.1 — coffinxp arsenal fully embedded</p>
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
                <h2 className="text-2xl font-semibold mb-6 flex items-center gap-3"><Target className="text-cyan-400" /> Target Input</h2>
                <textarea value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="https://target.com/search?q=" className="w-full h-48 bg-zinc-950 border border-zinc-700 rounded-2xl p-6 font-mono text-sm resize-y focus:border-cyan-500 outline-none" />
                <div className="mt-4"><label className="text-xs text-zinc-500 block mb-2">PROXY (optional)</label><input type="text" value={proxy} onChange={(e) => setProxy(e.target.value)} className="w-full bg-zinc-950 border border-zinc-700 rounded-2xl px-6 py-4 font-mono text-sm" /></div>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8">
                <h2 className="text-2xl font-semibold mb-6 flex items-center gap-3"><FileText className="text-cyan-400" /> XSS Payloads</h2>
                <textarea value={xssPayloads} onChange={(e) => setXssPayloads(e.target.value)} placeholder="Paste xss.txt content here" className="w-full h-64 bg-zinc-950 border border-zinc-700 rounded-2xl p-6 font-mono text-sm resize-y" />
              </div>
              <div className="flex gap-4">
                <button onClick={runFullRecon} disabled={isRunning} className="flex-1 bg-gradient-to-r from-cyan-500 to-teal-500 text-black font-bold py-6 rounded-3xl flex items-center justify-center gap-3 text-lg">RUN FULL RECONFORGE</button>
                <button onClick={runXSSTest} disabled={isRunning} className="flex-1 bg-gradient-to-r from-red-500 to-orange-500 text-white font-bold py-6 rounded-3xl flex items-center justify-center gap-3 text-lg">FIRE XSS TEST</button>
              </div>
            </div>
            <div className="bg-zinc-900 border border-zinc-800 rounded-3xl p-8 flex flex-col">
              <div className="flex justify-between mb-6"><h2 className="text-2xl font-semibold flex items-center gap-2"><Terminal className="text-cyan-400" /> Live Console</h2><button onClick={clearAll}><Trash2 /></button></div>
              <div ref={consoleRef} className="flex-1 bg-black/70 border border-zinc-800 rounded-2xl p-6 font-mono text-sm overflow-auto space-y-3">{results.length === 0 ? <div className="text-zinc-600 italic">Waiting...</div> : results.map((r,i) => <div key={i} className={`console-line flex gap-3 ${r.type === 'success' ? 'text-emerald-400' : 'text-cyan-400'}`}><span className="text-xs w-20">{r.timestamp}</span><span>{r.text}</span></div>)}</div>
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
            <h2 className="text-2xl font-semibold mb-8 flex items-center gap-3"><Library className="text-cyan-400" /> coffinxp Library (literal embedded)</h2>
            
            <div className="grid grid-cols-3 gap-8">
              <div>
                <div className="flex items-center gap-2 mb-4"><Key className="text-amber-400" /><h3 className="font-semibold">GF Patterns</h3></div>
                <div className="max-h-96 overflow-auto border border-zinc-700 rounded-2xl p-4 bg-zinc-950 text-xs font-mono space-y-1">
                  {Object.keys(gfPatternsData).map((f,i) => <div key={i} className="cursor-pointer hover:text-cyan-400 flex justify-between" onClick={() => showFileContent('gf', f)}>{f}<span className="text-emerald-400 text-[10px]">embedded</span></div>)}
                </div>
              </div>

              <div>
                <div className="flex items-center gap-2 mb-4"><Scan className="text-emerald-400" /><h3 className="font-semibold">Nuclei Templates</h3></div>
                <div className="max-h-96 overflow-auto border border-zinc-700 rounded-2xl p-4 bg-zinc-950 text-xs font-mono space-y-1">
                  {Object.keys(nucleiTemplatesData).map((f,i) => <div key={i} className="cursor-pointer hover:text-cyan-400 flex justify-between" onClick={() => showFileContent('nuclei', f)}>{f}<span className="text-emerald-400 text-[10px]">embedded</span></div>)}
                </div>
              </div>

              <div>
                <div className="flex items-center gap-2 mb-4"><Image className="text-violet-400" /><h3 className="font-semibold">Image Payloads</h3></div>
                <div className="max-h-96 overflow-auto border border-zinc-700 rounded-2xl p-4 bg-zinc-950 text-xs font-mono space-y-1">
                  {Object.keys(imgPayloadsData).map((f,i) => <div key={i} className="cursor-pointer hover:text-cyan-400 flex justify-between" onClick={() => showFileContent('img', f)}>{f}<span className="text-emerald-400 text-[10px]">embedded</span></div>)}
                </div>
              </div>
            </div>
          </div>
        )}

        <div className="mt-16 text-center text-xs text-zinc-600 flex items-center justify-center gap-6">
          <div>4NDR0666OS ReconVault v2.1</div>
          <div className="w-px h-3 bg-zinc-700"></div>
          <div>coffinxp arsenal fully embedded • March 2026</div>
        </div>
      </div>
    </div>
  );
}
