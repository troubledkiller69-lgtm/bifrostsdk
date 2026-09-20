import React, { useState, useEffect, useRef, useMemo } from 'react';
import AddressExplorer from './AddressExplorer';

function fmtAddr(addr) {
  return '0x' + addr.toString(16).toUpperCase();
}

function unwrapPayload(res) {
  return res && res.type === 'result' ? res.data : res;
}

function baseName(p) {
  return String(p || '').split(/[\\/]/).pop() || p || '';
}

// Tokenize decompiled C and wrap known function identifiers + hex
// constants that resolve to functions in clickable spans. Non-matching
// text stays plain — the mono block keeps its copyable shape.
function CodeBlock({ code, symbols, addrName, onJump }) {
  const hasLinks = symbols && addrName && (Object.keys(symbols).length > 0);
  if (!hasLinks) return <pre className="code-view">{code}</pre>;

  const tokenRe = /[A-Za-z_$][A-Za-z0-9_$.~]*|0x[0-9a-fA-F]+/g;
  const lines = code.split('\n');
  return (
    <div className="code-view">
      {lines.map((line, i) => {
        const parts = [];
        let last = 0;
        let m;
        tokenRe.lastIndex = 0;
        while ((m = tokenRe.exec(line)) !== null) {
          const token = m[0];
          let target = null;
          if (symbols[token] !== undefined) target = symbols[token];
          else if (/^0x/i.test(token)) {
            const n = parseInt(token, 16);
            if (addrName[n]) target = n;
          }
          if (target) {
            if (m.index > last) parts.push(line.slice(last, m.index));
            parts.push(
              <button
                key={`${i}-${m.index}`}
                className="code-link"
                title={`Jump to ${addrName[target] || token}`}
                onClick={(e) => { e.stopPropagation(); onJump(token, target); }}
              >
                {token}
              </button>
            );
            last = m.index + token.length;
          }
        }
        if (last < line.length) parts.push(line.slice(last));
        return <div key={i} className="code-line">{parts}</div>;
      })}
    </div>
  );
}

export default function AnalyzerPage() {
  const [probe, setProbe] = useState(null);
  const [probeError, setProbeError] = useState('');
  const [sourceType, setSourceType] = useState('file');
  const [filePath, setFilePath] = useState('');
  const [modulePid, setModulePid] = useState('');
  const [moduleName, setModuleName] = useState('');
  const [running, setRunning] = useState(null); // 'analyze' | 'analyze_export' | null
  const [progress, setProgress] = useState({ stage: '', pct: 0 });
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [exportInfo, setExportInfo] = useState(null);
  const [exportLimit, setExportLimit] = useState(500);
  const [filter, setFilter] = useState('');
  const [activeAddr, setActiveAddr] = useState(null);
  const [decompiling, setDecompiling] = useState(false);
  const [decompiled, setDecompiled] = useState(null);
  const [codeError, setCodeError] = useState('');
  const [decompTarget, setDecompTarget] = useState(null); // {addr, name} from list OR identifier link
  const [symbols, setSymbols] = useState({}); // name -> addr (full binary)
  const [strings, setStrings] = useState(null); // strings table rows
  const [stringsLoading, setStringsLoading] = useState(false);
  const [stringsError, setStringsError] = useState('');
  const [stringFilter, setStringFilter] = useState('');
  const [explorerTarget, setExplorerTarget] = useState(null); // {addr, ts}
  const [engineChoice, setEngineChoice] = useState('auto'); // auto | rizin | ida | iced

  const consoleEndRef = useRef(null);
  const api = window.bifrost;

  useEffect(() => { window.__bifrost_analyzing = running != null; }, [running]);

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    if (!api) { setProbeError('Bridge unavailable (not running in Electron)'); return; }
    let alive = true;
    api.analyzeProbe()
      .then((r) => {
        if (!alive) return;
        const payload = unwrapPayload(r);
        if (payload?.error) { setProbeError(payload.error); return; }
        setProbe(payload);
      })
      .catch((e) => { if (alive) setProbeError(e?.message || String(e)); });
    return () => { alive = false; };
  }, [api]);

  useEffect(() => {
    if (!api) return;

    const unsubLog = api.onAnalyzeLog((data) => {
      if (!data || data.level === 'error') return;
      const text = typeof data === 'string' ? data : data.text;
      setLogs(prev => [...prev.slice(-300), {
        time: new Date().toLocaleTimeString(),
        text,
        level: data.level || 'info'
      }]);
    });

    const unsubProgress = api.onAnalyzeProgress((data) => {
      if (data?.type === 'progress') {
        setProgress({ stage: data.stage, pct: data.pct });
      }
    });

    const unsubError = api.onAnalyzeError((data) => {
      const text = data?.text || (typeof data === 'string' ? data : 'Analysis error');
      setLogs(prev => [...prev.slice(-300), {
        time: new Date().toLocaleTimeString(),
        text: `[ERROR] ${text}`,
        level: 'error'
      }]);
      setRunning(null);
    });

    const unsubComplete = api.onAnalyzeComplete((data) => {
      if (data?.type === 'error') {
        setLogs(prev => [...prev.slice(-300), {
          time: new Date().toLocaleTimeString(),
          text: `[ERROR] ${data.text || 'Analysis failed'}`,
          level: 'error'
        }]);
        setRunning(null);
        return;
      }
      if (data?.type !== 'result' || !data.data) return;
      const payload = data.data;
      setRunning(null);
      setProgress({ stage: '', pct: 0 });

      if (payload.error) {
        const level = payload.code === 'CANCELLED' ? 'warn' : 'error';
        setLogs(prev => [...prev.slice(-300), {
          time: new Date().toLocaleTimeString(),
          text: payload.code === 'CANCELLED' ? 'Operation cancelled' : `[ERROR] ${payload.error}`,
          level
        }]);
        return;
      }

      if (data.stream === 'analyze_export' || payload.count !== undefined) {
        setExportInfo(payload);
        setLogs(prev => [...prev.slice(-300), {
          time: new Date().toLocaleTimeString(),
          text: `Export complete — ${payload.count} files in ${payload.dir}`,
          level: 'success'
        }]);
        return;
      }

      setResult(payload);
      setActiveAddr(null);
      setDecompiled(null);
      setCodeError('');
      setDecompTarget(null);
      setSymbols({});
      (payload.warnings || []).forEach(w => {
        setLogs(prev => [...prev.slice(-300), {
          time: new Date().toLocaleTimeString(),
          text: w,
          level: 'warn'
        }]);
      });
      setLogs(prev => [...prev.slice(-300), {
        time: new Date().toLocaleTimeString(),
        text: `Analysis complete — ${payload.functions ? payload.functions.length : 0} functions listed`,
        level: 'success'
      }]);
      if (payload.session) refreshSymbolsAndStrings();
    });

    return () => {
      unsubLog && unsubLog();
      unsubProgress && unsubProgress();
      unsubError && unsubError();
      unsubComplete && unsubComplete();
    };
  }, [api]);

  const addLog = (text, level = 'info') => {
    setLogs(prev => [...prev.slice(-300), { time: new Date().toLocaleTimeString(), text, level }]);
  };

  const fetchStrings = (minLen = 6) => {
    if (!api) return;
    setStringsLoading(true);
    setStringsError('');
    api.analyzerStrings(minLen, 2000)
      .then((r) => {
        const p = unwrapPayload(r);
        if (p?.error) { setStringsError(p.code ? `${p.code}: ${p.error}` : p.error); setStrings(null); }
        else setStrings(Array.isArray(p?.strings) ? p.strings : []);
      })
      .catch((e) => { setStringsError(e?.message || String(e)); setStrings(null); })
      .finally(() => setStringsLoading(false));
  };

  const refreshSymbolsAndStrings = () => {
    if (!api) return;
    api.analyzerSymbols()
      .then((r) => {
        const p = unwrapPayload(r);
        if (p && !p.error && p.symbols) setSymbols(p.symbols);
      })
      .catch(() => {});
    fetchStrings();
  };

  const handleBrowse = async () => {
    if (!api) return;
    const res = await api.selectFilePath();
    if (res?.path) {
      setFilePath(res.path);
      setSourceType('file');
    }
  };

  const handleAnalyze = () => {
    if (running || !api) return;
    let source;
    if (sourceType === 'module') {
      const pid = parseInt(modulePid, 10);
      if (!pid || pid <= 0) { addLog('Invalid PID', 'error'); return; }
      if (!moduleName.trim()) { addLog('Missing module name (exe/dll)', 'error'); return; }
      source = { type: 'module', pid, module: moduleName.trim() };
    } else {
      if (!filePath) { addLog('Choose a binary first', 'error'); return; }
      source = { type: 'file', path: filePath };
    }
    if (engineChoice !== 'auto') source.engine = engineChoice;
    setLogs([]);
    setResult(null);
    setExportInfo(null);
    setDecompiled(null);
    setCodeError('');
    setActiveAddr(null);
    setDecompTarget(null);
    setSymbols({});
    setStrings(null);
    setStringsError('');
    setProgress({ stage: 'Starting', pct: 0 });
    setRunning('analyze');
    addLog(`Analyzing ${sourceType === 'module' ? `${moduleName.trim()} (PID ${parseInt(modulePid, 10)})` : filePath}${engineChoice !== 'auto' ? ` [${engineChoice}]` : ''}`);
    api.startAnalyze({ source, limit: 400 });
  };

  const handleCancelAnalyze = () => {
    if (!api || !running) return;
    setRunning(null);
    setProgress({ stage: 'Cancelling…', pct: progress.pct });
    addLog('Cancellation requested — analyze will stop at the next checkpoint (cooperative, not instant)', 'warn');
    if (running === 'analyze_export') api.stopAnalyzeExport();
    else api.stopAnalyze();
    // watchdog: if backend doesn't ACK in 5s, nudge
    setTimeout(() => { if (window.bifrost?.toast) window.bifrost.toast('If cancel stalls, backend thread dump in Diagnostics will show where it is hung', 'info'); }, 5000);
  };

  const handleExport = () => {
    if (!api || running || !result?.session || decompiling) return;
    const lim = Math.min(2000, Math.max(1, parseInt(exportLimit, 10) || 500));
    setExportInfo(null);
    setProgress({ stage: 'Exporting', pct: 0 });
    setRunning('analyze_export');
    addLog(`Exporting top ${lim} functions...`);
    api.startAnalyzeExport({ limit: lim });
  };

  const doDecompile = async (addr, name) => {
    if (!api || decompiling) return;
    setActiveAddr(addr);
    setDecompTarget({ addr, name: name || null });
    setCodeError('');
    if (!result?.session) {
      setDecompiled(null);
      setCodeError('No decompiler session open — this binary was analyzed with the iced-x86 fallback. Run tools/provision_rizin.ps1 once and re-analyze for C output.');
      return;
    }
    setDecompiling(true);
    setDecompiled(null);
    try {
      const r = await api.decompileFn(addr);
      const payload = unwrapPayload(r);
      if (payload?.error) {
        setCodeError(payload.code ? `${payload.code}: ${payload.error}` : payload.error);
      } else if (payload && payload.code !== undefined) {
        setDecompiled(payload);
      }
    } catch (e) {
      setCodeError(e?.message || String(e));
    }
    setDecompiling(false);
  };

  const handleRowClick = (fn) => {
    doDecompile(fn.addr, fn.name);
  };

  // Identifier (or hex-constant) link inside a decompiled body.
  const jumpToSymbol = (token, addr) => {
    const name = addrName[addr] || (symbols[token] !== undefined ? token : null);
    doDecompile(addr, name);
  };

  const rizinOk = !!(probe?.rizin?.available && probe?.rizin?.decompiler);
  const rizinPresent = !!probe?.rizin?.available;
  const functions = result?.functions || [];
  const addrName = useMemo(() => {
    const m = {};
    Object.keys(symbols).forEach((n) => { m[symbols[n]] = n; });
    return m;
  }, [symbols]);
  const q = filter.trim().toLowerCase();
  const visibleFns = q
    ? functions.filter(fn => {
        if ((fn.name || '').toLowerCase().includes(q)) return true;
        return fmtAddr(fn.addr).toLowerCase().includes(q);
      })
    : functions;
  const activeFn = functions.find(fn => fn.addr === activeAddr) || null;

  return (
    <>
      <div className="page-header">
        <div className="page-title">Analyzer</div>
        <div className="page-subtitle">Open a binary or running module, map functions, decompile bodies via rizin-ghidra</div>
      </div>

      <div className="page-grid">
        <div className="page-config">
          <div className="page-config-card">
            <div className="page-config-title">Decompiler Engines</div>
            {probeError ? (
              <div style={{ fontSize: 12, color: 'var(--error)' }}>{probeError}</div>
            ) : !probe ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Checking engine availability...</div>
            ) : (
              <>
                {/* Deck preset — rizin | ida | iced, lime edge on selected */}
                <div role="radiogroup" aria-label="Engine" style={{ display: 'flex', gap: 6, background: '#050507', border: '1px solid rgba(0,0,0,0.6)', borderRadius: 3, padding: 4, boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6), inset -1px -1px 0 rgba(255,255,255,0.04)', marginBottom: 10 }}>
                  {[
                    { id: 'auto', label: 'Auto', hint: 'best' },
                    { id: 'rizin', label: 'Rizin', hint: probe?.rizin?.available ? (probe?.rizin?.decompiler ? '●' : 'no ghidra') : 'missing' },
                    { id: 'ida', label: 'IDA', hint: probe?.ida?.available ? '●' : 'no exe' },
                    { id: 'iced', label: 'Iced', hint: 'fallback' },
                  ].map(opt => {
                    const active = engineChoice === opt.id;
                    const disabled = (opt.id === 'ida' && !probe?.ida?.available) || (opt.id === 'rizin' && !probe?.rizin?.available);
                    return (
                      <button key={opt.id} role="radio" aria-checked={active} disabled={disabled}
                        onClick={() => setEngineChoice(opt.id)}
                        style={{
                          flex: 1, padding: '6px 6px', borderRadius: 3,
                          border: active ? '1px solid rgba(126,255,63,0.42)' : '1px solid transparent',
                          borderTopColor: active ? 'rgba(126,255,63,0.55)' : 'transparent',
                          background: active ? '#0a0a0c' : 'transparent',
                          color: disabled ? 'var(--text-ghost)' : active ? '#7EFF3F' : 'var(--text-muted)',
                          fontSize: 11, fontWeight: 700, fontFamily: 'var(--font-display)', letterSpacing: '0.08em', textTransform: 'uppercase',
                          cursor: disabled ? 'not-allowed' : 'pointer',
                          boxShadow: active ? 'inset 0 1px 0 rgba(255,255,255,0.06), 0 0 8px rgba(126,255,63,0.14)' : 'none',
                          textShadow: active ? '0 0 6px rgba(126,255,63,0.28)' : 'none', opacity: disabled ? 0.45 : 1
                        }}>
                        {opt.label}<span style={{ display: 'block', fontSize: 9, fontWeight: 500, letterSpacing: '0.04em', opacity: 0.65, marginTop: 1 }}>{opt.hint}</span>
                      </button>
                    );
                  })}
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                  <span className="engine-card-tag" style={{ background: rizinOk ? 'rgba(126,255,63,0.12)' : 'var(--warn-soft)', color: rizinOk ? '#7EFF3F' : 'var(--warn)', border: rizinOk ? '1px solid rgba(126,255,63,0.22)' : '1px solid transparent', textShadow: rizinOk ? '0 0 6px rgba(126,255,63,0.28)' : 'none' }}>{rizinOk ? 'rizin-ghidra' : 'rizin — no ghidra'}</span>
                  <span className="engine-card-tag" style={{ background: probe?.ida?.available ? 'rgba(126,255,63,0.12)' : 'var(--border)', color: probe?.ida?.available ? '#7EFF3F' : 'var(--text-ghost)' }}>{probe?.ida?.available ? `ida ${probe.ida.version || ''}`.trim() : 'ida — not found'}</span>
                  <span className="engine-card-tag" style={{ background: 'var(--border)', color: 'var(--text-muted)' }}>iced-x86</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  {engineChoice === 'ida' && !probe?.ida?.available && <span style={{ color: 'var(--error)' }}>IDA exe not found — place your licensed IDA in Downloads\IDA_Test\IDA Professional 9.1\idat.exe or C:\Program Files\IDA* — </span>}
                  {engineChoice === 'rizin' && !probe?.rizin?.available && <span style={{ color: 'var(--error)' }}>Rizin not provisioned — </span>}
                  Auto picks rizin-ghidra first, then IDA {probe?.ida?.available ? '(found)' : '(provide idat.exe)'}, then iced. Provision rizin via <span className="log-line dim">tools/provision_rizin.ps1</span> · IDA via <span className="log-line dim">tools/provision_ida.ps1</span>
                </div>
              </>
            )}
          </div>

          <div className="page-config-card">
            <div className="page-config-title">Source</div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <button
                className={`btn ${sourceType === 'file' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1, padding: '8px 0', fontSize: 11 }}
                onClick={() => setSourceType('file')}
              >
                Binary file
              </button>
              <button
                className={`btn ${sourceType === 'module' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1, padding: '8px 0', fontSize: 11 }}
                onClick={() => setSourceType('module')}
              >
                Running module
              </button>
            </div>

            {sourceType === 'file' ? (
              <>
                <button className="btn" style={{ width: '100%', padding: '10px' }} onClick={handleBrowse}>
                  {filePath ? 'Choose different binary...' : 'Open binary...'}
                </button>
                {filePath ? (
                  <div
                    className="log-line dim"
                    style={{ marginTop: 10, fontSize: 11 }}
                    title={filePath}
                  >
                    {filePath}
                  </div>
                ) : (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10, lineHeight: 1.5 }}>
                    Any PE/ELF/raw on-disk file. Decompilation needs a rizin-provisioned engine.
                  </div>
                )}
              </>
            ) : (
              <>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>
                    PID
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    placeholder="1234"
                    value={modulePid}
                    onChange={(e) => setModulePid(e.target.value.replace(/[^0-9]/g, ''))}
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>
                    Module
                  </label>
                  <input
                    type="text"
                    className="input-field"
                    placeholder="game.exe"
                    value={moduleName}
                    onChange={(e) => setModuleName(e.target.value)}
                  />
                </div>
                <div style={{ fontSize: 11, color: 'var(--warn)', marginTop: 10, lineHeight: 1.5 }}>
                  Module source requires a running target. The module image is dumped
                  (hijack/direct attach — never a kernel driver), then analyzed on disk.
                </div>
              </>
            )}
          </div>

          <div className="page-config-card">
            <div className="page-config-title">Actions</div>
            <button
              className="btn btn-primary"
              onClick={handleAnalyze}
              disabled={!!running || decompiling}
              style={{ width: '100%', padding: '12px' }}
            >
              {running === 'analyze' ? 'ANALYZING...' : 'ANALYZE'}
            </button>
            {running === 'analyze' && (
              <button
                className="btn btn-danger"
                onClick={handleCancelAnalyze}
                style={{ width: '100%', padding: '10px', marginTop: 10 }}
              >
                Cancel
              </button>
            )}
            <div style={{ height: 1, background: 'var(--border)', margin: '16px 0' }} />
            <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>
              Export Top N
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                type="number"
                className="input-field"
                style={{ width: 110 }}
                min="1"
                max="2000"
                value={exportLimit}
                onChange={(e) => setExportLimit(e.target.value)}
              />
              <button
                className="btn btn-secondary"
                onClick={handleExport}
                disabled={!!running || decompiling || !result?.session}
                style={{ flex: 1 }}
                title={!result?.session ? 'Analyze a binary with rizin provisioned first' : 'Batch-decompile the largest functions to .c files'}
              >
                {running === 'analyze_export' ? 'EXPORTING...' : 'EXPORT'}
              </button>
            </div>
            {running === 'analyze_export' && (
              <button
                className="btn btn-danger"
                onClick={handleCancelAnalyze}
                style={{ width: '100%', padding: '10px', marginTop: 10 }}
              >
                Cancel Export
              </button>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {running && (
            <div className="progress-bar-container" style={{ marginBottom: 0 }}>
              <div className="progress-label">
                <span className="stage">
                  {running === 'analyze_export' ? `Export: ${progress.stage}` : progress.stage}
                </span>
                <span className="pct">{progress.pct}%</span>
              </div>
              <div className="progress-track" role="progressbar" aria-valuenow={progress.pct} aria-valuemin={0} aria-valuemax={100} aria-label={running === 'analyze_export' ? 'Export progress' : 'Analyze progress'}>
                <div
                  className={`progress-fill ${progress.pct >= 100 ? 'complete' : ''}`}
                  style={{ width: `${progress.pct}%` }}
                />
              </div>
            </div>
          )}

          <div className="page-console">
            <div className="page-console-header">
              <span className="page-console-title">analyzer.log</span>
            </div>
            <div className="page-console-body">
              {logs.length === 0 ? (
                <div className="log-line dim">Awaiting analysis job...</div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10 }}>
                    <span style={{ color: 'var(--text-ghost)', flexShrink: 0 }}>[{log.time}]</span>
                    <span className={`log-line ${log.level}`}>{log.text}</span>
                  </div>
                ))
              )}
              <div ref={consoleEndRef} />
            </div>
          </div>

          {result && (
            <div className="stats-row" style={{ marginBottom: 0 }}>
              <div className="stat-card">
                <div className="stat-label">Engine</div>
                <div className="stat-value" style={{ fontSize: 15, color: result.engine === 'rizin-ghidra' ? 'var(--success)' : 'var(--warn)' }}>
                  {result.engine || '-'}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Source</div>
                <div className="stat-value" style={{ fontSize: 15, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={result.file}>
                  {baseName(result.file) || '-'}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Functions</div>
                <div className="stat-value" style={{ fontSize: 15 }}>
                  {result.total_functions != null ? result.total_functions.toLocaleString() : functions.length.toLocaleString()}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Session</div>
                <div className="stat-value" style={{ fontSize: 15, color: result.session ? 'var(--success)' : 'var(--text-ghost)' }}>
                  {result.session ? 'Open' : 'None'}
                </div>
              </div>
            </div>
          )}

          {result && result.decompiler === false && (
            <div style={{
              padding: '10px 14px',
              background: 'var(--warn-soft)',
              border: '1px solid var(--warn)',
              borderRadius: 8,
              color: 'var(--warn)',
              fontSize: 12
            }}>
              {result.session
                ? 'rz-ghidra is not available — decompiled bodies come back as comment headers or fail. Run tools/provision_rizin.ps1 once.'
                : 'iced-x86 engine is disassembly-only — function bodies are unavailable. Run tools/provision_rizin.ps1 once and re-analyze for decompiled C output.'}
            </div>
          )}

          {exportInfo && (
            <div className="page-config-card" style={{ padding: 14 }}>
              <div className="page-config-title" style={{ marginBottom: 8 }}>
                Export — {exportInfo.count} files in {exportInfo.dir}
              </div>
              <div className="log-console" style={{ maxHeight: 180 }}>
                {(exportInfo.files || []).map((f, i) => (
                  <p key={i} className="log-line dim" style={{ fontSize: 11 }} title={f.path}>
                    {fmtAddr(f.addr)}  {f.name}
                  </p>
                ))}
              </div>
            </div>
          )}

          {(result || true) && (
            <div className="analyzer-deck">
              {/* LEFT — function tree */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>
                {result ? (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--text-secondary)', fontFamily: 'var(--font-display)' }}>Functions</span>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{visibleFns.length} / {functions.length}</span>
                      <span style={{ flex: 1 }} />
                      {decompiling && <span style={{ fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>● DECOMPILING</span>}
                    </div>
                    <div style={{ marginBottom: 8 }}>
                      <input type="text" className="input-field" style={{ width: '100%', padding: '7px 10px', fontSize: 12, background: '#050507', borderColor: 'rgba(0,0,0,0.6)', boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6)' }} placeholder="Filter by name or address" value={filter} onChange={(e) => setFilter(e.target.value)} />
                    </div>
                    <div className="process-table-wrapper" style={{ maxHeight: '56vh', minHeight: 240 }}>
                      <table className="process-table">
                        <thead>
                          <tr>
                            <th style={{ width: 120 }}>Address</th>
                            <th>Name</th>
                            <th style={{ width: 70 }}>Size</th>
                          </tr>
                        </thead>
                        <tbody>
                          {decompiling ? (
                            Array.from({ length: 4 }).map((_, i) => (
                              <tr key={`sk-${i}`}><td colSpan="3" style={{ padding: 0, border: 'none' }}><div className="skeleton-row"><div className="skeleton skeleton-cell pid" style={{ width: 90 }} /><div className="skeleton skeleton-cell name" style={{ flex: 1 }} /></div></td></tr>
                            ))
                          ) : visibleFns.map((fn, idx) => (
                            <tr key={idx} tabIndex={0} role="button" aria-selected={fn.addr === activeAddr} className={fn.addr === activeAddr ? 'selected' : ''} onClick={() => handleRowClick(fn)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleRowClick(fn); } }}>
                              <td style={{ color: 'var(--accent)', fontSize: 11 }}>{fmtAddr(fn.addr)}</td>
                              <td className="name" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 140 }} title={fn.name}>{fn.name || '-'}</td>
                              <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>{fn.size != null ? fn.size.toLocaleString() : '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {visibleFns.length === 0 && !decompiling && (
                        <div className="log-line dim" style={{ padding: 12, fontSize: 11, textAlign: 'center' }}>{result ? 'No functions match filter' : 'Analyze a binary to populate'}</div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="page-config-card" style={{ padding: 16, textAlign: 'center' }}>
                    <div className="log-line dim" style={{ fontSize: 12 }}>No analysis yet</div>
                    <div style={{ fontSize: 11, color: 'var(--text-ghost)', marginTop: 6, fontFamily: 'var(--font-mono)' }}>Pick a binary → Analyze → functions appear here</div>
                  </div>
                )}
              </div>

              {/* CENTER — decompile */}
              <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(activeFn || decompTarget) ? (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--accent)', background: '#050507', border: '1px solid rgba(0,0,0,0.6)', borderRadius: 3, padding: '4px 8px', boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6)' }}>{fmtAddr((decompTarget || activeFn).addr)}</span>
                      <span className="name" style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{(decompTarget || activeFn).name || ''}</span>
                      <div style={{ flex: 1 }} />
                      <button className="btn" style={{ padding: '4px 8px', fontSize: 10 }} onClick={() => { if (decompiled?.code && navigator.clipboard) navigator.clipboard.writeText(decompiled.code).then(()=>window.bifrost?.toast && window.bifrost.toast('Copied','success')); }} disabled={!decompiled?.code}>Copy</button>
                      {decompiling && <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>decompiling…</span>}
                    </div>
                    {decompiling ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: '8px 0' }}>{Array.from({ length: 5 }).map((_, i) => (<div key={i} className="skeleton-row" style={{ padding: '6px 12px' }}><div className="skeleton skeleton-cell" style={{ width: `${60 + i * 7}%`, height: 10 }} /></div>))}</div>
                    ) : codeError ? (
                      <div className="log-console" style={{ maxHeight: 420, borderColor: 'var(--error)' }}><p className="log-line error">{codeError}</p></div>
                    ) : decompiled ? (
                      <div style={{ maxHeight: '56vh', overflow: 'auto' }}><CodeBlock code={decompiled.code} symbols={symbols} addrName={addrName} onJump={jumpToSymbol} /></div>
                    ) : (
                      <div className="empty-state" style={{ padding: 20 }}><div className="empty-title">Pick a function</div><p className="empty-hint">Click a row on the left or a highlighted identifier in the body.</p></div>
                    )}
                  </div>
                ) : (
                  <div className="page-config-card" style={{ padding: 24, textAlign: 'center', minHeight: 260, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <div style={{ width: 3, height: 18, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.35)', marginBottom: 12 }} />
                    <div style={{ fontFamily: 'var(--font-display)', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', fontSize: 13, color: 'var(--text-secondary)' }}>Decompile</div>
                    <div style={{ fontSize: 11, color: 'var(--text-ghost)', marginTop: 6, fontFamily: 'var(--font-mono)', maxWidth: 320 }}>Select a function from the left pane. Identifiers and 0x… constants that resolve to symbols are clickable → jump.</div>
                  </div>
                )}
              </div>

              {/* RIGHT — strings + explorer stack */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>
                {result?.session ? (
                  <div className="page-config-card" style={{ padding: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                      <span className="page-config-title" style={{ marginBottom: 0, fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Strings</span>
                      {strings && !stringsLoading && <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{strings.length}</span>}
                      <div style={{ flex: 1 }} />
                      <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 10 }} onClick={() => fetchStrings()} disabled={stringsLoading}>{stringsLoading ? 'SCANNING…' : (strings ? 'RESCAN' : 'SCAN')}</button>
                    </div>
                    <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
                      <input type="text" className="input-field" style={{ flex: 1, padding: '6px 8px', fontSize: 11 }} placeholder="Filter strings" value={stringFilter} onChange={(e) => setStringFilter(e.target.value)} />
                    </div>
                    {stringsError ? (<div className="log-line error" style={{ fontSize: 11 }}>{stringsError}</div>) : stringsLoading ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>{Array.from({ length: 3 }).map((_, i) => (<div key={i} className="skeleton-row" style={{ padding: '6px 8px' }}><div className="skeleton skeleton-cell" style={{ width: 70 }} /><div className="skeleton skeleton-cell" style={{ flex: 1 }} /></div>))}</div>
                    ) : !strings ? (<div className="log-line dim" style={{ fontSize: 11 }}>ASCII + UTF-16LE runs → VAs. Click to open in explorer.</div>) : strings.length === 0 ? (<div className="log-line dim" style={{ fontSize: 11 }}>No printable runs.</div>) : (
                      (() => { const q = stringFilter.trim().toLowerCase(); const visible = q ? strings.filter(s => s.text.toLowerCase().includes(q) || fmtAddr(s.addr).toLowerCase().includes(q)) : strings; const slice = visible.slice(0, 120); return (<div className="log-console" style={{ maxHeight: 220, overflow: 'auto', padding: 0 }}>{visible.length === 0 ? (<div className="log-line dim" style={{ padding: 8 }}>No match</div>) : slice.map((s, i) => (<div key={i} className="hex-row" style={{ cursor: 'pointer', padding: '4px 8px' }} title="Open in explorer" onClick={() => setExplorerTarget({ addr: s.addr, ts: Date.now() })}><span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>{fmtAddr(s.addr)}</span><span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 9, padding: '0 6px' }}>{s.enc}</span><span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.text}</span></div>))}{visible.length > 120 && <div className="log-line dim" style={{ padding: '6px 8px', fontSize: 10 }}>… and {visible.length - 120} more — filter to narrow</div>}</div>); })()
                    )}
                  </div>
                ) : (
                  <div className="page-config-card" style={{ padding: 12 }}><div className="log-line dim" style={{ fontSize: 11 }}>{result ? 'Session closed — strings need an open session (rizin/ida).' : 'Run Analyze to unlock strings + explorer.'}</div></div>
                )}
                <AddressExplorer api={api} enabled={!!result} sessionOpen={!!result?.session} jumpTarget={explorerTarget} />
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
