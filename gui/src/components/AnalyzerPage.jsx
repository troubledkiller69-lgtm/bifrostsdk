import React, { useState, useEffect, useRef } from 'react';
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

  const consoleEndRef = useRef(null);
  const api = window.bifrost;

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
    setLogs([]);
    setResult(null);
    setExportInfo(null);
    setDecompiled(null);
    setCodeError('');
    setActiveAddr(null);
    setProgress({ stage: 'Starting', pct: 0 });
    setRunning('analyze');
    addLog(`Analyzing ${sourceType === 'module' ? `${moduleName.trim()} (PID ${parseInt(modulePid, 10)})` : filePath}`);
    api.startAnalyze({ source, limit: 400 });
  };

  const handleCancelAnalyze = () => {
    if (!api || !running) return;
    setRunning(null);
    addLog('Cancellation requested — analyze will stop at the next checkpoint', 'warn');
    if (running === 'analyze_export') api.stopAnalyzeExport();
    else api.stopAnalyze();
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

  const handleRowClick = async (fn) => {
    if (!api || decompiling) return;
    setActiveAddr(fn.addr);
    setCodeError('');
    if (!result?.session) {
      setDecompiled(null);
      setCodeError('No decompiler session open — this binary was analyzed with the iced-x86 fallback. Run tools/provision_rizin.ps1 once and re-analyze for C output.');
      return;
    }
    setDecompiling(true);
    setDecompiled(null);
    try {
      const r = await api.decompileFn(fn.addr);
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

  const rizinOk = !!(probe?.rizin?.available && probe?.rizin?.decompiler);
  const rizinPresent = !!probe?.rizin?.available;
  const functions = result?.functions || [];
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

      <div className="hunter-grid">
        <div className="hunter-config">
          <div className="hunter-config-card">
            <div className="hunter-config-title">Decompiler Engines</div>
            {probeError ? (
              <div style={{ fontSize: 12, color: 'var(--error)' }}>{probeError}</div>
            ) : !probe ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Checking engine availability...</div>
            ) : (
              <>
                <span
                  className="engine-card-tag"
                  style={{
                    background: rizinOk ? 'var(--success-soft)' : 'var(--warn-soft)',
                    color: rizinOk ? 'var(--success)' : 'var(--warn)'
                  }}
                >
                  {rizinOk ? 'rizin-ghidra (Ghidra decompiler)' : 'iced-x86 (fallback)'}
                </span>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 10, lineHeight: 1.6 }}>
                  {rizinOk ? (
                    <>
                      rizin {probe.rizin.version || ''} with rz-ghidra loaded — full C decompilation
                      for function bodies.
                    </>
                  ) : rizinPresent ? (
                    <>
                      rizin is installed but the rz-ghidra plugin is missing. Run
                      <span className="log-line dim"> tools/provision_rizin.ps1 </span>
                      once to enable Ghidra decompilation.
                    </>
                  ) : (
                    <>
                      rizin is not provisioned. Run
                      <span className="log-line dim"> tools/provision_rizin.ps1 </span>
                      once from the SDK root to enable Ghidra decompilation.
                    </>
                  )}
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8, lineHeight: 1.5 }}>
                  Fallback engine: iced-x86 — linear disassembly only, no decompiler.
                </div>
              </>
            )}
          </div>

          <div className="hunter-config-card">
            <div className="hunter-config-title">Source</div>
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

          <div className="hunter-config-card">
            <div className="hunter-config-title">Actions</div>
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
              <div className="progress-track">
                <div
                  className={`progress-fill ${progress.pct >= 100 ? 'complete' : ''}`}
                  style={{ width: `${progress.pct}%` }}
                />
              </div>
            </div>
          )}

          <div className="hunter-console">
            <div className="hunter-console-header">
              <span className="hunter-console-title">analyzer.log</span>
            </div>
            <div className="hunter-console-body">
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
            <div className="hunter-config-card" style={{ padding: 14 }}>
              <div className="hunter-config-title" style={{ marginBottom: 8 }}>
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

          {result && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--text-secondary)' }}>
                  Functions
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {visibleFns.length} / {functions.length}
                </span>
                <div style={{ flex: 1 }} />
                <input
                  type="text"
                  className="input-field"
                  style={{ width: 240, padding: '6px 10px', fontSize: 12 }}
                  placeholder="Filter by name or address"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
              </div>
              <div className="process-table-wrapper" style={{ maxHeight: 420 }}>
                <table className="process-table">
                  <thead>
                    <tr>
                      <th style={{ width: 180 }}>Address</th>
                      <th style={{ width: 120 }}>Size</th>
                      <th>Name</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleFns.map((fn, idx) => (
                      <tr
                        key={idx}
                        className={fn.addr === activeAddr ? 'selected' : ''}
                        onClick={() => handleRowClick(fn)}
                      >
                        <td style={{ color: 'var(--accent)' }}>{fmtAddr(fn.addr)}</td>
                        <td style={{ color: 'var(--text-muted)' }}>{fn.size != null ? fn.size.toLocaleString() : '-'}</td>
                        <td className="name">{fn.name || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {visibleFns.length === 0 && (
                  <div className="log-line dim" style={{ padding: 20, textAlign: 'center' }}>
                    No functions match the filter
                  </div>
                )}
              </div>
            </div>
          )}

              {activeFn && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--accent)' }}>
                      {fmtAddr(activeFn.addr)}
                    </span>
                    <span className="name" style={{ fontSize: 13 }}>{activeFn.name}</span>
                    <div style={{ flex: 1 }} />
                    {decompiling && <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>decompiling...</span>}
                  </div>
                  {codeError ? (
                    <div className="log-console" style={{ maxHeight: 240, borderColor: 'var(--error)' }}>
                      <p className="log-line error">{codeError}</p>
                    </div>
                  ) : decompiled ? (
                    <pre className="code-view">{decompiled.code}</pre>
                  ) : !decompiling && (
                    <div className="empty-state">
                      <div className="empty-title">No function selected</div>
                      <div className="empty-hint">Pick a function from the list to decompile it, or jump to an address below.</div>
                    </div>
                  )}
                </div>
              )}

              <AddressExplorer
                api={api}
                enabled={!!result}
                sessionOpen={!!result?.session}
              />
        </div>
      </div>
    </>
  );
}
