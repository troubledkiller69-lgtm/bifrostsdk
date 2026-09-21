import React, { useState, useEffect, useCallback, useRef, Component, createContext, useContext } from 'react';
import Titlebar from './components/Titlebar';
import Sidebar from './components/Sidebar';

export const ToastContext = createContext(() => {});
export const ConfirmContext = createContext(() => {});

// Error boundary to prevent single-page crashes from taking down the whole app (council T3 fix)
class PageErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 32, color: 'var(--error)', textAlign: 'center' }}>
          <h2 style={{ marginBottom: 12, fontWeight: 600 }}>Page Error</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: 16 }}>
            {this.state.error?.message || 'An unexpected error occurred'}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{
              padding: '8px 20px', background: 'var(--bg-elevated)', color: 'var(--text-primary)',
              border: '1px solid var(--border-hover)', borderRadius: 6, cursor: 'pointer'
            }}
          >
            Try Again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
import DashboardPage from './components/DashboardPage';
import EnginesPage from './components/EnginesPage';
import ProcessesPage from './components/ProcessesPage';
import DumpPage from './components/DumpPage';
import ResultsPage from './components/ResultsPage';
import DiffPage from './components/DiffPage';
import MemoryViewerPage from './components/MemoryViewerPage';
import ACMonitorPage from './components/ACMonitorPage';
import AnalyzerPage from './components/AnalyzerPage';
import DiagnosticsPage from './components/DiagnosticsPage';
import DriverBayPage from './components/DriverBayPage';
import SettingsPage from './components/SettingsPage';
import ConfigEditorPage from './components/ConfigEditorPage';
import CommandPalette from './components/CommandPalette';

// One-time migration: ouroboros_ → bifrost_ prefix (brand consolidation)
if (!localStorage.getItem('bifrost_migrated')) {
  for (const key of Object.keys(localStorage)) {
    if (key.startsWith('ouroboros_')) {
      localStorage.setItem(key.replace('ouroboros_', 'bifrost_'), localStorage.getItem(key));
    }
  }
  localStorage.setItem('bifrost_migrated', '1');
}

function loadSession(key, fallback) {
  try { const v = localStorage.getItem(`bifrost_${key}`); return v ? JSON.parse(v) : fallback; } catch { return fallback; }
}
function saveSession(key, value) {
  localStorage.setItem(`bifrost_${key}`, JSON.stringify(value));
}

// Apply theme before first paint (no flash from the :root default).
{
  const t = loadSession('theme', 'midnight');
  document.documentElement.setAttribute('data-theme',
    ['midnight', 'paper', 'terminal'].includes(t) ? t : 'midnight');
}

export default function App() {
  const [page, setPage] = useState(() => loadSession('page', 'engines'));
  const [stealth, setStealth] = useState(() => {
    const saved = loadSession('stealth', 'auto');
    if (saved === 'extreme') return 'cr3';
    return ['auto', 'direct', 'hijack', 'driver', 'cr3'].includes(saved) ? saved : 'auto';
  });
  const [driverKey, setDriverKey] = useState(() => loadSession('driverKey', null));
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [theme, setTheme] = useState(() => {
    const saved = loadSession('theme', 'midnight');
    return ['midnight', 'paper', 'terminal'].includes(saved) ? saved : 'midnight';
  });

  const [selectedEngine, setSelectedEngine] = useState(() => loadSession('engine', null));
  const [selectedProcess, setSelectedProcess] = useState(() => loadSession('process', null));
  const [dumpResults, setDumpResults] = useState(() => loadSession('dumpResults', null));
  const [logs, setLogs] = useState([]);
  const [dumpProgress, setDumpProgress] = useState({ stage: '', pct: 0, running: false });
  const [bridgeStatus, setBridgeStatus] = useState('unknown'); // 'ok' | 'error' | 'unknown'
  // staleBackend: true when bridge_info either fails or returns an old build
  // missing the current feature flags. Shows a persistent banner so the user
  // knows to restart the Python subprocess.
  const [staleBackend, setStaleBackend] = useState(false);
  const [dumpOptions, setDumpOptions] = useState({ forceDiscovery: true, regenerate: false });
  const [accessInfo, setAccessInfo] = useState(null);
  const [lastDump, setLastDump] = useState(() => loadSession('lastDump', null));
  const [dumpQueue, setDumpQueue] = useState(() => loadSession('dumpQueue', []));
  const dumpQueueRef = useRef([]);
  useEffect(() => { dumpQueueRef.current = dumpQueue; saveSession('dumpQueue', dumpQueue); }, [dumpQueue]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [confirm, setConfirm] = useState({ open: false, title: '', body: '', confirmLabel: 'Confirm', onConfirm: null });

  const api = window.bifrost;

  const toast = useCallback((msg, type = 'success') => {
    const id = Date.now() + Math.random();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 2500);
  }, []);

  const copyWithToast = useCallback(async (text, label = 'Copied to clipboard') => {
    try {
      await navigator.clipboard.writeText(text);
      toast(label, 'success');
    } catch {
      toast('Copy failed', 'error');
    }
  }, [toast]);

  const confirmDestructive = useCallback(({ title, body, confirmLabel = 'Confirm', onConfirm }) => {
    setConfirm({ open: true, title, body, confirmLabel, onConfirm });
  }, []);

  // expose via window globals for non-React consumers — window.bifrost is frozen via contextBridge, so use __bifrost_* helpers
  useEffect(() => {
    try {
      const b = window.bifrost;
      if (b && Object.isExtensible(b)) {
        b.toast = toast;
        b.copyWithToast = copyWithToast;
        b.confirmDestructive = confirmDestructive;
      }
    } catch {}
    window.__bifrost_toast = toast;
    window.__bifrost_copyWithToast = copyWithToast;
    window.__bifrost_confirmDestructive = confirmDestructive;
    // also expose on bifrost via defineProperty fallback if extensible check missed
    try {
      if (window.bifrost) {
        try { Object.defineProperty(window.bifrost, 'toast', { value: toast, writable: true, configurable: true }); } catch {}
        try { Object.defineProperty(window.bifrost, 'copyWithToast', { value: copyWithToast, writable: true, configurable: true }); } catch {}
        try { Object.defineProperty(window.bifrost, 'confirmDestructive', { value: confirmDestructive, writable: true, configurable: true }); } catch {}
      }
    } catch {}
  }, [toast, copyWithToast, confirmDestructive]);

  // Custom event bridge for explicit navigation (Dashboard/EnginesPage CTA)
  useEffect(() => {
    const h = (e) => { if (e?.detail) setPage(e.detail); };
    window.addEventListener('bifrost:navigate', h);
    // expose direct setter for EnginesPage CTA fallback
    window.__bifrost_navigate = (p) => setPage(p);
    return () => {
      window.removeEventListener('bifrost:navigate', h);
      try { delete window.__bifrost_navigate; } catch {}
    };
  }, []);

  // Persist session state
  useEffect(() => { saveSession('page', page); }, [page]);
  useEffect(() => { saveSession('stealth', stealth); }, [stealth]);
  useEffect(() => { saveSession('driverKey', driverKey); }, [driverKey]);
  useEffect(() => {
    saveSession('theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);
  useEffect(() => { saveSession('engine', selectedEngine); }, [selectedEngine]);
  useEffect(() => { saveSession('process', selectedProcess); }, [selectedProcess]);
  useEffect(() => { saveSession('dumpResults', dumpResults); }, [dumpResults]);

  const addLog = useCallback((text, type = 'info') => {
    setLogs(prev => [...prev.slice(-200), { text, type, ts: Date.now() }]);
  }, []);

  // Bridge health check + stale-backend detection.
  // After ping, request bridge_info and check for the current feature flags.
  // If the response is missing or lacks the powershell-fallback flag, the
  // running Python subprocess is from a previous revision — banner up.
  const REQUIRED_BACKEND_FEATURES = ['webhook_powershell_fallback'];
  useEffect(() => {
    if (!api) { setBridgeStatus('error'); return; }
    api.command('ping').then(async (r) => {
      setBridgeStatus(r?.status === 'ok' ? 'ok' : 'error');
      if (r?.status !== 'ok') return;
      try {
        const info = await api.command('bridge_info', {});
        const features = info?.data?.features || {};
        const missing = REQUIRED_BACKEND_FEATURES.filter(f => !features[f]);
        setStaleBackend(missing.length > 0);
      } catch {
        // bridge_info command itself is missing — definitely stale
        setStaleBackend(true);
      }
    }).catch(() => setBridgeStatus('error'));
  }, [api]); // Removed 'page' — ping on every navigation is unnecessary (council T3 fix)

  // Dump event listeners — stabilized hygiene (100-iter-02)
  // Progress and completion are handled by separate channels; results only
  // ever arrive from dump events now that main.js routes by stream tag.
  // lastDumpEventRef feeds the stall watchdog effect below.
  const lastDumpEventRef = useRef(Date.now());
  const stallWarnedRef = useRef(false);
  // Batch queue: runDumpTargetRef lets the dump-complete listener advance
  // the queue without re-subscribing (effect deps stay [api, addLog]).
  const runDumpTargetRef = useRef(null);
  const advanceQueue = useCallback((ok) => {
    const next = dumpQueueRef.current;
    if (!next || next.length === 0) return false;
    const [head, ...rest] = next;
    setDumpQueue(rest);
    addLog(`[QUEUE] ${ok ? 'next' : 'skipping ahead after error'}: ${head.engine} → ${head.name} (PID ${head.pid}) — ${rest.length} left`, ok ? 'info' : 'warn');
    if (runDumpTargetRef.current) runDumpTargetRef.current(head);
    return true;
  }, [addLog]);
  useEffect(() => {
    if (!api) return;

    const unsubs = [];

    const unsubProgress = api.onDumpProgress((msg) => {
      if (msg.type === 'progress') {
        lastDumpEventRef.current = Date.now();
        setDumpProgress({ stage: msg.stage, pct: msg.pct, running: true });
      }
    });
    unsubs.push(unsubProgress);

    const unsubLog = api.onDumpLog((data) => {
      lastDumpEventRef.current = Date.now();
      if (typeof data === 'string') addLog(data, 'info');
      else if (data && data.text) addLog(data.text, data.level || 'info');
    });
    unsubs.push(unsubLog);

    const unsubError = api.onDumpError((data) => {
      lastDumpEventRef.current = Date.now();
      setDumpProgress(p => ({ ...p, running: false }));
    });
    unsubs.push(unsubError);

    const unsubAccess = api.onDumpAccess((msg) => {
      lastDumpEventRef.current = Date.now();
      if (msg?.type === 'access' && msg.data) setAccessInfo(msg.data);
    });
    unsubs.push(unsubAccess);

    const unsubComplete = api.onDumpComplete((msg) => {
      lastDumpEventRef.current = Date.now();
      setDumpProgress(p => ({ ...p, running: false }));
      if (msg?.type !== 'result' || !msg.data) return;
      if (msg.data.error) {
        if (msg.data.code === 'BUSY') {
          addLog(`[BUSY] ${msg.data.error}`, 'warn');
        } else {
          addLog(`[ERROR] ${msg.data.error}`, 'error');
        }
        advanceQueue(false);
        return;
      }
      setDumpResults(msg.data);
      addLog('Dump complete', 'success');
      if (!advanceQueue(true)) {
        const settings = loadSession('settings', { autoNavigate: true });
        if (settings.autoNavigate !== false) {
          setPage('results');
        }
      }
    });
    unsubs.push(unsubComplete);

    return () => {
      unsubs.forEach(unsub => unsub && unsub());
    };
  }, [api, addLog]);

  const runDumpTarget = useCallback((target) => {
    if (!api || !target) return;
    const { engine: eng, pid: procPid, name: procName } = target;
    setDumpProgress({ stage: 'Initializing...', pct: 0, running: true });
    setLogs([]);
    setAccessInfo(null);
    lastDumpEventRef.current = Date.now();
    stallWarnedRef.current = false;

    const settings = loadSession('settings', {});

    const dumpArgs = {
      engine: eng,
      pid: procPid,
      name: procName,
      stealth,
      webhook: (settings.discordWebhook || '').trim(),
      force_discovery: dumpOptions.forceDiscovery,
      regenerate: dumpOptions.regenerate,
    };
    // BYO driver: only send when kernel mode and a key is selected
    if ((stealth === 'driver' || stealth === 'cr3') && driverKey) {
      dumpArgs.driver = driverKey;
    }
    api.startDump(dumpArgs);
  }, [api, stealth, dumpOptions, driverKey]);
  useEffect(() => { runDumpTargetRef.current = runDumpTarget; }, [runDumpTarget]);

  const startDump = useCallback(() => {
    if (!selectedEngine || !selectedProcess) return;
    setLastDump({
      engine: selectedEngine,
      pid: selectedProcess.pid,
      name: selectedProcess.name,
    });
    runDumpTarget({
      engine: selectedEngine,
      pid: selectedProcess.pid,
      name: selectedProcess.name,
    });
  }, [selectedEngine, selectedProcess, runDumpTarget]);

  useEffect(() => { saveSession('lastDump', lastDump); }, [lastDump]);

  const runQueueHead = useCallback(() => {
    const q = dumpQueueRef.current;
    if (!q || q.length === 0 || !runDumpTargetRef.current) return;
    const [head, ...rest] = q;
    setDumpQueue(rest);
    setLastDump(head);
    runDumpTargetRef.current(head);
  }, []);
  const stopDump = useCallback(() => {
    if (!api) return;
    api.stopDump();
    setDumpProgress(p => ({ ...p, running: false }));
    if (dumpQueueRef.current.length > 0) {
      addLog(`[QUEUE] cleared ${dumpQueueRef.current.length} queued target(s)`, 'warn');
      setDumpQueue([]);
    }
    addLog('Cancellation requested — dump will stop at the next checkpoint', 'warn');
  }, [api, addLog]);

  // beforeunload guard if dump/analyze is running
  // Note: analyzing state lives in AnalyzerPage; we check a window flag if needed.
  useEffect(() => {
    const handler = (e) => {
      const analyzing = window.__bifrost_analyzing === true;
      if (dumpProgress.running || analyzing) {
        e.preventDefault();
        e.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dumpProgress.running]);

  // Stall watchdog: a running dump that stops emitting events (progress,
  // logs, terminal) for 45s is wedged or silently dead. Warn once per
  // episode and point at Diagnostics instead of waiting forever.
  useEffect(() => {
    if (!dumpProgress.running) {
      stallWarnedRef.current = false;
      return;
    }
    const timer = setInterval(() => {
      const silentFor = (Date.now() - lastDumpEventRef.current) / 1000;
      if (silentFor > 45 && !stallWarnedRef.current) {
        stallWarnedRef.current = true;
        addLog(`No dump events in ${Math.floor(silentFor)}s — the backend may be wedged. ` +
          'Open Diagnostics (Ctrl+11) for a thread dump and operation telemetry.', 'warn');
      }
    }, 10000);
    return () => clearInterval(timer);
  }, [dumpProgress.running, addLog]);

  // Keyboard shortcuts + Cmd+K palette
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen(o => !o);
        return;
      }
      if (e.ctrlKey && !e.shiftKey && !e.altKey) {
        const pages = ['dashboard', 'engines', 'processes', 'dump', 'results', 'diff', 'memory', 'acmonitor', 'analyzer', 'diag', 'driverbay', 'config', 'settings'];
        const num = parseInt(e.key);
        if (num >= 1 && num <= pages.length) {
          e.preventDefault();
          setPage(pages[num - 1]);
        }
        if (e.key === 'Enter' && page === 'dump' && !dumpProgress.running) {
          e.preventDefault();
          startDump();
        }
        if (e.key === 'Escape' && dumpProgress.running) {
          e.preventDefault();
          stopDump();
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [page, dumpProgress.running, startDump, stopDump]);

  const renderPage = () => {
    switch (page) {
      case 'dashboard':
        return <DashboardPage />;
      case 'engines':
        return (
          <EnginesPage
            selected={selectedEngine}
            onSelect={(e) => { setSelectedEngine(e); }}
          />
        );
      case 'processes':
        return (
          <ProcessesPage
            selected={selectedProcess}
            onSelect={(p) => {
              setSelectedProcess(p);
              if (p.engine) setSelectedEngine(p.engine);
              setPage('dump');
            }}
          />
        );
      case 'dump':
        return (
          <DumpPage
            engine={selectedEngine}
            process={selectedProcess}
            progress={dumpProgress}
            logs={logs}
            onStart={startDump}
            onStop={stopDump}
            dumpOptions={dumpOptions}
            setDumpOptions={setDumpOptions}
            accessInfo={accessInfo}
            lastDump={lastDump}
            onRedump={() => runDumpTarget(lastDump)}
            stealth={stealth}
            driverKey={driverKey}
            setDriverKey={setDriverKey}
            dumpQueue={dumpQueue}
            setDumpQueue={setDumpQueue}
            queueRunning={dumpProgress.running}
            onRunQueue={runQueueHead}
          />
        );
      case 'results':
        return (
          <ResultsPage
            data={dumpResults}
            setPage={setPage}
            setDumpResults={setDumpResults}
          />
        );
      case 'diff':
        return <DiffPage />;
      case 'memory':
        return <MemoryViewerPage />;
      case 'acmonitor':
        return <ACMonitorPage />;
      case 'analyzer':
        return <AnalyzerPage />;
      case 'diag':
        return <DiagnosticsPage />;
      case 'driverbay':
        return <DriverBayPage driverKey={driverKey} setDriverKey={setDriverKey} stealth={stealth} setStealth={setStealth} />;
      case 'config':
        return <ConfigEditorPage />;
      case 'settings':
            return <SettingsPage theme={theme} setTheme={setTheme} />;
      default:
        return null;
    }
  };

  return (
    <ToastContext.Provider value={toast}>
      <ConfirmContext.Provider value={confirmDestructive}>
        <Titlebar onMenuToggle={() => setSidebarOpen(o => !o)} sidebarOpen={sidebarOpen} />
        <Sidebar
          page={page}
          setPage={setPage}
          stealth={stealth}
          setStealth={setStealth}
          bridgeStatus={bridgeStatus}
          open={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />
        <main className="main-content-full">
          {staleBackend && (
            <div className="banner">
              <span className="banner-dot" />
              <span>
                Backend code has been updated but the running Python subprocess
                is from a previous build — fully quit and relaunch the app for
                the latest fixes to take effect. (Verify via Settings → About.)
              </span>
            </div>
          )}
          <div className="main-content-inner">
            <PageErrorBoundary key={page}>
              {renderPage()}
            </PageErrorBoundary>
          </div>
          <div className="toast-container" role="status" aria-live="polite">
            {toasts.map(t => (
              <div key={t.id} className={`toast toast-${t.type}`}>{t.msg}</div>
            ))}
          </div>
        </main>
        <CommandPalette
          open={paletteOpen}
          setOpen={setPaletteOpen}
          onNavigate={setPage}
          onAction={(fn) => {
            if (fn === 'toggleTheme') setTheme(t => t === 'midnight' ? 'paper' : t === 'paper' ? 'terminal' : 'midnight');
            else if (fn === 'startDump') startDump();
            else if (fn === 'copyCpp') copyWithToast('C++ header copied', 'success');
          }}
        />
        {confirm.open && (
          <div className="cmdk-overlay" onClick={() => setConfirm(c => ({ ...c, open: false }))} role="dialog" aria-modal="true" aria-label={confirm.title}>
            <div className="cmdk-panel" onClick={e => e.stopPropagation()} style={{ padding: 16 }}>
              <h3 style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>{confirm.title}</h3>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>{confirm.body}</p>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button className="btn" onClick={() => setConfirm(c => ({ ...c, open: false }))}>Cancel</button>
                <button className="btn btn-primary" onClick={() => { const fn = confirm.onConfirm; setConfirm(c => ({ ...c, open: false })); if (fn) fn(); }}>{confirm.confirmLabel}</button>
              </div>
            </div>
          </div>
        )}
      </ConfirmContext.Provider>
    </ToastContext.Provider>
  );
}
