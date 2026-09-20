import React, { useState, useEffect, useRef, useContext } from 'react';
import { ToastContext } from '../App';

function fmtAge(seconds) {
  if (seconds == null) return '-';
  if (seconds < 1) return '<1s';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m${s}s`;
}

function fmtClock(ts) {
  if (!ts) return '-';
  return new Date(ts * 1000).toLocaleTimeString();
}

function fmtBytes(n) {
  if (n == null) return '-';
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1024 / 1024).toFixed(1)}MB`;
}

const STALL_SECONDS = 30;

export default function DiagnosticsPage() {
  const [snap, setSnap] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [threads, setThreads] = useState(null);
  const [threadsBusy, setThreadsBusy] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(() => {
    try {
      const v = localStorage.getItem('bifrost_diag_autoRefresh');
      return v == null ? true : JSON.parse(v);
    } catch { return true; }
  });
  const [copied, setCopied] = useState(false);
  const toast = useContext(ToastContext);
  const api = window.bifrost;

  useEffect(() => {
    try { localStorage.setItem('bifrost_diag_autoRefresh', JSON.stringify(autoRefresh)); } catch {}
  }, [autoRefresh]);

  const fetchSnapshot = async (includeThreads) => {
    if (!api) return;
    if (includeThreads) setThreadsBusy(true);
    else setBusy(true);
    try {
      const res = await api.debugSnapshot(!!includeThreads);
      const payload = res && res.type === 'result' ? res.data : res;
      if (payload?.error) { setError(`${payload.code || 'ERROR'}: ${payload.error}`); return; }
      setError('');
      setSnap(payload);
      if (includeThreads) setThreads(payload.threads || '(no thread dump returned)');
    } catch (e) {
      setError(e?.message || String(e));
    } finally {
      if (includeThreads) setThreadsBusy(false);
      else setBusy(false);
    }
  };

  useEffect(() => {
    fetchSnapshot(false);
    const timer = setInterval(() => {
      if (autoRefresh) fetchSnapshot(false);
    }, 5000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, autoRefresh]);

  const current = snap?.current || null;
  const last = snap?.last || null;
  const stalled = current ? current.idle_s > STALL_SECONDS : false;
  const ring = current?.ring || [];

  const copySnapshot = async () => {
    try {
      if (window.bifrost?.copyWithToast) {
        await window.bifrost.copyWithToast(JSON.stringify(snap, null, 2), 'Snapshot copied');
      } else {
        await navigator.clipboard.writeText(JSON.stringify(snap, null, 2));
        toast && toast('Snapshot copied', 'success');
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { toast && toast('Copy failed', 'error'); }
  };

  const handleGoToDump = () => {
    try { localStorage.setItem('bifrost_page', JSON.stringify('dump')); } catch {}
    // If App exposes page setter via event, dispatch; fallback to reload
    window.dispatchEvent(new CustomEvent('bifrost:navigate', { detail: 'dump' }));
    // Fallback: reload so App picks up saved page
    setTimeout(() => { if (window.location) window.location.reload(); }, 80);
  };

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Diagnostics</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: stalled ? '#d94a4a' : current ? '#7EFF3F' : 'var(--text-ghost)', letterSpacing: '0.08em' }}>● {stalled ? 'STALLED' : current ? `${current.cmd.toUpperCase()} · ${current.pct}%` : last ? `LAST ${last.cmd.toUpperCase()} · ${last.outcome}` : 'IDLE'}</span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Operation telemetry — see what the backend is doing, or why it stopped — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>auto-refresh 5s · ring buffer</span></div>
      </div>

      <div className="stats-row" style={{ marginBottom: 12 }}>
        <div className="stat-card">
          <div className="stat-label">Bridge uptime</div>
          <div className="stat-value" style={{ fontSize: 14 }}>
            {snap ? fmtAge(snap.uptime_s) : '-'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Active op</div>
          <div className="stat-value" style={{ fontSize: 14, color: current ? 'var(--accent)' : 'var(--text-ghost)' }}>
            {current ? current.cmd : 'none'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Last op</div>
          <div className="stat-value" style={{ fontSize: 14, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {last ? `${last.cmd} — ${last.outcome || '?'}` : 'none'}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Engines registered</div>
          <div className="stat-value" style={{ fontSize: 14 }}>
            {snap ? (snap.known_engines || []).length : '-'}
          </div>
        </div>
      </div>

      <div className="page-grid" style={{ alignItems: 'start' }}>
        <div className="page-config" style={{ gap: 12 }}>
          <div className="page-config-card">
            <div className="page-config-title" style={{ fontWeight: 600, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>Controls</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <button className="btn btn-secondary" onClick={() => fetchSnapshot(false)} disabled={threadsBusy} style={{ width: '100%', fontSize: 12 }}>
                {threadsBusy ? 'Refreshing...' : 'Refresh now'}
              </button>
              <button className="btn" onClick={() => setAutoRefresh(v => !v)} style={{ width: '100%', fontSize: 12 }}>
                {autoRefresh ? 'Auto-refresh ON (5s)' : 'Auto-refresh OFF'}
              </button>
              <button className="btn btn-primary" onClick={() => fetchSnapshot(true)} disabled={threadsBusy} style={{ width: '100%', fontSize: 12 }}>
                {threadsBusy ? 'DUMPING THREADS...' : 'Thread dump'}
              </button>
              <button className="btn" onClick={copySnapshot} style={{ width: '100%', fontSize: 12 }}>
                {copied ? 'Copied' : 'Copy snapshot JSON'}
              </button>
            </div>
            {error && (
              <div role="alert" style={{ color: 'var(--error)', fontSize: 11, fontFamily: 'var(--font-mono)', marginTop: 10, wordBreak: 'break-all', background: 'var(--error-soft)', border: '1px solid rgba(217,74,74,0.18)', borderRadius: 5, padding: '6px 10px' }}>
                {error}
              </div>
            )}
          </div>

          {snap?.output && snap.output.length > 0 && (
            <div className="page-config-card" style={{ padding: 12 }}>
              <div className="page-config-title" style={{ marginBottom: 8, fontSize: 11 }}>Output — output/{last?.meta?.name || current?.meta?.name || ''}</div>
              <div className="log-console" style={{ maxHeight: 220, overflow: 'auto', padding: 8 }}>
                {snap.output.map((f, i) => (
                  <div key={i} className="hex-row" style={{ display: 'flex', gap: 8, padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                    <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0 }}>{fmtBytes(f.size)}</span>
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{f.path}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>
          {current && (
            <div className="page-config-card" style={{ padding: 12, borderColor: stalled ? 'var(--error)' : 'transparent' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
                <span className="page-config-title" style={{ marginBottom: 0 }}>
                  Active: {current.cmd}
                </span>
                {stalled ? (
                  <span style={{ background: 'var(--error)', color: '#0A0A0A', padding: '2px 8px', borderRadius: 3, fontSize: 11, fontWeight: 700 }}>
                    NO EVENTS {fmtAge(current.idle_s)} — STALLED?
                  </span>
                ) : (
                  <span style={{ background: 'var(--success-soft)', color: 'var(--success)', padding: '2px 8px', borderRadius: 3, fontSize: 11 }}>
                    idle {fmtAge(current.idle_s)}
                  </span>
                )}
                <div style={{ flex: 1 }} />
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  started {fmtClock(current.started)} · running {fmtAge(current.running_s)}
                </span>
              </div>

              {current.meta && (current.meta.pid || current.meta.name) && (
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 10, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>target: <span style={{ color: 'var(--text-secondary)' }}>{current.meta.name || '-'}</span></span>
                  <span style={{ color: 'var(--text-muted)' }}>pid: <span style={{ color: 'var(--text-secondary)' }}>{current.meta.pid || '-'}</span></span>
                  <span style={{ color: 'var(--text-muted)' }}>engine: <span style={{ color: 'var(--text-secondary)' }}>{current.meta.engine || '-'}</span></span>
                  <span style={{ color: 'var(--text-muted)' }}>stealth: <span style={{ color: 'var(--text-secondary)' }}>{current.meta.stealth || '-'}</span></span>
                  {snap?.target && (
                    <span style={{ color: snap.target.running ? 'var(--success)' : 'var(--error)', fontWeight: 600 }}>
                      {snap.target.running ? '● alive' : '■ DEAD'}
                    </span>
                  )}
                </div>
              )}

              {current.stage && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4, fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--text-muted)' }}>{current.stage}</span>
                    <span style={{ color: '#7EFF3F', textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>{current.pct}%</span>
                  </div>
                  <div className="progress-track">
                    <div className={`progress-fill ${current.pct >= 100 ? 'complete' : ''}`} style={{ width: `${current.pct}%` }} />
                  </div>
                </div>
              )}

              <div className="page-console" style={{ maxHeight: 260, height: 260 }}>
                <div className="page-console-body">
                  {ring.length === 0 ? (
                    <div className="log-line dim">No events recorded yet.</div>
                  ) : ring.map((ev, i) => (
                    <div key={i} style={{ display: 'flex', gap: 10 }}>
                      <span style={{ color: 'var(--text-ghost)', flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 11 }}>+{ev.t}s</span>
                      <span className={`log-line ${ev.level}`} style={{ fontSize: 12 }}>{ev.kind === 'progress' ? `[stage] ${ev.text}` : ev.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {!current && last && (
            <div className="page-config-card" style={{ padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <span className="page-config-title" style={{ marginBottom: 0 }}>Last operation: {last.cmd}</span>
                <span style={{
                  background: last.outcome === 'ok' ? 'var(--success-soft)' : last.outcome === 'cancelled' ? 'var(--warn-soft)' : 'var(--warn-soft)',
                  color: last.outcome === 'ok' ? 'var(--success)' : 'var(--warn)',
                  padding: '2px 8px', borderRadius: 3, fontSize: 11, fontFamily: 'var(--font-mono)',
                }}>
                  {last.outcome || '?'}
                </span>
                <div style={{ flex: 1 }} />
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {last.meta?.name || last.meta?.engine || ''} · took {last.duration != null ? fmtAge(last.duration) : '-'} · ended {fmtClock(last.ended)}
                </span>
              </div>
              {last.ring && last.ring.length > 0 && (
                <div className="page-console" style={{ maxHeight: 180, height: 180, marginTop: 10 }}>
                  <div className="page-console-body">
                    {last.ring.map((ev, i) => (
                      <div key={i} style={{ display: 'flex', gap: 10 }}>
                        <span style={{ color: 'var(--text-ghost)', flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 11 }}>+{ev.t}s</span>
                        <span className={`log-line ${ev.level}`} style={{ fontSize: 12 }}>{ev.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {!current && !last && (
            <div className="empty-state">
              <div className="empty-title">No operations recorded</div>
              <p className="empty-hint">No dump or operation has run yet. Start a dump and return here for telemetry.</p>
              <div className="empty-action">
                <button className="btn btn-primary" onClick={handleGoToDump}>Go to Dump</button>
              </div>
            </div>
          )}

          {threads && (
            <div className="page-config-card" style={{ padding: 12 }}>
              <div className="page-config-title" style={{ marginBottom: 10, fontWeight: 600, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>Backend thread dump</div>
              <pre className="page-console" style={{ maxHeight: 480, overflow: 'auto', padding: 10, fontSize: 11, whiteSpace: 'pre', fontFamily: 'var(--font-mono)', display: 'block' }}>{threads}</pre>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
