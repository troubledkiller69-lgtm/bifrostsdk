import React, { useState, useEffect, useRef } from 'react';

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
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [copied, setCopied] = useState(false);
  const api = window.bifrost;

  const fetchSnapshot = async (includeThreads) => {
    if (!api) return;
    if (includeThreads) setThreadsBusy(true);
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
      await navigator.clipboard.writeText(JSON.stringify(snap, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard unavailable */ }
  };

  return (
    <>
      <div className="page-header">
        <div className="page-title">Diagnostics</div>
        <div className="page-subtitle">Operation telemetry — see what the backend is doing, or why it stopped</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="stats-row" style={{ marginBottom: 0 }}>
          <div className="stat-card">
            <div className="stat-label">Bridge uptime</div>
            <div className="stat-value" style={{ fontSize: 15 }}>
              {snap ? fmtAge(snap.uptime_s) : '-'}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Active op</div>
            <div className="stat-value" style={{ fontSize: 15, color: current ? 'var(--accent)' : 'var(--text-ghost)' }}>
              {current ? current.cmd : 'none'}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Last op</div>
            <div className="stat-value" style={{ fontSize: 15, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {last ? `${last.cmd} — ${last.outcome || '?'}` : 'none'}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Engines registered</div>
            <div className="stat-value" style={{ fontSize: 15 }}>
              {snap ? (snap.known_engines || []).length : '-'}
            </div>
          </div>
        </div>

        {current && (
          <div className="hunter-config-card" style={{
            padding: 14,
            borderColor: stalled ? 'var(--error)' : 'var(--border)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
              <span className="hunter-config-title" style={{ marginBottom: 0 }}>
                Active: {current.cmd}
              </span>
              {stalled ? (
                <span style={{
                  background: 'var(--error)', color: '#0A0A0A', padding: '2px 8px',
                  borderRadius: 3, fontSize: 11, fontWeight: 700,
                }}>
                  NO EVENTS {fmtAge(current.idle_s)} — STALLED?
                </span>
              ) : (
                <span style={{
                  background: 'var(--success-soft)', color: 'var(--success)', padding: '2px 8px',
                  borderRadius: 3, fontSize: 11,
                }}>
                  idle {fmtAge(current.idle_s)}
                </span>
              )}
              <div style={{ flex: 1 }} />
              <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                started {fmtClock(current.started)} · running {fmtAge(current.running_s)}
              </span>
            </div>

            {current.meta && (current.meta.pid || current.meta.name) && (
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 10, fontSize: 12 }}>
                <span style={{ color: 'var(--text-secondary)' }}>
                  target: <span className="log-line">{current.meta.name || '-'}</span>
                </span>
                <span style={{ color: 'var(--text-secondary)' }}>
                  pid: <span className="log-line">{current.meta.pid || '-'}</span>
                </span>
                <span style={{ color: 'var(--text-secondary)' }}>
                  engine: <span className="log-line">{current.meta.engine || '-'}</span>
                </span>
                <span style={{ color: 'var(--text-secondary)' }}>
                  stealth: <span className="log-line">{current.meta.stealth || '-'}</span>
                </span>
                {snap?.target && (
                  <span style={{ color: snap.target.running ? 'var(--success)' : 'var(--error)' }}>
                    process {snap.target.running ? 'alive' : 'DEAD'}
                  </span>
                )}
              </div>
            )}

            {current.stage && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                  <span className="stage">{current.stage}</span>
                  <span className="pct">{current.pct}%</span>
                </div>
                <div className="progress-track">
                  <div
                    className={`progress-fill ${current.pct >= 100 ? 'complete' : ''}`}
                    style={{ width: `${current.pct}%` }}
                  />
                </div>
              </div>
            )}

            <div className="log-console" style={{ maxHeight: 260, overflow: 'auto' }}>
              {ring.length === 0 ? (
                <div className="log-line dim">No events recorded yet.</div>
              ) : ring.map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 10 }}>
                  <span style={{ color: 'var(--text-ghost)', flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    +{ev.t}s
                  </span>
                  <span className={`log-line ${ev.level}`} style={{ fontSize: 12 }}>
                    {ev.kind === 'progress' ? `[stage] ${ev.text}` : ev.text}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {!current && last && (
          <div className="hunter-config-card" style={{ padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <span className="hunter-config-title" style={{ marginBottom: 0 }}>
                Last operation: {last.cmd}
              </span>
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
              <div className="log-console" style={{ maxHeight: 180, overflow: 'auto', marginTop: 10 }}>
                {last.ring.map((ev, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10 }}>
                    <span style={{ color: 'var(--text-ghost)', flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      +{ev.t}s
                    </span>
                    <span className={`log-line ${ev.level}`} style={{ fontSize: 12 }}>
                      {ev.text}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {!current && !last && (
          <div className="hunter-config-card" style={{ padding: 14 }}>
            <div className="log-line dim" style={{ fontSize: 12 }}>
              No operations recorded yet. Run a dump, then come back here if it misbehaves.
            </div>
          </div>
        )}

        {snap?.output && snap.output.length > 0 && (
          <div className="hunter-config-card" style={{ padding: 14 }}>
            <div className="hunter-config-title" style={{ marginBottom: 10 }}>
              Output directory — output/{last?.meta?.name || current?.meta?.name || ''}
            </div>
            <div className="log-console" style={{ maxHeight: 220, overflow: 'auto', padding: 0 }}>
              {snap.output.map((f, i) => (
                <div key={i} className="hex-row" style={{ display: 'flex', gap: 10 }}>
                  <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0 }}>
                    {fmtBytes(f.size)}
                  </span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                    {f.path}
                  </span>
                  <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0 }}>
                    {new Date(f.mtime * 1000).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {error && (
          <div style={{ color: 'var(--error)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            className="btn btn-secondary"
            onClick={() => fetchSnapshot(false)}
            disabled={busy}
            style={{ padding: '8px 16px', fontSize: 12 }}
          >
            Refresh now
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => setAutoRefresh(v => !v)}
            style={{ padding: '8px 16px', fontSize: 12 }}
          >
            {autoRefresh ? 'Auto-refresh ON (5s)' : 'Auto-refresh OFF'}
          </button>
          <button
            className="btn btn-primary"
            onClick={() => fetchSnapshot(true)}
            disabled={threadsBusy}
            style={{ padding: '8px 16px', fontSize: 12 }}
          >
            {threadsBusy ? 'DUMPING THREADS...' : 'Thread dump'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={copySnapshot}
            style={{ padding: '8px 16px', fontSize: 12 }}
          >
            {copied ? 'Copied' : 'Copy snapshot JSON'}
          </button>
        </div>

        {threads && (
          <div className="hunter-config-card" style={{ padding: 14 }}>
            <div className="hunter-config-title" style={{ marginBottom: 10 }}>
              Backend thread dump
            </div>
            <pre className="log-console" style={{ maxHeight: 480, overflow: 'auto', padding: 10, fontSize: 11, whiteSpace: 'pre', fontFamily: 'var(--font-mono)' }}>
              {threads}
            </pre>
          </div>
        )}
      </div>
    </>
  );
}
