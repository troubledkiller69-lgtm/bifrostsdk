import React, { useRef, useEffect } from 'react';

const accessTone = (acc) => {
  if (!acc) return '';
  if (acc.fallback) return 'warn';
  if (acc.probed) return 'ok';
  return 'bad';
};

export default function DumpPage({ engine, process, progress, logs, onStart, onStop, dumpOptions, setDumpOptions, accessInfo, lastDump, onRedump }) {
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <>
      <div className="page-header">
        <div className="page-title">Dump Offsets</div>
        <div className="page-subtitle">Execute the offset dumper against the selected target</div>
      </div>

      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-label">Engine</div>
          <div className="stat-value">{engine || 'None'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Target</div>
          <div className="stat-value">{process?.name || 'None'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">PID</div>
          <div className="stat-value">{process?.pid || '-'}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className="stat-value" style={{ color: progress.running ? 'var(--warn)' : 'var(--text-muted)' }}>
            {progress.running ? 'Running' : 'Idle'}
          </div>
        </div>
      </div>

      {progress.running && (
        <div className="progress-bar-container">
          <div className="progress-label">
            <span className="stage">{progress.stage}</span>
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

      {accessInfo && (
        <div className="access-panel" style={{ marginTop: 14 }}>
          <div className="access-head">
            <span className="access-tag">ACCESS</span>
            <span className={`access-dot ${accessTone(accessInfo)}`} />
            <span className="access-transport">{accessInfo.method_name || accessInfo.transport}</span>
            <span className="access-dim">
              {accessInfo.requested !== accessInfo.transport
                ? `(requested: ${accessInfo.requested})` : ''}
              {accessInfo.fallback ? '  kernel attach failed → direct fallback' : ''}
            </span>
            <span className="access-ms">{accessInfo.ms != null ? `${accessInfo.ms} ms` : ''}</span>
          </div>
          {accessInfo.steps && accessInfo.steps.length > 0 && (
            <div className="access-steps">
              {accessInfo.steps.map((s, i) => (
                <div key={i} className="access-step">
                  <span className={`access-dot ${s.ok ? 'ok' : 'bad'}`} style={{ width: 6, height: 6 }} />
                  <span className="access-step-name">{s.step}</span>
                  <span className="access-dim">{s.detail}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="log-console" ref={logRef}>
        {logs.length === 0 ? (
          <p className="log-line dim">Awaiting dump start...</p>
        ) : (
          logs.map((log, i) => (
            <p key={i} className={`log-line ${log.type}`}>{log.text}</p>
          ))
        )}
      </div>

      <div className="btn-group">
        <button
          className="btn btn-primary"
          onClick={onStart}
          disabled={!engine || !process || progress.running}
        >
          {progress.running ? 'Dumping...' : 'Start Dump'}
        </button>
        {lastDump && !progress.running && (
          <button
            className="btn"
            onClick={onRedump}
            disabled={!lastDump}
            title={`Re-dump ${lastDump.name} (pid ${lastDump.pid}) with the current access mode`}
          >
            Re-dump {lastDump.name}
          </button>
        )}
        {progress.running && (
          <button
            className="btn btn-danger"
            onClick={onStop}
          >
            Cancel
          </button>
        )}
      </div>

      {!engine && !process && (
        <div style={{ textAlign: 'center', marginTop: 16, color: 'var(--text-muted)', fontSize: 12 }}>
          Select an engine and process first to start a dump.
        </div>
      )}
    </>
  );
}
