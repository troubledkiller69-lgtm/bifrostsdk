import React, { useRef, useEffect, useMemo } from 'react';

const accessTone = (acc) => {
  if (!acc) return '';
  if (acc.fallback) return 'warn';
  if (acc.probed) return 'ok';
  return 'bad';
};

export default function DumpPage({ engine, process, progress, logs, onStart, onStop, dumpOptions, setDumpOptions, accessInfo, lastDump, onRedump, stealth, driverKey, setDriverKey, dumpQueue, setDumpQueue, queueRunning, onRunQueue, watch, setWatch }) {
  const queueTarget = () => {
    if (!engine || !process || !setDumpQueue) return;
    const entry = { engine, pid: process.pid, name: process.name };
    if ((dumpQueue || []).some(q => q.engine === entry.engine && q.pid === entry.pid)) {
      window.bifrost?.toast && window.bifrost.toast('Already queued', 'info');
      return;
    }
    setDumpQueue([...(dumpQueue || []), entry]);
    window.bifrost?.toast && window.bifrost.toast(`Queued ${entry.name} (PID ${entry.pid})`, 'success');
  };
  const [driverOptions, setDriverOptions] = React.useState(null);
  React.useEffect(() => {
    if ((stealth === 'driver' || stealth === 'cr3') && window.bifrost?.command) {
      window.bifrost.command('driver_list', {}).then(r => {
        const p = r?.type === 'result' ? r.data : r;
        if (p?.drivers) setDriverOptions(p.drivers.filter(d=>d.present));
      }).catch(()=>{});
    }
  }, [stealth]);
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  // stale accessInfo guard: hide panel when target changes until next dump
  const accessKeyRef = useRef(null);
  const currentKey = `${engine || ''}:${process?.pid || ''}`;
  useEffect(() => {
    // mark current target; accessInfo from previous target is considered stale
    accessKeyRef.current = currentKey;
  }, [currentKey]);

  const showAccess = useMemo(() => {
    if (!accessInfo) return null;
    // if accessKeyRef hasn't been set yet, show; otherwise require match at time of dump
    // we keep previous key at mount, so first render after navigation hides stale panel
    // simpler: only show if engine/process still match the running/complete context
    // since we cannot know dump-time key, hide when currentKey differs from last captured
    // capture on accessInfo change
    return accessInfo;
  }, [accessInfo]);

  // when engine/process changes, visually the old access panel is stale — effect documents clearing
  useEffect(() => {
    // Intent: parent clears accessInfo on target change (via App). This effect ensures
    // we don't keep showing a previous attach resolution after user switches engine/pid.
    // If parent hasn't cleared yet, we suppress rendering until next access event.
  }, [engine, process]);

  const hasError = useMemo(() => logs.some(l => l.type === 'error' || (l.text && /\[ERROR\]/i.test(l.text))), [logs]);

  const navigateViaHotkey = (num) => {
    const ev = new KeyboardEvent('keydown', { key: String(num), ctrlKey: true, bubbles: true });
    window.dispatchEvent(ev);
  };

  const displayAccess = (() => {
    if (!showAccess) return null;
    // stale check: if currentKey changed after accessInfo arrived, suppress
    // store arrival key
    return showAccess;
  })();

  // improved stale suppression: track arrival key
  const arrivalKeyRef = useRef(null);
  useEffect(() => {
    if (accessInfo) arrivalKeyRef.current = currentKey;
  }, [accessInfo, currentKey]);
  const isStale = arrivalKeyRef.current && arrivalKeyRef.current !== currentKey;
  const effectiveAccess = isStale ? null : showAccess;

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Dump Offsets</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)', letterSpacing: '0.08em' }}>● ARMED  <span style={{ color: '#7EFF3F' }}>{engine || 'NO ENGINE'} → {process?.name || 'NO TARGET'}</span></span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Execute the offset dumper against the selected target — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>FM 89.7 — TORRETTOS GARAGE</span></div>
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
      {(stealth === 'driver' || stealth === 'cr3') && (
        <div style={{ marginBottom: 12, padding: '10px 12px', borderRadius: 5, background: '#0a0a0c', border: '1px solid rgba(126,255,63,0.22)', borderTop: '1px solid rgba(126,255,63,0.32)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.08), 0 0 8px rgba(126,255,63,0.08)' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>Driver — {stealth}</span>
          <select className="input-field" style={{ flex: '1 1 200px', fontSize: 12, minWidth: 180 }} value={driverKey || ''} onChange={e=>setDriverKey && setDriverKey(e.target.value || null)}>
            <option value="">Auto (first available)</option>
            {(driverOptions||[]).map(d => <option key={d.key} value={d.key}>{d.key} — {d.filename}{d.byo ? ' (BYO)' : ''} {d.present ? '' : '(missing)'}</option>)}
          </select>
          <span style={{ fontSize: 11, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>{driverKey ? `→ ${driverKey}` : 'auto-detect'}</span>
          <button className="btn" style={{ fontSize: 11, padding: '6px 10px' }} onClick={()=>window.dispatchEvent(new CustomEvent('bifrost:navigate',{detail:'driverbay'}))}>Driver Bay</button>
        </div>
      )}

      {progress.running && (
        <div className="progress-bar-container">
          <div className="progress-label">
            <span className="stage">{progress.stage}</span>
            <span className="pct">{progress.pct}%</span>
          </div>
          <div className="progress-track" role="progressbar" aria-valuenow={progress.pct} aria-valuemin={0} aria-valuemax={100} aria-label="Dump progress">
            <div
              className={`progress-fill ${progress.pct >= 100 ? 'complete' : ''}`}
              style={{ width: `${progress.pct}%` }}
            />
          </div>
        </div>
      )}

      {hasError && !progress.running && (
        <div style={{
          padding: '12px 16px', marginTop: 14, borderRadius: 5,
          background: 'rgba(217,74,74,0.12)', border: '1px solid rgba(217,74,74,0.32)',
          borderTop: '1px solid rgba(255,255,255,0.10)',
          color: '#d94a4a', fontSize: 12, fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06), inset 0 -1px 0 rgba(0,0,0,0.45)'
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 14 }}>!</span>
            <span>Dump reported errors — check the console below.</span>
          </span>
          <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 11 }} onClick={onStart} disabled={!engine || !process || progress.running}>Retry</button>
        </div>
      )}

      {effectiveAccess && (
        <div className="access-panel" style={{ marginTop: 14 }}>
          <div className="access-head">
            <span className="access-tag">ACCESS</span>
            <span className={`access-dot ${accessTone(effectiveAccess)}`} />
            <span className="access-transport">{effectiveAccess.method_name || effectiveAccess.transport}</span>
            <span className="access-dim">
              {effectiveAccess.requested !== effectiveAccess.transport
                ? `(requested: ${effectiveAccess.requested})` : ''}
              {effectiveAccess.fallback ? '  kernel attach failed → direct fallback' : ''}
            </span>
            <span className="access-ms">{effectiveAccess.ms != null ? `${effectiveAccess.ms} ms` : ''}</span>
          </div>
          {effectiveAccess.steps && effectiveAccess.steps.length > 0 && (
            <div className="access-steps">
              {effectiveAccess.steps.map((s, i) => (
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
        {!progress.running && engine && process && (
          <button
            className="btn"
            onClick={queueTarget}
            title="Add this engine+process to the batch queue — runs after the current dump finishes"
          >
            Queue Target{(dumpQueue?.length || 0) > 0 ? ` (${dumpQueue.length})` : ''}
          </button>
        )}
      </div>

      <div style={{ marginTop: 12, padding: '10px 12px', borderRadius: 5, background: '#0a0a0c', border: `1px solid ${watch?.on ? 'rgba(126,255,63,0.22)' : 'rgba(255,255,255,0.08)'}`, borderTop: '1px solid rgba(255,255,255,0.12)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.08)' }}>
        <span style={{ fontSize: 11, color: watch?.on ? '#7EFF3F' : 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>● Watch{watch?.on ? ' — on' : ' — off'}</span>
        <select className="input-field" style={{ fontSize: 12, minWidth: 130 }} value={watch?.minutes || 15} onChange={(e) => setWatch && setWatch({ ...(watch || {}), minutes: parseInt(e.target.value, 10) })} title="Re-dump interval">
          <option value={5}>every 5m</option>
          <option value={15}>every 15m</option>
          <option value={30}>every 30m</option>
          <option value={60}>every 60m</option>
        </select>
        <button className={`btn ${watch?.on ? 'btn-primary' : ''}`} style={{ fontSize: 11, padding: '6px 12px' }} onClick={() => setWatch && setWatch({ ...(watch || { minutes: 15 }), on: !watch?.on })} title="Re-dump this target on an interval; drift vs the previous dump logs + toasts">
          {watch?.on ? 'Stop' : 'Start'}
        </button>
        <span style={{ fontSize: 11, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>re-dumps {process?.name || 'target'} · drift alerts in log</span>
      </div>

      {(dumpQueue?.length || 0) > 0 && (
        <div style={{ marginTop: 12, padding: '10px 12px', borderRadius: 5, background: '#0a0a0c', border: '1px solid rgba(255,255,255,0.08)', borderTop: '1px solid rgba(255,255,255,0.12)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, color: 'var(--text-secondary)', fontFamily: 'var(--font-display)' }}>Batch queue</span>
            <span style={{ fontSize: 11, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{dumpQueue.length} queued{queueRunning ? ' · running' : ''}</span>
            <span style={{ flex: 1 }} />
            {!queueRunning && (
              <button className="btn btn-primary" style={{ fontSize: 11, padding: '4px 12px' }} onClick={onRunQueue} title="Dump the first queued entry, then chain the rest">Run Queue</button>
            )}
            <button className="btn" style={{ fontSize: 11, padding: '4px 12px' }} onClick={() => setDumpQueue([])}>Clear</button>
          </div>
          {(dumpQueue || []).map((q, i) => (
            <div key={`${q.engine}-${q.pid}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderTop: i ? '1px solid rgba(255,255,255,0.05)' : 'none', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              <span style={{ color: 'var(--text-ghost)' }}>{i + 1}.</span>
              <span style={{ color: 'var(--text-primary)' }}>{q.engine}</span>
              <span style={{ color: 'var(--text-muted)' }}>→</span>
              <span style={{ color: 'var(--text-primary)' }}>{q.name}</span>
              <span style={{ color: 'var(--text-ghost)' }}>PID {q.pid}</span>
              <span style={{ flex: 1 }} />
              <button className="btn" style={{ fontSize: 10, padding: '2px 8px' }} onClick={() => setDumpQueue(dumpQueue.filter((_, j) => j !== i))}>Remove</button>
            </div>
          ))}
        </div>
      )}

      {!engine && !process && (
        <div className="empty-state" style={{ marginTop: 16 }}>
          <div className="empty-title">No target selected</div>
          <p className="empty-hint">Pick an engine and a process before dumping.</p>
          <div className="empty-action" style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" onClick={() => navigateViaHotkey(1)}>Go to Engines</button>
            <button className="btn" onClick={() => navigateViaHotkey(2)}>Go to Processes</button>
          </div>
        </div>
      )}
      {(!engine || !process) && (engine || process) && !progress.running && (
        <div className="empty-state" style={{ marginTop: 16 }}>
          <div className="empty-title">Target incomplete</div>
          <p className="empty-hint">{!engine ? 'Select an engine first.' : 'Select a process to attach.'}</p>
          <div className="empty-action" style={{ display: 'flex', gap: 8 }}>
            {!engine && <button className="btn btn-primary" onClick={() => navigateViaHotkey(1)}>Go to Engines</button>}
            {!process && <button className="btn btn-primary" onClick={() => navigateViaHotkey(2)}>Go to Processes</button>}
          </div>
        </div>
      )}
    </>
  );
}
