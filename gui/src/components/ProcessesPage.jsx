import React, { useState, useEffect, useCallback } from 'react';

export default function ProcessesPage({ selected, onSelect }) {
  const [processes, setProcesses] = useState([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const api = window.bifrost;

  const [bridgeOffline, setBridgeOffline] = useState(false);

  const fetchProcesses = useCallback(() => {
    if (!api) {
      setProcesses([]);
      setBridgeOffline(true);
      setLoading(false);
      return;
    }
    setLoading(true);
    setBridgeOffline(false);
    api.command('list_processes').then((result) => {
      const data = result?.data || result;
      if (Array.isArray(data) && data.length > 0) {
        setProcesses(data);
      } else {
        setProcesses([]);
      }
      setLastUpdated(new Date().toLocaleTimeString());
      setLoading(false);
    }).catch(() => {
      setProcesses([]);
      setBridgeOffline(true);
      setLoading(false);
    });
  }, [api]);

  useEffect(() => { fetchProcesses(); }, [fetchProcesses]);

  const refresh = () => fetchProcesses();

  const filtered = processes.filter((p) => {
    const q = search.toLowerCase();
    return p.name.toLowerCase().includes(q) || String(p.pid).includes(q);
  });

  const isEmpty = !loading && filtered.length === 0;

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Processes</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: selected ? '#7EFF3F' : 'var(--text-ghost)', letterSpacing: '0.08em' }}>● {selected ? `${selected.name.toUpperCase()} : ${selected.pid}` : 'NO TARGET'}</span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Select the target game process to attach — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{filtered.length} visible · {lastUpdated ? `updated ${lastUpdated}` : 'idle'}</span></div>
      </div>

      {bridgeOffline && (
        <div style={{
          padding: '12px 16px', margin: '0 0 12px', borderRadius: 5,
          background: 'rgba(217,74,74,0.12)', border: '1px solid rgba(217,74,74,0.32)',
          borderTop: '1px solid rgba(255,255,255,0.10)',
          color: '#d94a4a', fontSize: 12, fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 8,
          boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06), inset 0 -1px 0 rgba(0,0,0,0.45)'
        }}>
          <span style={{ fontSize: 14, color: '#d94a4a' }}>!</span>
          <span>Bridge Offline — Cannot enumerate processes. Start the Python backend first.</span>
        </div>
      )}

      <div className="search-bar" style={{ position: 'sticky', top: 0, zIndex: 2, background: 'var(--bg-base)', padding: '6px 0 8px', marginBottom: 10 }}>
        <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          placeholder="Search by name or PID... (e.g. cs2, 4820)"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          disabled={bridgeOffline}
          aria-label="Filter processes"
        />
        <span style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)', letterSpacing: '0.04em' }}>{filtered.length}/{processes.length}</span>
      </div>

      <div className="process-table-wrapper">
        <table className="process-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>Name</th>
              <th>Window</th>
              <th>Engine</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={`sk-${i}`}><td colSpan="4" style={{ padding: 0, border: 'none' }}>
                  <div className="skeleton-row">
                    <div className="skeleton skeleton-cell pid" />
                    <div className="skeleton skeleton-cell name" />
                    <div className="skeleton skeleton-cell win" />
                    <div className="skeleton skeleton-cell pid" />
                  </div>
                </td></tr>
              ))
            ) : filtered.length > 0 ? (
              filtered.map((p) => (
                <tr
                  key={p.pid}
                  tabIndex={0}
                  role="button"
                  aria-selected={selected?.pid === p.pid}
                  aria-label={`${p.name} pid ${p.pid}`}
                  className={selected?.pid === p.pid ? 'selected' : ''}
                  onClick={() => onSelect(p)}
                  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(p); } }}
                >
                  <td className="pid">{p.pid}</td>
                  <td className="name">{p.name}</td>
                  <td>{p.window || '-'}</td>
                  <td>{p.engine || '-'}</td>
                </tr>
              ))
            ) : null}
          </tbody>
        </table>
      </div>
      {isEmpty && (
        <div className="empty-state" style={{ marginTop: 12 }}>
          <div className="empty-title">{search ? `No processes match "${search}"` : 'No processes found'}</div>
          <p className="empty-hint">{search ? 'Try a different name or PID.' : 'No running processes enumerated. The backend may be offline.'}</p>
          <div className="empty-action">
            {search ? (
              <button className="btn btn-secondary" onClick={() => setSearch('')}>Clear filter</button>
            ) : (
              <button className="btn btn-secondary" onClick={refresh} disabled={loading} aria-busy={loading}>Refresh</button>
            )}
          </div>
        </div>
      )}

      <div className="btn-group">
        <button className="btn" onClick={refresh} disabled={loading} aria-busy={loading}>{loading ? 'Refreshing…' : 'Refresh'}</button>
      </div>
    </>
  );
}
