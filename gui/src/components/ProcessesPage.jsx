import React, { useState, useEffect } from 'react';

export default function ProcessesPage({ selected, onSelect }) {
  const [processes, setProcesses] = useState([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);

  const api = window.bifrost;

  const [bridgeOffline, setBridgeOffline] = useState(false);

  const fetchProcesses = () => {
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
      setLoading(false);
    }).catch(() => {
      setProcesses([]);
      setBridgeOffline(true);
      setLoading(false);
    });
  };

  useEffect(() => { fetchProcesses(); }, [api]);

  const refresh = () => fetchProcesses();

  const filtered = processes.filter((p) => {
    const q = search.toLowerCase();
    return p.name.toLowerCase().includes(q) || String(p.pid).includes(q);
  });

  return (
    <>
      <div className="page-header">
        <div className="page-title">Processes</div>
        <div className="page-subtitle">Select the target game process to attach</div>
      </div>

      {bridgeOffline && (
        <div style={{
          padding: '12px 16px', margin: '0 16px 12px', borderRadius: 8,
          background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.3)',
          color: 'var(--error)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8
        }}>
          <span style={{ fontSize: 16 }}>!</span>
          <span>Bridge Offline — Cannot enumerate processes. Start the Python backend first.</span>
        </div>
      )}

      <div className="search-bar">
        <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
        <input
          type="text"
          placeholder="Search by name or PID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
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
              <tr><td colSpan="4" style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>Scanning processes...</td></tr>
            ) : filtered.length === 0 ? (
              <tr><td colSpan="4" style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>No processes found</td></tr>
            ) : (
              filtered.map((p) => (
                <tr
                  key={p.pid}
                  className={selected?.pid === p.pid ? 'selected' : ''}
                  onClick={() => onSelect(p)}
                >
                  <td className="pid">{p.pid}</td>
                  <td className="name">{p.name}</td>
                  <td>{p.window || '-'}</td>
                  <td>{p.engine || '-'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="btn-group">
        <button className="btn" onClick={refresh}>Refresh</button>
      </div>
    </>
  );
}

function getDemoProcesses() {
  return [
    { pid: 8124, name: 'OverwatchClient.exe', window: 'Overwatch', engine: 'blizzard' },
    { pid: 6340, name: 'r5apex.exe', window: 'Apex Legends', engine: 'source_eac' },
    { pid: 12480, name: 'FortniteClient-Win64.exe', window: 'Fortnite', engine: 'unreal' },
    { pid: 3720, name: 'cs2.exe', window: 'Counter-Strike 2', engine: 'source' },
    { pid: 9916, name: 'Valorant.exe', window: 'VALORANT', engine: 'unreal' },
    { pid: 4052, name: 'RustClient.exe', window: 'Rust', engine: 'unity' },
  ];
}
