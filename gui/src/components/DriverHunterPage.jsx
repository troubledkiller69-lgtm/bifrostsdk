import React, { useState, useEffect, useRef } from 'react';

export function DriverHunterPage() {
  const [isHunting, setIsHunting] = useState(false);
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState([]);
  const [maxDrivers, setMaxDrivers] = useState(100);

  const consoleEndRef = useRef(null);
  const api = window.bifrost;

  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    if (!api) return;

    const unsubLog = api.onHuntLog((data) => {
      const text = typeof data === 'string' ? data : (data?.text || JSON.stringify(data));
      setLogs(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        text,
        level: data.level || 'info'
      }]);
    });

    const unsubComplete = api.onHuntComplete((data) => {
      setIsHunting(false);
      const payload = data?.type === 'result' ? data.data : data;
      if (payload && Array.isArray(payload)) {
        setResults(payload);
      } else if (payload && payload.error) {
        setLogs(prev => [...prev, {
          time: new Date().toLocaleTimeString(),
          text: `[ERROR] ${payload.error}`,
          level: 'error'
        }]);
      }
    });

    return () => {
      unsubLog && unsubLog();
      unsubComplete && unsubComplete();
    };
  }, [api]);

  const handleStart = () => {
    if (isHunting) return;
    setIsHunting(true);
    setLogs([]);
    setResults([]);

    if (api) {
      api.startHunt({ max_drivers: maxDrivers });
    } else {
      setLogs([{ time: new Date().toLocaleTimeString(), text: 'Cannot connect to bridge (not in Electron).', level: 'error' }]);
      setIsHunting(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <div className="page-title">Vulnerable Driver Hunter</div>
        <div className="page-subtitle">Scrape LOLDrivers and Microsoft Catalogs for 0-day Read/Write primitives</div>
      </div>

      <div className="hunter-grid">
        <div className="hunter-config">
          <div className="hunter-config-card">
            <div className="hunter-config-title">
              <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ width: 16, height: 16 }}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Hunt Configuration
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>
                Max Drivers to Scan
              </label>
              <input
                type="number"
                className="input-field"
                value={maxDrivers}
                onChange={(e) => setMaxDrivers(parseInt(e.target.value) || 50)}
              />
            </div>

            <button
              className="btn btn-primary"
              onClick={handleStart}
              disabled={isHunting}
              style={{ width: '100%', padding: '12px' }}
            >
              {isHunting ? 'HUNTING...' : 'START HUNT'}
            </button>
          </div>

          <div className="hunter-config-card">
            <div className="hunter-config-title">Analysis Status</div>
            <div className="hunter-count">
              <span className="hunter-count-label">Discovered</span>
              <span className="hunter-count-value">{results.length}</span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="hunter-console">
            <div className="hunter-console-header">
              <span className="hunter-console-title">hunter.log</span>
            </div>

            <div className="hunter-console-body">
              {logs.length === 0 ? (
                <div className="log-line dim">Waiting to begin hunt...</div>
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

          {results.length > 0 && (
            <div className="process-table-wrapper" style={{ maxHeight: 300 }}>
              <table className="process-table">
                <thead>
                  <tr>
                    <th>Driver ID</th>
                    <th>Vulnerability</th>
                    <th>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((driver, idx) => (
                    <tr key={idx}>
                      <td className="name">{driver.id}</td>
                      <td>{driver.vulnerability}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {(driver.tags || []).slice(0, 3).map((tag, i) => (
                            <span key={i} className="engine-card-tag" style={{
                              background: 'rgba(255,255,255,0.06)',
                              color: 'var(--text-muted)',
                              fontSize: 9
                            }}>
                              {tag}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
