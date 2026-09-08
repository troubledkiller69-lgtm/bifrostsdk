import React, { useState, useEffect } from 'react';

const AC_DEFINITIONS = [
  { id: 'eac', name: 'Easy Anti-Cheat', color: '#f59e0b', services: ['EasyAntiCheat', 'EasyAntiCheatSvc'], drivers: ['EasyAntiCheat.sys'] },
  { id: 'battleye', name: 'BattlEye', color: '#3b82f6', services: ['BEService', 'BEDaisy'], drivers: ['BEDaisy.sys', 'bedaisy.sys'] },
  { id: 'vanguard', name: 'Riot Vanguard', color: '#ef4444', services: ['vgc', 'vgk'], drivers: ['vgk.sys'] },
  { id: 'ricochet', name: 'RICOCHET', color: '#a855f7', services: ['atvi-acfg'], drivers: ['atvi-re.sys'] },
  { id: 'nprotect', name: 'nProtect GameGuard', color: '#22c55e', services: ['npggsvc'], drivers: ['npptNT2.sys'] },
];

const STEALTH_RECOMMENDATIONS = {
  none: { level: 'DIRECT', desc: 'No anti-cheat detected. Standard memory access is safe.', color: 'var(--success)' },
  light: { level: 'HIJACK', desc: 'Lightweight AC detected. Handle hijacking recommended.', color: 'var(--warn)' },
  heavy: { level: 'DRIVER', desc: 'Kernel-level AC detected. Use driver-based access.', color: 'var(--error)' },
  extreme: { level: 'CR3', desc: 'Aggressive AC with CR3 monitoring. Use CR3 bypass mode.', color: '#ff0040' },
};

export default function ACMonitorPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [lastScan, setLastScan] = useState(null);

  const api = window.bifrost;

  const scan = async () => {
    setLoading(true);
    if (api) {
      try {
        const result = await api.command('ac_detect');
        // Request-response results arrive as {type:'result', data:{<ac_id>: {...}}}
        const payload = result?.type === 'result' ? result.data : result;
        if (payload && !payload.error) {
          setStatus(payload);
          setLastScan(new Date().toLocaleTimeString());
        } else if (payload?.error) {
          console.error('AC scan failed:', payload.error);
          setStatus(null);
        }
      } catch {
        // Fallback: simulate a scan
        simulateScan();
      }
    } else {
      simulateScan();
    }
    setLoading(false);
  };

  const simulateScan = () => {
    const simulated = {};
    AC_DEFINITIONS.forEach(ac => {
      simulated[ac.id] = {
        running: false,
        driver_loaded: false,
        service_status: 'NOT_FOUND',
      };
    });
    setStatus(simulated);
    setLastScan(new Date().toLocaleTimeString());
  };

  useEffect(() => { scan(); }, []);

  const getRecommendation = () => {
    if (!status) return STEALTH_RECOMMENDATIONS.none;
    const running = AC_DEFINITIONS.filter(ac => status[ac.id]?.running);
    if (running.length === 0) return STEALTH_RECOMMENDATIONS.none;
    const hasVanguard = status.vanguard?.running;
    const hasRicochet = status.ricochet?.running;
    if (hasVanguard || hasRicochet) return STEALTH_RECOMMENDATIONS.extreme;
    const hasEac = status.eac?.running;
    const hasBattleye = status.battleye?.running;
    if (hasEac || hasBattleye) return STEALTH_RECOMMENDATIONS.heavy;
    return STEALTH_RECOMMENDATIONS.light;
  };

  const recommendation = getRecommendation();

  return (
    <>
      <div className="page-header">
        <div className="page-title">Anti-Cheat Monitor</div>
        <div className="page-subtitle">
          Detect running anti-cheat systems and get stealth recommendations
          {lastScan && <span style={{ marginLeft: 12, color: 'var(--text-muted)', fontSize: 11 }}>Last scan: {lastScan}</span>}
        </div>
      </div>

      <div className="ac-grid">
        {AC_DEFINITIONS.map(ac => {
          const info = status?.[ac.id] || { running: false, driver_loaded: false, service_status: 'NOT_FOUND' };
          return (
            <div key={ac.id} className={`ac-card ${info.running ? 'running' : ''}`} style={{ '--ac-color': ac.color }}>
              <div className="ac-card-name">{ac.name}</div>
              <div className="ac-card-status">
                <span className={`dot ${info.running ? 'running' : 'stopped'}`} />
                <span style={{ color: info.running ? 'var(--error)' : 'var(--text-muted)' }}>
                  {info.running ? 'ACTIVE' : 'Not Found'}
                </span>
              </div>
              <div className="ac-card-status">
                <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                  Driver: {info.driver_loaded ? 'Loaded' : 'Not loaded'}
                </span>
              </div>
              <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-ghost)' }}>
                Services: {ac.services.join(', ')}
              </div>
            </div>
          );
        })}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="ac-recommendation">
          <div className="ac-recommendation-title">Recommended Stealth Level</div>
          <div className="ac-recommendation-level" style={{ color: recommendation.color }}>
            {recommendation.level}
          </div>
          <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
            {recommendation.desc}
          </div>
        </div>

        <div className="ac-recommendation">
          <div className="ac-recommendation-title">Detected Threats</div>
          {status ? (
            (() => {
              const active = AC_DEFINITIONS.filter(ac => status[ac.id]?.running);
              return active.length === 0 ? (
                <div style={{ color: 'var(--success)', fontSize: 14, fontWeight: 600 }}>
                  No active anti-cheat detected
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {active.map(ac => (
                    <div key={ac.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: ac.color }} />
                      <span style={{ color: 'var(--text-primary)', fontSize: 13 }}>{ac.name}</span>
                    </div>
                  ))}
                </div>
              );
            })()
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>Scanning...</div>
          )}
        </div>
      </div>

      <div className="btn-group">
        <button className="btn btn-primary" onClick={scan} disabled={loading}>
          {loading ? 'Scanning...' : 'Rescan'}
        </button>
      </div>
    </>
  );
}
