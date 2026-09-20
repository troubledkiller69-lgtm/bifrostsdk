import React, { useState, useEffect } from 'react';

const AC_DEFINITIONS = [
  { id: 'eac', name: 'Easy Anti-Cheat', color: '#d4af37', services: ['EasyAntiCheat', 'EasyAntiCheatSvc'], drivers: ['EasyAntiCheat.sys'] },
  { id: 'battleye', name: 'BattlEye', color: '#d4af37', services: ['BEService', 'BEDaisy'], drivers: ['BEDaisy.sys', 'bedaisy.sys'] },
  { id: 'vanguard', name: 'Riot Vanguard', color: '#d94a4a', services: ['vgc', 'vgk'], drivers: ['vgk.sys'] },
  { id: 'ricochet', name: 'RICOCHET', color: '#d94a4a', services: ['atvi-acfg'], drivers: ['atvi-re.sys'] },
  { id: 'nprotect', name: 'nProtect GameGuard', color: '#d4af37', services: ['npggsvc'], drivers: ['npptNT2.sys'] },
];

const STEALTH_RECOMMENDATIONS = {
  none: { level: 'DIRECT', desc: 'No anti-cheat detected. Standard memory access is safe.', color: '#7EFF3F' },
  light: { level: 'HIJACK', desc: 'Lightweight AC detected. Handle hijacking recommended.', color: '#7EFF3F' },
  heavy: { level: 'DRIVER', desc: 'Kernel-level AC detected. Use driver-based access.', color: 'var(--error)' },
  extreme: { level: 'CR3', desc: 'Aggressive AC with CR3 monitoring. Use CR3 bypass mode.', color: '#d94a4a' },
};

export default function ACMonitorPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [lastScan, setLastScan] = useState(null);
  const [scanError, setScanError] = useState('');

  const api = window.bifrost;

  const scan = async () => {
    setLoading(true);
    setScanError('');
    if (api) {
      try {
        const result = await api.command('ac_detect');
        const payload = result?.type === 'result' ? result.data : result;
        if (payload && !payload.error) {
          setStatus(payload);
          setLastScan(new Date().toLocaleTimeString());
        } else if (payload?.error) {
          setScanError(payload.error);
          setStatus(null);
        }
      } catch {
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
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Anti-Cheat Monitor</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: recommendation.level === 'DIRECT' ? 'var(--success)' : recommendation.level === 'CR3' ? '#d94a4a' : '#7EFF3F', letterSpacing: '0.08em' }}>● {recommendation.level}{lastScan ? ` · ${lastScan}` : ''}</span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Detect running anti-cheat systems and get stealth recommendations — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{AC_DEFINITIONS.length} providers · driver/service scan</span></div>
      </div>

      {scanError && (
        <div className="page-config-card" role="alert" style={{ padding: 12, marginBottom: 12, borderColor: 'rgba(217,74,74,0.22)', background: 'var(--error-soft)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--error)', fontFamily: 'var(--font-mono)' }}>Scan failed</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 4, wordBreak: 'break-word' }}>{scanError}</div>
            </div>
            <button className="btn btn-primary" onClick={scan} disabled={loading} style={{ flexShrink: 0 }}>
              {loading ? 'Scanning...' : 'Rescan'}
            </button>
          </div>
        </div>
      )}

      <div className="ac-grid">
        {AC_DEFINITIONS.map(ac => {
          if (loading && !status) {
            return (
              <div key={ac.id} className="ac-card">
                <div className="skeleton" style={{ height: 12, width: 120, marginBottom: 10 }} />
                <div className="skeleton" style={{ height: 10, width: 80, marginBottom: 8 }} />
                <div className="skeleton" style={{ height: 10, width: 140 }} />
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>Scanning...</div>
              </div>
            );
          }
          const info = status?.[ac.id] || { running: false, driver_loaded: false, service_status: 'NOT_FOUND' };
          const isScanningState = !status && !scanError;
          return (
            <div key={ac.id} className={`ac-card ${info.running ? 'running' : ''}`} style={{ '--ac-color': ac.color }}>
              <div className="ac-card-name" style={{ fontWeight: 600, letterSpacing: -0.01 }}>{ac.name}</div>
              <div className="ac-card-status">
                <span className={`dot ${info.running ? 'running' : 'stopped'}`} aria-label={info.running ? 'active' : 'not found'} role="img" />
                <span style={{ color: info.running ? '#7EFF3F' : 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 0.8, fontWeight: 700, textTransform: 'uppercase', textShadow: info.running ? '0 0 6px rgba(126,255,63,0.28)' : 'none' }}>
                  {isScanningState ? 'Scanning...' : info.running ? 'ACTIVE' : 'Not Found'}
                </span>
              </div>
              <div className="ac-card-status">
                <span style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  Driver: {isScanningState ? '—' : info.driver_loaded ? 'Loaded' : 'Not loaded'}
                </span>
              </div>
              <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>
                Services: {ac.services.join(', ')}
              </div>
            </div>
          );
        })}
      </div>

      <style>{`.ac-recommendations-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:640px){.ac-recommendations-grid{grid-template-columns:1fr}}`}</style>
      <div className="ac-recommendations-grid">
        <div className="ac-recommendation">
          <div className="ac-recommendation-title">Recommended Stealth Level</div>
          <div className="ac-recommendation-level" style={{ color: recommendation.color, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>
            {recommendation.level}
          </div>
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5, fontFamily: 'var(--font-mono)' }}>
            {recommendation.desc}
          </div>
        </div>

        <div className="ac-recommendation">
          <div className="ac-recommendation-title">Detected Threats</div>
          {status ? (
            (() => {
              const active = AC_DEFINITIONS.filter(ac => status[ac.id]?.running);
              return active.length === 0 ? (
                <div style={{ color: 'var(--success)', fontSize: 12, fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                  No active anti-cheat detected
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {active.map(ac => (
                    <div key={ac.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: ac.color, flexShrink: 0 }} aria-label="detected" role="img" />
                      <span style={{ color: 'var(--text-secondary)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>{ac.name}</span>
                    </div>
                  ))}
                </div>
              );
            })()
          ) : scanError ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>Scan failed — see above.</div>
          ) : (
            <div style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>Scanning...</div>
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
