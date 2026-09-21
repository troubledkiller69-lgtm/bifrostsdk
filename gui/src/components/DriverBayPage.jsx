import React, { useState, useEffect, useCallback } from 'react';

function fmtHash(h) { return h ? h.slice(0,16)+'…' : '—'; }

export default function DriverBayPage({ driverKey, setDriverKey, stealth, setStealth }) {
  const [drivers, setDrivers] = useState(null);
  const [error, setError] = useState('');
  const [testing, setTesting] = useState(null);
  const [results, setResults] = useState({});
  const api = window.bifrost;

  const load = useCallback(async () => {
    if (!api) { setError('Bridge unavailable'); return; }
    setError('');
    try {
      const res = await api.command('driver_list', {});
      const payload = res?.type === 'result' ? res.data : res;
      if (payload?.error) { setError(payload.error); setDrivers(null); return; }
      setDrivers(payload?.drivers || []);
    } catch (e) { setError(e?.message || String(e)); }
  }, [api]);

  useEffect(() => { load(); }, [load]);

  const test = async (key, force=false) => {
    if (!api) return;
    setTesting(key);
    try {
      const res = await api.command('driver_test', { driver: key, force });
      const p = res?.type === 'result' ? res.data : res;
      setResults(prev => ({ ...prev, [key]: p }));
      if (p?.success) {
        window.bifrost?.toast && window.bifrost.toast(`${key} — probe ${p.stage}`, 'success');
      } else {
        window.bifrost?.toast && window.bifrost.toast(`${key}: ${p?.error || p?.code || 'failed'}`, 'error');
      }
    } catch (e) { setResults(prev => ({ ...prev, [key]: { error: String(e), code: 'EXCEPTION' } })); }
    setTesting(null);
  };

  const presentCount = drivers ? drivers.filter(d=>d.present).length : 0;
  const byoCount = drivers ? drivers.filter(d=>d.byo).length : 0;
  const loadedCount = drivers ? drivers.filter(d=>d.loaded===true).length : 0;
  const activeDriver = drivers?.find(d=>d.key===driverKey) || null;

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Driver Bay</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: drivers ? '#7EFF3F' : 'var(--text-ghost)', letterSpacing: '0.08em' }}>● {presentCount}/{drivers?.length||0} PRESENT{byoCount?` · ${byoCount} BYO`:''}{loadedCount?` · ${loadedCount} LOADED`:''}</span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Bring your own vulnerable driver — drop .sys + .json into <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)' }}>drivers/byo/</span> and test here. Stealth `driver`/`cr3` will pick it up.</div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center', background: '#0a0a0c', border: '1px solid rgba(255,255,255,0.08)', borderTop: '1px solid rgba(255,255,255,0.12)', borderRadius: 5, padding: '8px 10px', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.08)' }}>
        <button className="btn btn-secondary" onClick={load} style={{ fontSize: 11 }}>Refresh</button>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{drivers ? `${drivers.length} profiles scanned` : 'loading…'} {activeDriver ? <span style={{ color: '#7EFF3F' }}>· active: {activeDriver.key}</span> : <span style={{ color: 'var(--text-ghost)' }}>· no driver selected</span>}</div>
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={() => window.bifrost?.copyWithToast && window.bifrost.copyWithToast('drivers/byo/example_generic_bulk.json', 'Template path copied')} style={{ fontSize: 11 }}>Copy template path</button>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)' }}>Admin + SeLoadDriverPrivilege required for Test</span>
      </div>
      {(stealth === 'driver' || stealth === 'cr3') && activeDriver && (
        <div style={{ marginBottom: 12, padding: '8px 12px', borderRadius: 5, background: 'rgba(126,255,63,0.08)', border: '1px solid rgba(126,255,63,0.22)', fontFamily: 'var(--font-mono)', fontSize: 11, color: '#7EFF3F' }}>
          Dump will use <span style={{ color: '#f8fafc' }}>{stealth} → {activeDriver.key} ({activeDriver.device_path})</span> — change stealth in the sidebar if you want direct/hijack.
        </div>
      )}

      {error && <div style={{ background: 'var(--error-soft)', border: '1px solid rgba(217,74,74,0.22)', borderRadius: 5, padding: '8px 12px', color: 'var(--error)', fontFamily: 'var(--font-mono)', fontSize: 11, marginBottom: 12 }}>{error}</div>}

      {!drivers ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>{Array.from({length:4}).map((_,i)=>(<div key={i} className="skeleton-row" style={{ padding: '10px 12px' }}><div className="skeleton skeleton-cell" style={{width:80,height:10}}/><div className="skeleton skeleton-cell" style={{flex:1,height:10}}/></div>))}</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(340px,1fr))', gap: 12 }}>
          {drivers.map(d => {
            const r = results[d.key];
            const isTesting = testing === d.key;
            const hashBadge = d.known_hashes?.length ? (d.hash_ok===true ? 'ok' : d.hash_ok===false ? 'mismatch' : 'no file') : 'no hashes';
            const hashColor = d.hash_ok===true ? '#7EFF3F' : d.hash_ok===false ? '#d94a4a' : 'var(--text-ghost)';
            return (
              <div key={d.key} style={{ background: '#0a0a0c', border: `1px solid ${d.present ? (d.byo ? 'rgba(126,255,63,0.22)' : 'rgba(255,255,255,0.08)') : 'rgba(217,74,74,0.18)'}`, borderTop: `1px solid ${d.present ? (d.byo ? 'rgba(126,255,63,0.32)' : 'rgba(255,255,255,0.12)') : 'rgba(217,74,74,0.22)'}`, borderRadius: 5, padding: 12, boxShadow: d.byo && d.present ? 'inset 0 1px 0 rgba(255,255,255,0.08), 0 0 8px rgba(126,255,63,0.08)' : 'inset 0 1px 0 rgba(255,255,255,0.08)', position: 'relative' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontFamily: 'var(--font-display)', fontWeight: 700, fontSize: 13, color: d.present ? '#f8fafc' : 'var(--text-muted)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>{d.key}</span>
                  {d.byo && <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: 'rgba(126,255,63,0.14)', color: '#7EFF3F', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.06em' }}>BYO</span>}
                  {d.loaded===true && <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 3, background: 'rgba(126,255,63,0.16)', color: '#7EFF3F', fontFamily: 'var(--font-mono)', fontWeight: 700, letterSpacing: '0.06em', boxShadow: '0 0 6px rgba(126,255,63,0.35)' }} title="Service is currently running in SCM — a previous Test Load or dump left it mapped">LOADED</span>}
                  <span style={{ marginLeft: 'auto', width: 7, height: 7, borderRadius: '50%', background: d.present ? '#7EFF3F' : '#d94a4a', boxShadow: d.present ? '0 0 6px rgba(126,255,63,0.45)' : 'none', flexShrink:0 }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: d.present ? 'var(--text-muted)' : '#d94a4a', letterSpacing: '0.04em' }}>{d.present ? 'PRESENT' : 'MISSING'}</span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={d.filename}>{d.filename} → <span style={{ color: 'var(--text-muted)' }}>{d.device_path}</span></div>
                {d.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.4, marginBottom: 8 }}>{d.description}</div>}
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                  <span className="engine-card-tag" style={{ background: d.byo ? 'rgba(126,255,63,0.10)' : 'var(--bg-elevated)', color: d.byo ? '#7EFF3F' : 'var(--text-muted)', borderColor: d.byo ? 'rgba(126,255,63,0.22)' : 'rgba(255,255,255,0.08)' }}>{d.strategy}</span>
                  <span className="engine-card-tag" style={{ background: hashBadge==='ok' ? 'rgba(126,255,63,0.10)' : hashBadge==='mismatch' ? 'var(--error-soft)' : 'var(--bg-elevated)', color: hashColor, borderColor: hashBadge==='mismatch' ? 'rgba(217,74,74,0.22)' : 'rgba(255,255,255,0.08)' }}>{hashBadge} {d.hash_actual || ''}</span>
                  <span className="engine-card-tag" style={{ background: 'var(--bg-elevated)', color: 'var(--text-ghost)' }}>{d.ioctl_read} / {d.ioctl_write}</span>
                </div>
                {d.present && d.present_path && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)', marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={d.present_path}>{d.present_path}</div>}
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <button className="btn btn-secondary" style={{ flex: 1, fontSize: 11, padding: '6px 8px' }} onClick={() => test(d.key, false)} disabled={isTesting || !d.present}>{isTesting ? 'Testing…' : 'Test Load'}</button>
                  <button className="btn" style={{ fontSize: 11, padding: '6px 8px' }} onClick={() => test(d.key, true)} disabled={isTesting || !d.present} title="Skip hash mismatch">Force</button>
                  <button className={`btn ${driverKey===d.key ? 'btn-primary' : ''}`} style={{ fontSize: 11, padding: '6px 8px' }} onClick={() => { setDriverKey && setDriverKey(d.key); if (stealth!=='driver' && stealth!=='cr3') setStealth && setStealth('driver'); window.bifrost?.toast && window.bifrost.toast(`Driver ${d.key} selected for next dump`, 'success'); }} disabled={!d.present} title="Use for next driver/cr3 dump">{driverKey===d.key ? 'Selected' : 'Use'}</button>
                  <button className="btn" style={{ fontSize: 11, padding: '6px 8px' }} onClick={() => window.bifrost?.copyWithToast && window.bifrost.copyWithToast(d.device_path, 'Device path copied')} title="Copy device path">Copy</button>
                </div>
                {r && (
                  <div style={{ marginTop: 8, padding: '6px 8px', borderRadius: 3, background: r.success ? 'rgba(126,255,63,0.08)' : 'var(--error-soft)', border: `1px solid ${r.success ? 'rgba(126,255,63,0.18)' : 'rgba(217,74,74,0.22)'}`, fontFamily: 'var(--font-mono)', fontSize: 11, color: r.success ? '#7EFF3F' : 'var(--error)', wordBreak: 'break-word' }}>
                    {r.success ? `✓ ${r.stage} — ${r.device} — ${r.probe || ''}` : `${r.code || 'ERR'}: ${r.error || ''} ${r.stage ? `(${r.stage})` : ''}`}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div className="page-config-card" style={{ marginTop: 16, padding: 12 }}>
        <div className="page-config-title" style={{ marginBottom: 8 }}>How to bring your own</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
          1. Drop <span style={{ color: 'var(--text-secondary)' }}>.sys</span> into <span style={{ color: '#7EFF3F' }}>drivers/byo/</span> (or <span style={{ color: 'var(--text-secondary)' }}>drivers/</span>).<br/>
          2. Copy <span style={{ color: 'var(--text-secondary)' }}>example_generic_bulk.json</span> → <span style={{ color: 'var(--text-secondary)' }}>myvuln.json</span>, fill <span style={{ color: 'var(--text-secondary)' }}>service_name / device_path / ioctls / strategy</span>.<br/>
          3. Hit <span style={{ color: 'var(--text-secondary)' }}>Refresh</span> here — your key appears as <span style={{ color: '#7EFF3F' }}>BYO</span>. Then <span style={{ color: 'var(--text-secondary)' }}>Test Load</span> (needs Admin). A probe read at 0x1000 proves the IOCTL path.<br/>
          4. Use it: `Dump → stealth: driver → myvuln` or `Settings → Default Stealth → Driver (myvuln)`. Hash failures → <span style={{ color: 'var(--text-secondary)' }}>Force</span> for dev.<br/>
          <span style={{ color: 'var(--text-ghost)' }}>Staging is `%TEMP%\\wdf*.sys` with randomized service `MyVulnDrv abcd` — deleted on unload, no traces.</span>
        </div>
      </div>
    </>
  );
}
