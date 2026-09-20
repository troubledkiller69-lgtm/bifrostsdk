import React, { useState, useEffect, useMemo } from 'react';
import logo from '../assets/logo.png';

const DEFAULTS = {
  outputDir: 'C:\\BifrostProjects',
  defaultStealth: 'auto',
  defaultEngine: 'auto',
  defaultAnalyzerEngine: 'auto',
  autoNavigate: true,
  autoExportFormat: 'json',
  logLevel: 'info',
  analyzerCache: 400,
  recentLimit: 10,
  discordWebhook: '',
  telemetry: true,
  compactTables: false,
  fontScale: 100,
};

function isValidUrl(v) {
  if (!v) return true;
  try { const u = new URL(v); return u.protocol === 'http:' || u.protocol === 'https:'; } catch { return false; }
}

function loadSettings() {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem('bifrost_settings') || '{}') };
  } catch {
    return { ...DEFAULTS };
  }
}

function saveSettings(settings) {
  localStorage.setItem('bifrost_settings', JSON.stringify(settings));
}

export default function SettingsPage({ theme = 'midnight', setTheme }) {
  const [settings, setSettings] = useState(loadSettings);
  const [saved, setSaved] = useState(false);
  const [webhookStatus, setWebhookStatus] = useState(null);
  const [webhookError, setWebhookError] = useState(null);
  const [bridgeInfo, setBridgeInfo] = useState(null);

  const webhookValid = useMemo(() => isValidUrl(settings.discordWebhook.trim()), [settings.discordWebhook]);

  useEffect(() => {
    (async () => {
      try {
        const api = window.bifrost;
        if (!api?.command) return;
        const res = await api.command('bridge_info', {});
        if (res?.data) setBridgeInfo(res.data);
      } catch {
        setBridgeInfo({ build_stamp: 'unavailable' });
      }
    })();
  }, []);

  const update = (key, value) => {
    setSettings(prev => {
      const next = { ...prev, [key]: value };
      saveSettings(next);
      return next;
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  };

  const handleReset = () => {
    const doReset = () => {
      localStorage.clear();
      setSettings({ ...DEFAULTS });
      setSaved(true);
      if (window.bifrost?.toast) window.bifrost.toast('Settings reset', 'success');
      setTimeout(() => setSaved(false), 1500);
    };
    if (window.bifrost?.confirmDestructive) {
      window.bifrost.confirmDestructive({
        title: 'Reset all settings?',
        body: 'This will wipe all local settings and engine configs',
        confirmLabel: 'Reset',
        onConfirm: doReset,
      });
    } else if (window.confirm('This will wipe all local settings and engine configs. Continue?')) {
      doReset();
    }
  };

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <div className="page-title">Settings</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.12em', textTransform: 'uppercase', color: saved ? '#7EFF3F' : 'var(--text-ghost)', transition: 'color 120ms' }}>
          {saved ? '● Saved' : 'Garage config'}
        </span>
      </div>
      <div className="page-subtitle" style={{ marginTop: -12, marginBottom: 14, fontFamily: 'var(--font-mono)', fontSize: 11, color: '#64748b' }}>
        Tune the bay — deck presets, outputs, webhook ping
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, maxWidth: 760 }}>

        {/* General — deck plate */}
        <div className="settings-section" style={{ borderLeft: '2px solid rgba(255,255,255,0.06)' }}>
          <div className="settings-section-title" style={{ fontFamily: 'var(--font-display)', letterSpacing: '0.10em' }}>General</div>

          {/* Theme deck — 4 preset buttons like FM 1-4, no pill */}
          <div className="settings-row" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
            <div className="settings-label">
              Theme
              <small>Garage lime is the only live preset — others alias to it</small>
            </div>
            <div role="radiogroup" aria-label="Theme" style={{ display: 'flex', gap: 6, background: '#050507', border: '1px solid rgba(0,0,0,0.6)', borderRadius: 3, padding: 4, boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6), inset -1px -1px 0 rgba(255,255,255,0.04)' }}>
              {[
                { id: 'midnight', label: 'Midnight' },
                { id: 'paper', label: 'Paper' },
                { id: 'terminal', label: 'Terminal' },
                { id: 'alexandria-2000', label: 'Garage' },
              ].map(opt => {
                const active = theme === opt.id;
                return (
                  <button
                    key={opt.id}
                    role="radio"
                    aria-checked={active}
                    onClick={() => setTheme(opt.id)}
                    style={{
                      padding: '6px 12px',
                      borderRadius: 3,
                      border: active ? '1px solid rgba(126,255,63,0.42)' : '1px solid transparent',
                      borderTopColor: active ? 'rgba(126,255,63,0.55)' : 'transparent',
                      background: active ? '#0a0a0c' : 'transparent',
                      color: active ? '#7EFF3F' : 'var(--text-muted)',
                      fontSize: 11,
                      fontWeight: 700,
                      fontFamily: 'var(--font-display)',
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                      cursor: 'pointer',
                      boxShadow: active ? 'inset 0 1px 0 rgba(255,255,255,0.06), 0 0 8px rgba(126,255,63,0.14)' : 'none',
                      textShadow: active ? '0 0 6px rgba(126,255,63,0.38)' : 'none',
                      transition: 'all 120ms ease'
                    }}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Output Directory
              <small>Where dumps and generated projects are saved</small>
            </div>
            <input
              className="input-field"
              style={{ width: 260, fontSize: 12 }}
              value={settings.outputDir}
              onChange={(e) => update('outputDir', e.target.value)}
            />
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Default Stealth Mode
              <small>Applied when starting a new session</small>
            </div>
            <select
              className="input-field"
              style={{ width: 180, fontSize: 12 }}
              value={settings.defaultStealth}
              onChange={(e) => update('defaultStealth', e.target.value)}
            >
              <option value="auto">Auto (Direct)</option>
              <option value="direct">Direct</option>
              <option value="hijack">Handle Hijack</option>
              <option value="driver">Kernel Driver</option>
              <option value="cr3">CR3 Bypass</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Auto-Navigate on Dump Complete
              <small>Switch to Results when dump finishes</small>
            </div>
            <button
              className={`settings-toggle ${settings.autoNavigate ? 'on' : ''}`}
              onClick={() => update('autoNavigate', !settings.autoNavigate)}
              role="switch"
              aria-checked={settings.autoNavigate}
              aria-label="Auto-navigate on dump complete"
            />
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Default Analyzer Engine
              <small>Analyzer deck — rizin / ida / iced fallback chain</small>
            </div>
            <select className="input-field" style={{ width: 180, fontSize: 12 }} value={settings.defaultAnalyzerEngine} onChange={(e) => update('defaultAnalyzerEngine', e.target.value)}>
              <option value="auto">Auto (rizin → IDA → iced)</option>
              <option value="rizin">Rizin-ghidra</option>
              <option value="ida">IDA (licensed)</option>
              <option value="iced">Iced (fallback)</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Auto-Export Format
              <small>Results quick-export default</small>
            </div>
            <select className="input-field" style={{ width: 180, fontSize: 12 }} value={settings.autoExportFormat} onChange={(e) => update('autoExportFormat', e.target.value)}>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
              <option value="cpp">C++ header (.h)</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Analyzer Cache
              <small>Top-N functions per auto-analysis</small>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input className="input-field" style={{ width: 90, textAlign: 'center', fontSize: 12 }} type="number" min={50} max={2000} step={50} value={settings.analyzerCache} onChange={(e) => update('analyzerCache', Math.max(50, Math.min(2000, parseInt(e.target.value) || 400)))} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-ghost)' }}>FUNCS</span>
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Log Level
              <small>Console + file sink — verbose helps with offsets</small>
            </div>
            <select className="input-field" style={{ width: 180, fontSize: 12 }} value={settings.logLevel} onChange={(e) => update('logLevel', e.target.value)}>
              <option value="error">Error</option>
              <option value="warn">Warn</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </select>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Telemetry · Compact Tables · Font Scale
              <small>Diagnostics ring + density for garage monitors</small>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                <button className={`settings-toggle ${settings.telemetry ? 'on' : ''}`} onClick={() => update('telemetry', !settings.telemetry)} role="switch" aria-checked={settings.telemetry} /> Tel
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                <button className={`settings-toggle ${settings.compactTables ? 'on' : ''}`} onClick={() => update('compactTables', !settings.compactTables)} role="switch" aria-checked={settings.compactTables} /> Compact
              </label>
              <select className="input-field" style={{ width: 90, fontSize: 12 }} value={settings.fontScale} onChange={(e) => update('fontScale', parseInt(e.target.value))}>
                <option value={90}>90%</option>
                <option value={100}>100%</option>
                <option value={110}>110%</option>
                <option value={115}>115%</option>
              </select>
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-label">
              Recent Limit
              <small>Recent dumps kept in quick-jump</small>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input className="input-field" style={{ width: 90, textAlign: 'center', fontSize: 12 }} type="number" min={3} max={30} value={settings.recentLimit} onChange={(e) => update('recentLimit', Math.max(3, Math.min(30, parseInt(e.target.value) || 10)))} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-ghost)' }}>ITEMS</span>
            </div>
          </div>

          <div className="settings-row" style={{ borderBottom: 'none' }}>
            <div className="settings-label">
              Bridge Timeout
              <small>Fixed 15s default; decompile_fn extended to 120s</small>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input className="input-field" style={{ width: 74, textAlign: 'center', color: 'var(--text-ghost)' }} type="number" value={15} disabled />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-ghost)', letterSpacing: '0.04em' }}>SEC</span>
            </div>
          </div>
        </div>

        {/* Integrations — compact */}
        <div className="settings-section">
          <div className="settings-section-title" style={{ fontFamily: 'var(--font-display)', letterSpacing: '0.10em' }}>Integrations</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="settings-label">
              Discord Webhook
              <small>Get notified when dumps complete</small>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className="input-field"
                style={{ flex: 1, fontSize: 12, borderColor: !webhookValid ? 'rgba(217,74,74,0.45)' : undefined }}
                placeholder="https://discord.com/api/webhooks/..."
                value={settings.discordWebhook}
                onChange={(e) => update('discordWebhook', e.target.value)}
                aria-invalid={!webhookValid}
              />
              <button
                className="btn btn-primary"
                style={{ whiteSpace: 'nowrap', fontSize: 11, padding: '7px 14px', height: 34 }}
                disabled={!settings.discordWebhook || webhookStatus === 'testing'}
                onClick={async () => {
                  setWebhookStatus('testing');
                  setWebhookError(null);
                  try {
                    const api = window.bifrost;
                    if (!api?.command) {
                      setWebhookStatus('error');
                      setWebhookError('IPC bridge unavailable');
                    } else {
                      const res = await api.command('test_webhook', { url: settings.discordWebhook.trim() });
                      const ok = res?.data?.success === true;
                      const err = res?.data?.error || res?.error;
                      setWebhookStatus(ok ? 'ok' : 'error');
                      if (!ok && err) setWebhookError(err);
                    }
                  } catch (e) {
                    setWebhookStatus('error');
                    setWebhookError(e?.message || String(e));
                  }
                  setTimeout(() => { setWebhookStatus(null); setWebhookError(null); }, 6000);
                }}
              >
                {webhookStatus === 'testing' ? 'Sending…' : 'Test'}
              </button>
            </div>
            {!webhookValid && settings.discordWebhook && (
              <small role="alert" style={{ color: 'var(--error)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Invalid URL — must start with https://</small>
            )}
            {webhookStatus === 'ok' && <small style={{ color: '#7EFF3F', fontFamily: 'var(--font-mono)', fontSize: 11, textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>Webhook sent.</small>}
            {webhookStatus === 'error' && <small style={{ color: 'var(--error)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{webhookError || 'Webhook failed.'}</small>}
          </div>
        </div>

        {/* About + Danger in one row on desktop */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div className="settings-section" style={{ padding: 14 }}>
            <div className="settings-section-title" style={{ fontFamily: 'var(--font-display)', letterSpacing: '0.10em' }}>About</div>
            <div style={{ background: '#030303', border: '1px solid rgba(0,0,0,0.6)', borderRadius: 3, boxShadow: 'inset 1px 1px 0 rgba(0,0,0,0.6), inset -1px -1px 0 rgba(255,255,255,0.04)', padding: '10px', display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
              <img src={logo} alt="BIFROST" style={{ width: 36, height: 36, objectFit: 'contain', filter: 'brightness(1.6) contrast(1.25)' }} />
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 13, fontWeight: 700, letterSpacing: '0.10em', textTransform: 'uppercase', color: '#f8fafc' }}>BIFROST SDK</div>
              <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: '#7EFF3F', letterSpacing: '0.08em', textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>4.1.0</span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7 }}>
              <div><span style={{ color: 'var(--text-ghost)' }}>Engine</span> Electron + React + Vite</div>
              <div><span style={{ color: 'var(--text-ghost)' }}>Backend</span> Python 3.14 PyInstaller</div>
              <div><span style={{ color: 'var(--text-ghost)' }}>Bridge</span> JSON Lines stdio</div>
              <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--border)', display: 'flex', gap: 6, alignItems: 'center' }}>
                <span style={{ color: 'var(--text-ghost)' }}>Build</span>
                <span style={{ color: '#7EFF3F', textShadow: '0 0 6px rgba(126,255,63,0.28)' }}>{bridgeInfo?.build_stamp || 'loading…'}</span>
              </div>
            </div>
          </div>

          <div className="settings-section" style={{ padding: 14, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', borderColor: 'rgba(217,74,74,0.14)' }}>
            <div>
              <div className="settings-section-title" style={{ fontFamily: 'var(--font-display)', letterSpacing: '0.10em', color: 'var(--error)' }}>Danger Zone</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-ghost)', lineHeight: 1.5, marginBottom: 12 }}>
                Wipe all local prefs and engine configs. No recover.
              </div>
            </div>
            <button className="btn" onClick={handleReset} style={{ alignSelf: 'flex-start', borderColor: 'rgba(217,74,74,0.22)', color: 'var(--error)', fontFamily: 'var(--font-display)' }}>
              Reset All Settings
            </button>
          </div>
        </div>

      </div>

      <style>{`@media (max-width: 760px) { div[style*="gridTemplateColumns: '1fr 1fr'"] { grid-template-columns: 1fr !important; } }`}</style>
    </>
  );
}
