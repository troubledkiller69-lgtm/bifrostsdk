import React, { useState, useEffect } from 'react';
import logo from '../assets/logo.png';

const DEFAULTS = {
  outputDir: 'C:\\BifrostProjects',
  defaultStealth: 'auto',
  autoNavigate: true,
  discordWebhook: '',
};


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

export default function SettingsPage() {
  const [settings, setSettings] = useState(loadSettings);
  const [saved, setSaved] = useState(false);
  const [webhookStatus, setWebhookStatus] = useState(null);
  const [webhookError, setWebhookError] = useState(null);
  const [bridgeInfo, setBridgeInfo] = useState(null);

  // Fetch the live backend build stamp once on mount.
  // If this shows "unknown" or never resolves, the Python subprocess is dead
  // or running pre-bridge_info code → user needs to restart the app.
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

  return (
    <>
      <div className="page-header">
        <div className="page-title">Settings</div>
        <div className="page-subtitle">
          Configure BIFROST preferences
          {saved && <span style={{ marginLeft: 12, color: 'var(--success)', fontSize: 11, fontWeight: 600 }}>Saved</span>}
        </div>
      </div>

      <div className="settings-grid">
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* General */}
          <div className="settings-section">
            <div className="settings-section-title">General</div>

            <div className="settings-row">
              <div className="settings-label">
                Output Directory
                <small>Where dumps and generated projects are saved</small>
              </div>
              <input
                className="input-field"
                style={{ width: 220 }}
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
                style={{ width: 160 }}
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
                <small>Switch to Results page when a dump finishes</small>
              </div>
              <button
                className={`settings-toggle ${settings.autoNavigate ? 'on' : ''}`}
                onClick={() => update('autoNavigate', !settings.autoNavigate)}
              />
            </div>

            <div className="settings-row">
              <div className="settings-label">
                Bridge Timeout (seconds)
                <small>Max wait time for Python backend responses</small>
              </div>
              <input
                className="input-field"
                style={{ width: 80 }}
                type="number"
                value={15}
                disabled
              />
              <small style={{ color: 'var(--text-muted)' }}>Fixed 15s default; decompile_fn extended to 120s</small>
            </div>
          </div>
        </div>

        {/* Right column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Integrations */}
          <div className="settings-section">
            <div className="settings-section-title">Integrations</div>

            <div className="settings-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
              <div className="settings-label">
                Discord Webhook
                <small>Get notified when dumps complete</small>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input
                  className="input-field"
                  style={{ flex: 1 }}
                  placeholder="https://discord.com/api/webhooks/..."
                  value={settings.discordWebhook}
                  onChange={(e) => update('discordWebhook', e.target.value)}
                />
                <button
                  className="btn btn-primary"
                  style={{ whiteSpace: 'nowrap', fontSize: 11, padding: '6px 12px' }}
                  disabled={!settings.discordWebhook || webhookStatus === 'testing'}
                  onClick={async () => {
                    setWebhookStatus('testing');
                    setWebhookError(null);
                    // Route through the SAME Python sender used on dump complete.
                    // This guarantees a green Test == a green production send.
                    try {
                      const api = window.bifrost;
                      if (!api?.command) {
                        setWebhookStatus('error');
                        setWebhookError('IPC bridge unavailable');
                      } else {
                        const res = await api.command('test_webhook', {
                          url: settings.discordWebhook.trim(),
                        });
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
                  {webhookStatus === 'testing' ? 'Sending...' : 'Test'}
                </button>
              </div>
              {webhookStatus === 'ok' && (
                <small style={{ color: 'var(--success)', marginTop: 4 }}>Webhook sent successfully!</small>
              )}
              {webhookStatus === 'error' && (
                <small style={{
                  color: 'var(--error)', marginTop: 4, display: 'block',
                  lineHeight: 1.5, wordBreak: 'break-word',
                }}>
                  {webhookError || 'Webhook failed. Check URL.'}
                </small>
              )}
            </div>
          </div>

          {/* About */}
          <div className="settings-section">
            <div className="settings-section-title">About</div>
            <div className="settings-about-logo-wrap">
              <img src={logo} alt="BIFROST" className="settings-about-logo" />
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.8 }}>
              <div><span style={{ color: 'var(--text-ghost)' }}>Version:</span> 4.0.0</div>
              <div><span style={{ color: 'var(--text-ghost)' }}>Engine:</span> Electron + React + Vite</div>
              <div><span style={{ color: 'var(--text-ghost)' }}>Backend:</span> Python 3.10+ (PyInstaller)</div>
              <div><span style={{ color: 'var(--text-ghost)' }}>Bridge:</span> JSON Lines over stdio</div>
              <div><span style={{ color: 'var(--text-ghost)' }}>Theme:</span> Black Ice</div>
              <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--border)' }}>
                <span style={{ color: 'var(--text-ghost)' }}>Backend build:</span>{' '}
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {bridgeInfo?.build_stamp || 'loading…'}
                </span>
              </div>
              {bridgeInfo?.features && (
                <div style={{ fontSize: 11 }}>
                  <span style={{ color: 'var(--text-ghost)' }}>Features:</span>{' '}
                  {Object.entries(bridgeInfo.features)
                    .filter(([, v]) => v)
                    .map(([k]) => k)
                    .join(', ') || 'none'}
                </div>
              )}
            </div>
          </div>

          {/* Reset */}
          <div className="settings-section">
            <div className="settings-section-title">Danger Zone</div>
            <button
              className="btn btn-danger"
              onClick={() => {
                localStorage.clear();
                setSettings({ ...DEFAULTS });
                setSaved(true);
                setTimeout(() => setSaved(false), 1500);
              }}
            >
              Reset All Settings
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
