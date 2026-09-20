import React, { useState, useMemo } from 'react';

const DEFAULT_CONFIG = {
  offsets: {
    unreal_engine: {
      "GWorld": "48 8B 1D ? ? ? ? 48 85 DB 74 3B 41 B0 01",
      "GNames": "48 8D 05 ? ? ? ? 48 83 C4 28 C3 48 8B C8",
      "GObjects": "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8B 04 D1"
    },
    unity: {
      "GameAssembly": "48 83 EC 28 48 8B 05 ? ? ? ? 48 85 C0 74 3F"
    }
  }
};

function loadConfig() {
  try {
    const data = localStorage.getItem('bifrost_engine_config');
    return data ? JSON.parse(data) : DEFAULT_CONFIG;
  } catch {
    return DEFAULT_CONFIG;
  }
}

export default function ConfigEditorPage() {
  const [configStr, setConfigStr] = useState(() => JSON.stringify(loadConfig(), null, 2));
  const [status, setStatus] = useState('');

  const parseError = useMemo(() => {
    try { JSON.parse(configStr); return null; } catch (e) { return e.message; }
  }, [configStr]);

  const saveConfig = () => {
    try {
      const parsed = JSON.parse(configStr);
      localStorage.setItem('bifrost_engine_config', JSON.stringify(parsed));
      setStatus('Config saved successfully!');
      if (window.bifrost?.toast) window.bifrost.toast('Config saved', 'success');
      setTimeout(() => setStatus(''), 2000);
    } catch (e) {
      setStatus('Invalid JSON format!');
      if (window.bifrost?.toast) window.bifrost.toast('Invalid JSON format', 'error');
    }
  };

  const validateConfig = () => {
    try {
      JSON.parse(configStr);
      setStatus('JSON valid — ready to save');
      if (window.bifrost?.toast) window.bifrost.toast('JSON valid — ready to save', 'success');
      setTimeout(() => setStatus(''), 2000);
    } catch (e) {
      setStatus('Invalid JSON: ' + e.message);
      if (window.bifrost?.toast) window.bifrost.toast('Invalid JSON: ' + e.message, 'error');
    }
  };

  const resetConfig = () => {
    const doReset = () => {
      const def = JSON.stringify(DEFAULT_CONFIG, null, 2);
      setConfigStr(def);
      localStorage.removeItem('bifrost_engine_config');
      setStatus('Reset to defaults');
      if (window.bifrost?.toast) window.bifrost.toast('Reset to defaults', 'success');
      setTimeout(() => setStatus(''), 2000);
    };
    if (window.bifrost?.confirmDestructive) {
      window.bifrost.confirmDestructive({
        title: 'Reset configuration?',
        body: 'This will wipe your custom engine config and restore defaults. This cannot be undone.',
        confirmLabel: 'Reset',
        onConfirm: doReset,
      });
    } else if (window.confirm('Reset configuration to defaults? This will wipe your custom config.')) {
      doReset();
    }
  };

  const handleChange = (e) => {
    setConfigStr(e.target.value);
    // live validation via parseError memo; status cleared on typing unless error persists
    if (status.includes('Invalid')) {
      // keep status until next validate/save but parseError will show inline
    }
  };

  return (
    <>
      <div className="page-header" style={{ display: 'flex', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ width: 3, height: 14, background: '#7EFF3F', boxShadow: '0 0 6px rgba(126,255,63,0.45)', borderRadius: 1, display: 'inline-block' }} />Configuration Editor</div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-ghost)', letterSpacing: '0.08em' }}>● DECK  <span style={{ color: '#7EFF3F' }}>AOB PATTERNS</span></span>
        <div className="page-subtitle" style={{ width: '100%', marginTop: 2 }}>Dynamically update memory offset patterns without modifying Python code — <span style={{ color: 'var(--text-ghost)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>JSON — wildcards ? · deck-preset wells</span></div>
      </div>

      <div className="config-editor-stack">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: 0.3 }}>
            JSON — offsets.unreal_engine / unity — patterns are AOB strings with <span style={{ color: 'var(--text-ghost)' }}>?</span> wildcards
          </div>
          {parseError && (
            <span role="alert" aria-live="polite" style={{ fontSize: 11, color: 'var(--error)', fontFamily: 'var(--font-mono)', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={parseError}>
              Invalid JSON: {parseError}
            </span>
          )}
          {!parseError && (
            <span role="status" aria-live="polite" style={{ fontSize: 11, color: 'var(--success)', fontFamily: 'var(--font-mono)' }}>JSON valid</span>
          )}
        </div>
        <label htmlFor="config-json" style={{ fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: '#f8fafc', fontWeight: 600, textShadow: '0 1px 0 rgba(0,0,0,0.6)' }}>Config JSON</label>
        <textarea
          id="config-json"
          className="input-field config-editor-field"
          value={configStr}
          onChange={handleChange}
          spellCheck={false}
          placeholder='{"offsets": {"unreal_engine": {...}}}'
          aria-invalid={!!parseError}
          aria-describedby={parseError ? 'config-json-error' : undefined}
        />
        {parseError && (
          <div id="config-json-error" role="alert" aria-live="assertive" style={{ fontSize: 11, color: 'var(--error)', fontFamily: 'var(--font-mono)', background: 'var(--error-soft)', border: '1px solid rgba(217,74,74,0.22)', borderRadius: 5, padding: '6px 10px' }}>
            {parseError}
          </div>
        )}
        <div className="config-editor-bar">
          <span className={status.includes('Invalid') ? 'mono-hint error' : status ? 'mono-hint success' : 'mono-hint'} style={{ color: status.includes('Invalid') ? undefined : status ? undefined : 'var(--text-ghost)', fontSize: 11 }}>
            {status || ' '}
          </span>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button className="btn" onClick={validateConfig} style={{ fontSize: 12 }}>
              Validate
            </button>
            <button className="btn btn-danger" onClick={resetConfig} style={{ fontSize: 12 }}>
              Reset
            </button>
            <button className="btn btn-primary" onClick={saveConfig}>
              Save Configuration
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
