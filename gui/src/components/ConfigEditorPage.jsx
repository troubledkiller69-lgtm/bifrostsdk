import React, { useState } from 'react';

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

  const saveConfig = () => {
    try {
      const parsed = JSON.parse(configStr);
      localStorage.setItem('bifrost_engine_config', JSON.stringify(parsed));
      setStatus('Config saved successfully!');
      setTimeout(() => setStatus(''), 2000);
    } catch (e) {
      setStatus('Invalid JSON format!');
    }
  };

  return (
    <>
      <div className="page-header">
        <div className="page-title">Configuration Editor</div>
        <div className="page-subtitle">Dynamically update memory offset patterns without modifying Python code</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100% - 100px)' }}>
        <textarea
          className="input-field"
          style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: 13, resize: 'none', padding: 16 }}
          value={configStr}
          onChange={(e) => setConfigStr(e.target.value)}
        />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 16 }}>
          <span style={{ color: status.includes('Invalid') ? 'var(--shatter-red)' : 'var(--shatter-green)' }}>
            {status}
          </span>
          <button className="btn btn-primary" onClick={saveConfig}>
            Save Configuration
          </button>
        </div>
      </div>
    </>
  );
}
