import React from 'react';
import logo from '../assets/logo.png';

const STEALTH_MODES = ['auto', 'extreme', 'driver', 'hijack', 'direct'];
const STEALTH_LABELS = {
  auto: 'Auto',
  extreme: 'CR3 Bypass',
  driver: 'Kernel Driver',
  hijack: 'Handle Hijack',
  direct: 'Direct',
};

const NAV_ITEMS = [
  { key: 'engines', label: 'Engines', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  )},
  { key: 'processes', label: 'Processes', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="3" />
      <path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83" />
    </svg>
  )},
  { key: 'dump', label: 'Dump', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="22,12 18,12 15,21 9,3 6,12 2,12" />
    </svg>
  )},
  { key: 'results', label: 'Results', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
    </svg>
  )},
  { key: 'spoofer', label: 'Spoofer', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  )},
  { key: 'boilerplate', label: 'C++ Boilerplate', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  )},
  { key: 'hunter', label: 'Driver Hunter', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  )},
  { type: 'separator', label: 'Tools' },
  { key: 'diff', label: 'Diff Viewer', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3v18M3 12h18" />
      <path d="M8 8l-4 4 4 4" />
      <path d="M16 8l4 4-4 4" />
    </svg>
  )},
  { key: 'memory', label: 'Memory Viewer', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="2" y="6" width="20" height="12" rx="2" />
      <path d="M6 6V4M10 6V4M14 6V4M18 6V4M6 18v2M10 18v2M14 18v2M18 18v2" />
    </svg>
  )},
  { key: 'acmonitor', label: 'AC Monitor', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <circle cx="12" cy="16" r="0.5" fill="currentColor" />
    </svg>
  )},
  { key: 'config', label: 'Config Editor', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
    </svg>
  )},
  { key: 'settings', label: 'Settings', icon: (
    <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  )},
];

export default function Sidebar({ page, setPage, stealth, setStealth, bridgeStatus, open, onClose }) {
  const cycleStealth = () => {
    const idx = STEALTH_MODES.indexOf(stealth);
    setStealth(STEALTH_MODES[(idx + 1) % STEALTH_MODES.length]);
  };

  const navigate = (key) => {
    setPage(key);
    onClose();
  };

  return (
    <>
      {/* Overlay backdrop */}
      <div
        className={`sidebar-overlay ${open ? 'visible' : ''}`}
        onClick={onClose}
      />

      {/* Drawer */}
      <div className={`sidebar-drawer ${open ? 'open' : ''}`}>

        {/* Drawer header */}
        <div className="sidebar-drawer-header">
          <div className="sidebar-drawer-brand">
            <img src={logo} alt="" className="sidebar-drawer-logo" />
            <span className="sidebar-drawer-title">BIFROST SDK</span>
          </div>
          <button className="sidebar-close-btn" onClick={onClose}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Nav items */}
        <div className="sidebar-nav">
          {NAV_ITEMS.map((item, i) => {
            if (item.type === 'separator') {
              return (
                <div key={`sep-${i}`} className="sidebar-section" style={{ marginTop: 8 }}>
                  <div className="sidebar-label">{item.label}</div>
                </div>
              );
            }
            return (
              <div
                key={item.key}
                className={`sidebar-item ${page === item.key ? 'active' : ''}`}
                onClick={() => navigate(item.key)}
              >
                {item.icon}
                {item.label}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="sidebar-footer">
          <div className="bridge-status" title={`Bridge: ${bridgeStatus || 'unknown'}`}>
            <span className={`bridge-dot ${bridgeStatus === 'ok' ? 'connected' : 'disconnected'}`} />
            <span className="bridge-label">
              {bridgeStatus === 'ok' ? 'Bridge Connected' : bridgeStatus === 'error' ? 'Bridge Offline' : 'Checking...'}
            </span>
          </div>
          <div className="stealth-badge" onClick={cycleStealth} title="Click to cycle stealth mode">
            <span className={`stealth-dot ${stealth}`} />
            <span className="stealth-label">{STEALTH_LABELS[stealth]}</span>
          </div>
        </div>
      </div>
    </>
  );
}
