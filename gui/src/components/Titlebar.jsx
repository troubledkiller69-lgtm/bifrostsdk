import React from 'react';
import logo from '../assets/logo.png';

export default function Titlebar({ onMenuToggle }) {
  const api = window.bifrost;

  return (
    <div className="titlebar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button className="titlebar-menu-btn" onClick={onMenuToggle} title="Menu">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="3" y1="6" x2="21" y2="6" />
            <line x1="3" y1="12" x2="21" y2="12" />
            <line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
        <div className="titlebar-brand">
          <img src={logo} alt="" className="titlebar-logo" />
          BIFROST SDK
        </div>
      </div>
      <div className="titlebar-controls">
        <button className="titlebar-btn" onClick={() => api?.minimize()}>&#x2013;</button>
        <button className="titlebar-btn" onClick={() => api?.maximize()}>&#x25A1;</button>
        <button className="titlebar-btn close" onClick={() => api?.close()}>&#x2715;</button>
      </div>
    </div>
  );
}
