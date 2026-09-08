import React, { useState, useEffect, useCallback } from 'react';

/**
 * BridgeStatus — health indicator for the Python bridge + protocol.
 *
 * Health comes from ping only. A failed dump/spoof/analyze is an OPERATION
 * failure — it bumps a transient error pill, it does not brand the bridge
 * degraded. Degraded/offline is reserved for protocol anomalies, a stale
 * backend, or a dead subprocess, and the chip heals itself on the next
 * healthy ping (every 15s), so a single bad job no longer sticks the app
 * in a permanent warning state.
 */
export default function BridgeStatus() {
  const [status, setStatus] = useState('unknown'); // 'ok' | 'degraded' | 'offline' | 'unknown'
  const [protocolVersion, setProtocolVersion] = useState(null);
  const [recentErrors, setRecentErrors] = useState([]); // timestamps

  const api = window.bifrost;

  const bumpError = useCallback(() => {
    const now = Date.now();
    setRecentErrors(prev => [...prev.filter(t => now - t < 20000), now]);
  }, []);

  useEffect(() => {
    if (!api) {
      setStatus('offline');
      return;
    }

    const ping = () => {
      api.command('ping').then((r) => {
        if (r?.error) {
          setStatus('offline');
          return;
        }
        if (r?.status === 'ok') {
          setStatus('ok');
          if (r.protocol_version) setProtocolVersion(r.protocol_version);
        } else {
          setStatus('degraded');
        }
      }).catch(() => setStatus('offline'));
    };
    ping();
    const pingTimer = setInterval(ping, 15000);

    // One terminal error per failed operation (main.js mirrors result
    // errors into the op.error channel exactly once) — count it, don't
    // degrade the bridge over it.
    const unsubs = [];
    const bind = (fn) => {
      if (typeof fn === 'function') {
        const unsub = fn(bumpError);
        if (typeof unsub === 'function') unsubs.push(unsub);
      }
    };
    bind(api.onDumpError);
    bind(api.onSpoofError);
    bind(api.onAnalyzeError);

    return () => {
      clearInterval(pingTimer);
      unsubs.forEach((u) => u && u());
    };
  }, [api, bumpError]);

  const getColor = () => {
    if (status === 'ok') return 'var(--success)';
    if (status === 'degraded') return 'var(--warn)';
    if (status === 'offline') return 'var(--error)';
    return 'var(--text-muted)';
  };

  const label = status === 'ok' ? 'Bridge OK' : 
                status === 'degraded' ? 'Bridge Degraded' : 
                status === 'offline' ? 'Bridge Offline' : 'Checking...';

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      padding: '4px 10px',
      borderRadius: 6,
      background: 'rgba(255,255,255,0.06)',
      fontSize: 12,
      color: 'var(--text-primary)',
      border: `1px solid ${getColor()}33`
    }}>
      <div style={{ 
        width: 8, 
        height: 8, 
        borderRadius: '50%', 
        background: getColor(),
        flexShrink: 0
      }} />
      <span>{label}</span>
      {protocolVersion && (
        <span style={{ opacity: 0.6, fontSize: 10 }}>
          v{protocolVersion}
        </span>
      )}
      {recentErrors.length > 0 && (
        <span style={{
          background: 'var(--warn-soft)',
          color: 'var(--warn)',
          padding: '1px 5px',
          borderRadius: 3,
          fontSize: 10,
          fontFamily: 'var(--font-mono)'
        }}>
          {recentErrors.length} err
        </span>
      )}
    </div>
  );
}
