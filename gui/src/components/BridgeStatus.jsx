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
    bind(api.onAnalyzeError);

    return () => {
      clearInterval(pingTimer);
      unsubs.forEach((u) => u && u());
    };
  }, [api, bumpError]);

  const pillClass =
    status === 'ok' ? 'bridge-pill ok' :
    status === 'degraded' ? 'bridge-pill degraded' :
    status === 'offline' ? 'bridge-pill offline' : 'bridge-pill';

  const label = status === 'ok' ? 'Bridge OK' :
                status === 'degraded' ? 'Bridge Degraded' :
                status === 'offline' ? 'Bridge Offline' : 'Checking...';

  return (
    <div className={pillClass}>
      <span className="dot" />
      <span>{label}</span>
      {protocolVersion && (
        <span className="pill-ver">
          v{protocolVersion}
        </span>
      )}
      {recentErrors.length > 0 && (
        <span className="pill-err">
          {recentErrors.length} err
        </span>
      )}
    </div>
  );
}
