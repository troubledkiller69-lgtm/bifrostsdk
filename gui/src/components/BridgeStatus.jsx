import React, { useState, useEffect } from 'react';

/**
 * BridgeStatus — Tier 1 observability component (100-iter-02 + Tier 1 on-ramp)
 * 
 * Shows a compact health indicator for the Python bridge + protocol.
 * Subscribes to the improved error channels created in this batch.
 * 
 * Follows frontend-ux-engineer principles: real states, minimal surface, existing patterns.
 */
export default function BridgeStatus() {
  const [status, setStatus] = useState('unknown'); // 'ok' | 'degraded' | 'offline' | 'unknown'
  const [protocolVersion, setProtocolVersion] = useState(null);
  const [recentErrorCount, setRecentErrorCount] = useState(0);

  const api = window.bifrost;

  useEffect(() => {
    if (!api) {
      setStatus('offline');
      return;
    }

    // Initial health check. sendCommand always resolves (it never rejects),
    // so failures arrive as {error, code} — map them to offline explicitly.
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

    // Subscribe to the dedicated error channels (now properly supported after 100-iter-02 preload + main.js work)
    const unsubs = [];

    // Track which dedicated channels we successfully subscribed to, so the
    // log-level=error fallback below only fires for channels that DON'T have
    // a dedicated handler. Otherwise every dump failure double-counts: once
    // via onDumpError, once via onDumpLog{level:'error'}. See the "err 90"
    // incident — the counter hit 90 because every JPEXS retry registered 2x.
    const dedicatedChannels = { dump: false, spoof: false, gen: false, hunt: false };

    // Direct subscriptions to the improved on*Error methods
    if (typeof api.onDumpError === 'function') {
      const unsub = api.onDumpError(() => {
        setRecentErrorCount((c) => c + 1);
        setStatus(prev => prev !== 'offline' ? 'degraded' : prev);
      });
      if (typeof unsub === 'function') {
        unsubs.push(unsub);
        dedicatedChannels.dump = true;
      }
    }
    if (typeof api.onSpoofError === 'function') {
      const unsub = api.onSpoofError(() => {
        setRecentErrorCount((c) => c + 1);
        setStatus(prev => prev !== 'offline' ? 'degraded' : prev);
      });
      if (typeof unsub === 'function') {
        unsubs.push(unsub);
        dedicatedChannels.spoof = true;
      }
    }
    if (typeof api.onGenError === 'function') {
      const unsub = api.onGenError(() => {
        setRecentErrorCount((c) => c + 1);
        setStatus(prev => prev !== 'offline' ? 'degraded' : prev);
      });
      if (typeof unsub === 'function') {
        unsubs.push(unsub);
        dedicatedChannels.gen = true;
      }
    }
    if (typeof api.onHuntError === 'function') {
      const unsub = api.onHuntError(() => {
        setRecentErrorCount((c) => c + 1);
        setStatus(prev => prev !== 'offline' ? 'degraded' : prev);
      });
      if (typeof unsub === 'function') {
        unsubs.push(unsub);
        dedicatedChannels.hunt = true;
      }
    }

    // Fallback: only listen for log-level=error on channels where the
    // dedicated error subscription FAILED. Prevents double-counting on
    // backends that emit both event types. Old backends that only emit
    // log lines still surface in the counter via this fallback.
    if (!dedicatedChannels.dump && typeof api.onDumpLog === 'function') {
      const unsubGeneral = api.onDumpLog((data) => {
        if (data && data.level === 'error') {
          setRecentErrorCount((c) => c + 1);
          setStatus(prev => prev !== 'offline' ? 'degraded' : prev);
        }
      });
      if (typeof unsubGeneral === 'function') unsubs.push(unsubGeneral);
    }

    return () => {
      unsubs.forEach((u) => u && u());
    };
  }, [api]);

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
      {recentErrorCount > 0 && (
        <span style={{ 
          background: 'var(--warn-soft)', 
          color: 'var(--warn)', 
          padding: '1px 5px', 
          borderRadius: 3,
          fontSize: 10 
        }}>
          {recentErrorCount} err
        </span>
      )}
    </div>
  );
}
