import React, { useState, useEffect, useRef } from 'react';

/* ── Chevron SVG ──────────────────────────────────────── */
function Chevron({ open }) {
  return (
    <svg className={`collapsible-chevron ${open ? 'open' : ''}`} viewBox="0 0 24 24"
      fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

/* ── Collapsible Section ─────────────────────────────── */
function Collapsible({ title, badge, badgeType, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="collapsible">
      <div className="collapsible-header" onClick={() => setOpen(!open)}>
        <div className="collapsible-title">
          {title}
          {badge && (
            <span className={`collapsible-badge ${badgeType || ''}`}>{badge}</span>
          )}
        </div>
        <Chevron open={open} />
      </div>
      <div className={`collapsible-body ${open ? 'open' : ''}`}>
        <div className="collapsible-content">
          {children}
        </div>
      </div>
    </div>
  );
}

/* ── Priority dot ────────────────────────────────────── */
const PRIORITY_COLOR = {
  CRITICAL: 'var(--error)',
  HIGH:     'var(--warn, #f5a623)',
  MEDIUM:   '#d1c454',
  FUTURE:   'var(--text-ghost)',
};
function PriorityDot({ level }) {
  const c = PRIORITY_COLOR[level];
  if (!c) return null;
  return (
    <span
      title={level}
      style={{
        display: 'inline-block', width: 7, height: 7, borderRadius: '50%',
        background: c, marginRight: 6, flexShrink: 0,
      }}
    />
  );
}

/* ── Status Badge ────────────────────────────────────── */
function StatusBadge({ label, value, priority, warnText }) {
  const spoofed = value === true;
  const failed = value === false;
  const skipped = value === null || value === undefined;

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '8px 0',
      borderBottom: '1px solid var(--border)',
    }}>
      <span style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center' }}>
        {priority && <PriorityDot level={priority} />}
        {label}
      </span>
      <span style={{
        fontSize: 11,
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.5px',
        color: skipped
          ? 'var(--text-ghost)'
          : spoofed
            ? 'var(--success)'
            : 'var(--error)',
      }}>
        {warnText && skipped ? warnText : skipped ? 'PENDING' : spoofed ? 'SPOOFED' : 'FAILED'}
      </span>
    </div>
  );
}

/* ── Hardware Value ───────────────────────────────────── */
function HardwareValue({ label, value }) {
  return (
    <div style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '6px 0',
      borderBottom: '1px solid var(--border)',
      gap: 12,
    }}>
      <span style={{ fontSize: 11, color: 'var(--text-ghost)', flexShrink: 0 }}>{label}</span>
      <span style={{
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        color: 'var(--text-secondary)',
        textAlign: 'right',
        wordBreak: 'break-all',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
      }}>
        {value || 'Loading...'}
      </span>
    </div>
  );
}

/* ── Phase definitions (single source of truth for keys + UI metadata) ── */
const PHASES = [
  {
    id: 1, title: 'Phase 1 — Network & Disk',
    targets: [
      { key: 'mac',           label: 'Network Adapters (MAC)',   priority: 'CRITICAL' },
      { key: 'volume',        label: 'Disk Volume Serial',       priority: 'CRITICAL' },
      { key: 'disk_firmware', label: 'Disk Firmware (NVMe/SATA)', priority: 'HIGH' },
    ],
  },
  {
    id: 2, title: 'Phase 2 — SMBIOS & Physical',
    targets: [
      { key: 'smbios',      label: 'SMBIOS Motherboard',  priority: 'CRITICAL' },
      { key: 'smbios_uuid', label: 'SMBIOS System UUID',  priority: 'CRITICAL' },
      { key: 'baseboard',   label: 'Baseboard Serial',    priority: 'CRITICAL' },
      { key: 'bios',        label: 'BIOS Vendor/Version', priority: 'CRITICAL' },
      { key: 'monitor',     label: 'Monitor EDID',        priority: 'HIGH' },
    ],
  },
  {
    id: 3, title: 'Phase 3 — Registry Identity',
    targets: [
      { key: 'guid',         label: 'System GUIDs',         priority: 'CRITICAL' },
      { key: 'gpu',          label: 'GPU Identity',         priority: 'HIGH' },
      { key: 'windows_ids',  label: 'Windows Product IDs',  priority: 'HIGH' },
      { key: 'hostname',     label: 'Computer Hostname',    priority: 'MEDIUM' },
      { key: 'install_date', label: 'Install Date',         priority: 'MEDIUM' },
      { key: 'machine_sid',  label: 'Machine SID (advanced)', priority: 'HIGH',
        warnText: 'SKIPPED' },
    ],
  },
  {
    id: 4, title: 'Phase 4 — Device History',
    targets: [
      { key: 'usb_history', label: 'USB Device History', priority: 'HIGH' },
      { key: 'bluetooth',   label: 'Bluetooth MAC',      priority: 'MEDIUM' },
    ],
  },
  {
    id: 5, title: 'Phase 5 — Cache & Trace Cleanup',
    targets: [
      { key: 'event_logs',      label: 'Event Logs',     priority: 'MEDIUM' },
      { key: 'arp_flush',       label: 'ARP Cache',      priority: 'MEDIUM' },
      { key: 'dns_flush',       label: 'DNS Cache',      priority: 'MEDIUM' },
      { key: 'prefetch_recent', label: 'Prefetch / Recent', priority: 'MEDIUM' },
    ],
  },
  {
    id: 6, title: 'Phase 6 — Future Targets',
    targets: [
      { key: '__perm_mac', label: 'Permanent MAC (NDIS driver)', priority: 'FUTURE',
        warnText: 'REQUIRES DRIVER' },
    ],
  },
];

const ALL_KEYS = PHASES.flatMap(p => p.targets.map(t => t.key)).filter(k => !k.startsWith('__'));

/* ── Main Page ───────────────────────────────────────── */
export default function SpooferPage() {
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [currentValues, setCurrentValues] = useState(null);
  const logsEndRef = useRef(null);
  const api = window.bifrost;

  const fetchCurrentValues = async () => {
    if (!api || !api.command) return;
    try {
      const res = await api.command('spoof_info', {});
      if (res && res.data) setCurrentValues(res.data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => { fetchCurrentValues(); }, [api]);
  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  useEffect(() => {
    if (!api) return;
    const handleLog = (msg) => {
      const text = typeof msg === 'string' ? msg : (msg?.text || JSON.stringify(msg));
      setLogs(prev => [...prev, { text, ts: Date.now() }]);
    };
    const handleComplete = (data) => {
      setRunning(false);
      // Streaming results arrive as {type:'result', data:{...results...}}
      const payload = data?.type === 'result' ? data.data : data;
      if (payload?.error) {
        setLogs(prev => [...prev, { text: `[-] Spoofing failed: ${payload.error}`, ts: Date.now() }]);
        return;
      }
      setResults(payload);
      handleLog("[+] Spoofing sequence complete.");
      fetchCurrentValues();
    };
    const unsubLog = api.onSpoofLog(handleLog);
    const unsubComplete = api.onSpoofComplete(handleComplete);
    return () => { unsubLog?.(); unsubComplete?.(); };
  }, [api]);

  const [mode, setMode] = useState('random');
  const [advancedMode, setAdvancedMode] = useState(false);
  const [customSerials, setCustomSerials] = useState({
    // Phase 1
    mac: '', disk: '', disk_fw: '',
    // Phase 2
    smbios: '', smbios_uuid: '', baseboard: '', bios: '', monitor: '',
    // Phase 3
    guid: '', gpu: '', product_id: '', hostname: '', install_date: '', machine_sid: '',
    // Phase 4
    bluetooth: '',
  });

  const handleSpoof = () => {
    if (!api || running) return;
    if (mode === 'custom' && customSerials.mac) {
      const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
      if (!macRegex.test(customSerials.mac)) {
        setLogs([{ text: '[-] Error: Custom MAC must be in format XX:XX:XX:XX:XX:XX', ts: Date.now() }]);
        return;
      }
    }
    setRunning(true);
    setLogs([]);
    setResults(null);
    api.startSpoofing({
      mode,
      custom_serials: customSerials,
      advanced: advancedMode,
    });
  };

  const handleSpoofCritical = () => {
    if (!api || running) return;
    setRunning(true);
    setLogs([{ text: '[*] Critical-only mode — spoofing the 7 CRITICAL targets.', ts: Date.now() }]);
    setResults(null);
    // Backend doesn't expose a critical-only switch yet, so we ship the same
    // payload but with `mode: critical` so future versions can branch on it.
    api.startSpoofing({
      mode: 'random',
      custom_serials: customSerials,
      advanced: false,
      preset: 'critical',
    });
  };

  const handleRestore = async () => {
    if (!api || !api.command || running) return;
    setRunning(true);
    setLogs([{ text: '[*] Initiating Hardware Restore Sequence...', ts: Date.now() }]);
    try {
      const res = await api.command('spoof_restore', {});
      if (res?.data?.success || res?.success) {
        setLogs(prev => [...prev, { text: '[+] Restore completed successfully.', ts: Date.now() }]);
      } else {
        setLogs(prev => [...prev, { text: '[-] Restore failed.', ts: Date.now() }]);
      }
    } catch (e) {
      setLogs(prev => [...prev, { text: `[-] Restore Error: ${e.message}`, ts: Date.now() }]);
    }
    setRunning(false);
    fetchCurrentValues();
  };

  const updateCustom = (field, value) => {
    setCustomSerials(prev => ({ ...prev, [field]: value }));
  };

  // Summary counts — exclude Phase 6 (future) from totals
  const spoofCount = results ? ALL_KEYS.filter(k => results[k] === true).length : 0;
  const totalTargets = ALL_KEYS.length;
  const phaseResults = (keys) => {
    if (!results) return null;
    const real = keys.filter(k => !k.startsWith('__'));
    const passed = real.filter(k => results[k] === true).length;
    const total = real.length;
    return { passed, total, text: `${passed}/${total}` };
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Hardware Spoofer</h1>
        <div className="page-subtitle">
          Deep identity manipulation across 20 targets in 6 phases
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '24px' }}>
        {/* ── Left Column: Controls + Log ─────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

          {/* Summary badge */}
          {results && (
            <div className="stat-card" style={{
              textAlign: 'center',
              background: spoofCount === totalTargets ? 'var(--success-soft)' : 'var(--error-soft)',
              borderColor: spoofCount === totalTargets ? 'var(--success)' : 'var(--error)',
            }}>
              <div className="stat-value" style={{
                fontSize: 22,
                color: spoofCount === totalTargets ? 'var(--success)' : 'var(--error)',
              }}>
                {spoofCount}/{totalTargets} Targets Spoofed
              </div>
            </div>
          )}

          {/* Mode & Controls */}
          <Collapsible title="Spoof Configuration" defaultOpen={true}>
            <div style={{ display: 'flex', gap: '10px', marginBottom: 4 }}>
              <button
                className={`btn ${mode === 'random' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1 }}
                onClick={() => setMode('random')}
              >
                Randomize All
              </button>
              <button
                className={`btn ${mode === 'custom' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ flex: 1 }}
                onClick={() => setMode('custom')}
              >
                Custom Values
              </button>
            </div>

            {/* Advanced toggle */}
            <div style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '10px 0', borderTop: '1px solid var(--border)',
              borderBottom: '1px solid var(--border)', marginTop: 10, marginBottom: 8,
            }}>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Advanced Mode (Machine SID)
                </span>
                <span style={{ fontSize: 10, color: 'var(--text-ghost)' }}>
                  Dangerous — SAM hive surgery. Can break user profiles.
                </span>
              </div>
              <button
                className={`settings-toggle ${advancedMode ? 'on' : ''}`}
                onClick={() => setAdvancedMode(v => !v)}
              />
            </div>

            {mode === 'custom' && (
              <>
                <div style={{
                  fontSize: 10, textTransform: 'uppercase', color: 'var(--text-ghost)',
                  letterSpacing: 1, marginTop: 8, marginBottom: 4,
                }}>
                  Phase 1 — Network &amp; Disk
                </div>
                <input className="input-field" placeholder="MAC Address (00:11:22:33:44:55)"
                  value={customSerials.mac} onChange={(e) => updateCustom('mac', e.target.value)} />
                <input className="input-field" placeholder="Disk Volume Serial (SCSI)"
                  value={customSerials.disk} onChange={(e) => updateCustom('disk', e.target.value)} />
                <input className="input-field" placeholder="NVMe/SATA Firmware Serial"
                  value={customSerials.disk_fw} onChange={(e) => updateCustom('disk_fw', e.target.value)} />

                <div style={{
                  fontSize: 10, textTransform: 'uppercase', color: 'var(--text-ghost)',
                  letterSpacing: 1, marginTop: 12, marginBottom: 4,
                }}>
                  Phase 2 — SMBIOS &amp; Physical
                </div>
                <input className="input-field" placeholder="SMBIOS / Motherboard Serial"
                  value={customSerials.smbios} onChange={(e) => updateCustom('smbios', e.target.value)} />
                <input className="input-field" placeholder="SMBIOS System UUID (RFC 4122 v4)"
                  value={customSerials.smbios_uuid} onChange={(e) => updateCustom('smbios_uuid', e.target.value)} />
                <input className="input-field" placeholder="Baseboard Serial"
                  value={customSerials.baseboard} onChange={(e) => updateCustom('baseboard', e.target.value)} />
                <input className="input-field" placeholder="BIOS Version (e.g. F.42)"
                  value={customSerials.bios} onChange={(e) => updateCustom('bios', e.target.value)} />
                <input className="input-field" placeholder="Monitor EDID Serial"
                  value={customSerials.monitor} onChange={(e) => updateCustom('monitor', e.target.value)} />

                <div style={{
                  fontSize: 10, textTransform: 'uppercase', color: 'var(--text-ghost)',
                  letterSpacing: 1, marginTop: 12, marginBottom: 4,
                }}>
                  Phase 3 — Registry Identity
                </div>
                <input className="input-field" placeholder="System GUID"
                  value={customSerials.guid} onChange={(e) => updateCustom('guid', e.target.value)} />
                <input className="input-field" placeholder="GPU Adapter Name"
                  value={customSerials.gpu} onChange={(e) => updateCustom('gpu', e.target.value)} />
                <input className="input-field" placeholder="Windows Product ID (XXXXX-XXX-XXXXXXX-XXXXX)"
                  value={customSerials.product_id} onChange={(e) => updateCustom('product_id', e.target.value)} />
                <input className="input-field" placeholder="Computer Name (DESKTOP-XXXXXXX)"
                  value={customSerials.hostname} onChange={(e) => updateCustom('hostname', e.target.value)} />
                {advancedMode && (
                  <input className="input-field" placeholder="Machine SID (S-1-5-21-...)"
                    value={customSerials.machine_sid} onChange={(e) => updateCustom('machine_sid', e.target.value)} />
                )}

                <div style={{
                  fontSize: 10, textTransform: 'uppercase', color: 'var(--text-ghost)',
                  letterSpacing: 1, marginTop: 12, marginBottom: 4,
                }}>
                  Phase 4 — Device History
                </div>
                <input className="input-field" placeholder="Bluetooth MAC (00:11:22:33:44:55)"
                  value={customSerials.bluetooth} onChange={(e) => updateCustom('bluetooth', e.target.value)} />

                <div style={{ fontSize: 11, color: 'var(--text-ghost)', marginTop: 4 }}>
                  Leave blank to auto-randomize.
                </div>
              </>
            )}

            <div style={{ display: 'flex', gap: '10px', marginTop: 12 }}>
              <button className="btn btn-primary" onClick={handleSpoof} disabled={running}
                style={{ flex: 2, opacity: running ? 0.6 : 1 }}>
                {running ? 'Spoofing...' : 'Initiate Full Spoof Sequence'}
              </button>
              <button className="btn btn-secondary" onClick={handleSpoofCritical} disabled={running}
                style={{ flex: 1 }} title="Spoof only the 7 CRITICAL targets">
                Critical Only
              </button>
              <button className="btn btn-danger" onClick={handleRestore} disabled={running}
                style={{ flex: 1 }}>
                Restore
              </button>
            </div>
          </Collapsible>

          {/* Log Console */}
          <div className="log-console" style={{ flex: 1, minHeight: 280 }}>
            {logs.length === 0 && <div className="log-line dim">Awaiting initiation...</div>}
            {logs.map((log, i) => {
              let cls = "log-line ";
              if (log.text.includes("[+]")) cls += "success";
              else if (log.text.includes("[-]")) cls += "error";
              else if (log.text.includes("[!]")) cls += "warn";
              else if (log.text.includes("[*]") || log.text.includes("[Phase")) cls += "info";
              else cls += "dim";
              return <div key={i} className={cls}>{log.text}</div>;
            })}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* ── Right Column: Status + Hardware ────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

          {PHASES.map(phase => {
            const realKeys = phase.targets.map(t => t.key).filter(k => !k.startsWith('__'));
            const r = phaseResults(realKeys);
            const isFuture = phase.id === 6;
            const badge = isFuture
              ? 'STUB'
              : (r?.text);
            const badgeType = isFuture
              ? 'warn'
              : (r && r.passed === r.total ? 'success' : r ? 'error' : '');
            return (
              <Collapsible
                key={phase.id}
                title={phase.title}
                badge={badge}
                badgeType={badgeType}
                defaultOpen={phase.id <= 3}
              >
                {phase.targets.map(t => (
                  <StatusBadge
                    key={t.key}
                    label={t.label}
                    value={results?.[t.key]}
                    priority={t.priority}
                    warnText={t.warnText}
                  />
                ))}
              </Collapsible>
            );
          })}

          {/* Current Hardware — 15 values now */}
          <Collapsible title="Current Hardware" defaultOpen={false}>
            <HardwareValue label="MAC Address"       value={currentValues?.mac} />
            <HardwareValue label="Disk Volume"       value={currentValues?.disk} />
            <HardwareValue label="Disk Firmware"     value={currentValues?.disk_firmware} />
            <HardwareValue label="SMBIOS UUID"       value={currentValues?.smbios_uuid} />
            <HardwareValue label="Baseboard Serial"  value={currentValues?.baseboard_serial} />
            <HardwareValue label="BIOS Vendor"       value={currentValues?.bios_vendor} />
            <HardwareValue label="BIOS Version"      value={currentValues?.bios_version} />
            <HardwareValue label="Machine GUID"      value={currentValues?.guid} />
            <HardwareValue label="GPU"               value={currentValues?.gpu} />
            <HardwareValue label="Product ID"        value={currentValues?.product_id} />
            <HardwareValue label="Hostname"          value={currentValues?.hostname} />
            <HardwareValue label="Install Date"      value={currentValues?.install_date} />
            <HardwareValue label="Machine SID"       value={currentValues?.machine_sid} />
            <HardwareValue label="Bluetooth"         value={currentValues?.bluetooth_mac} />
            <HardwareValue label="USB Device Count"  value={currentValues?.usb_device_count} />
          </Collapsible>

        </div>
      </div>
    </div>
  );
}
