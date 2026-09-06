import React, { useState, useEffect, useRef } from 'react';

export default function BoilerplatePage({ dumpResults }) {
  const [projectName, setProjectName] = useState('BifrostProject');
  const [outputDir, setOutputDir] = useState('C:\\BifrostProjects');
  const [logs, setLogs] = useState([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const logEndRef = useRef(null);

  const api = window.bifrost;

  useEffect(() => {
    if (!api) return;

    const handleLog = (msg) => {
      const text = typeof msg === 'string' ? msg : (msg?.text || JSON.stringify(msg));
      setLogs((prev) => [...prev, { text, type: msg.level || 'info', time: new Date().toLocaleTimeString() }]);
    };

    const handleComplete = (result) => {
      setIsGenerating(false);
      // Streaming results arrive as {type:'result', data:{success, path, error?}}
      const payload = result?.type === 'result' ? result.data : result;
      if (payload?.success) {
        setLogs((prev) => [...prev, { text: `[SUCCESS] Project generated at ${payload.path}`, type: 'success', time: new Date().toLocaleTimeString() }]);
      } else {
        setLogs((prev) => [...prev, { text: `[ERROR] ${payload?.error || 'Failed to generate project.'}`, type: 'error', time: new Date().toLocaleTimeString() }]);
      }
    };

    const unsubLog = api.onGenLog(handleLog);
    const unsubComplete = api.onGenComplete(handleComplete);

    return () => {
      unsubLog && unsubLog();
      unsubComplete && unsubComplete();
    };
  }, [api]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleBrowse = async () => {
    if (!api || !api.selectDirectory) return;
    const result = await api.selectDirectory();
    if (!result.cancelled && result.path) {
      setOutputDir(result.path);
    }
  };

  const handleGenerate = () => {
    if (!api) return;
    if (!dumpResults) {
      setLogs([{ text: '[-] You must dump a game first before generating a boilerplate!', type: 'error', time: new Date().toLocaleTimeString() }]);
      return;
    }

    setIsGenerating(true);
    setLogs([{ text: '[*] Starting C++ Boilerplate Generation...', type: 'info', time: new Date().toLocaleTimeString() }]);
    
    api.startGeneration({
      project_name: projectName,
      output_dir: outputDir,
      sdk_data: dumpResults
    });
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Boilerplate Generator</h1>
        <div className="page-subtitle">Auto-generate a complete C++ Visual Studio project mapped to your dumped offsets.</div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '24px' }}>
        <div className="stat-card" style={{ background: 'rgba(13, 17, 23, 0.8)', border: '1px solid rgba(255,255,255,0.1)' }}>
          <div className="sidebar-label" style={{ marginBottom: 12 }}>Project Settings</div>
          
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--frost-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>Project Name</label>
            <input 
              type="text" 
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              style={{
                width: '100%',
                padding: '10px 12px',
                background: 'rgba(0,0,0,0.5)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '4px',
                color: 'white',
                fontFamily: 'var(--font-mono)'
              }}
            />
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--frost-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 1 }}>Output Directory</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input 
                type="text" 
                value={outputDir}
                onChange={(e) => setOutputDir(e.target.value)}
                style={{
                  flex: 1,
                  padding: '10px 12px',
                  background: 'rgba(0,0,0,0.5)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '4px',
                  color: 'white',
                  fontFamily: 'var(--font-mono)'
                }}
              />
              <button 
                className="btn btn-secondary" 
                onClick={handleBrowse}
                style={{ padding: '0 16px', fontSize: 12, letterSpacing: 1 }}
              >
                BROWSE
              </button>
            </div>
          </div>

          <button 
            className="btn btn-primary" 
            style={{ width: '100%', padding: '14px', fontSize: 14, letterSpacing: 2 }}
            onClick={handleGenerate}
            disabled={isGenerating}
          >
            {isGenerating ? 'GENERATING...' : 'GENERATE C++ PROJECT'}
          </button>
        </div>

        <div className="stat-card" style={{ background: 'rgba(13, 17, 23, 0.8)', border: '1px solid rgba(255,255,255,0.1)' }}>
           <div className="sidebar-label" style={{ marginBottom: 12 }}>Data Source</div>
           {dumpResults ? (
             <div>
               <div style={{ color: 'var(--shatter-green)', marginBottom: 8, fontSize: 13, fontWeight: 'bold' }}>✓ Active Dump Data Found</div>
               <div style={{ fontSize: 12, color: 'var(--frost-muted)' }}>Engine: <span style={{ color: 'white' }}>{dumpResults.engine || 'Unknown'}</span></div>
               <div style={{ fontSize: 12, color: 'var(--frost-muted)' }}>Classes: <span style={{ color: 'white' }}>{dumpResults.classes?.length || 0}</span></div>
               <div style={{ fontSize: 12, color: 'var(--frost-muted)' }}>Total Offsets: <span style={{ color: 'white' }}>{dumpResults.total_fields || 0}</span></div>
             </div>
           ) : (
             <div>
               <div style={{ color: 'var(--shatter-red)', marginBottom: 8, fontSize: 13, fontWeight: 'bold' }}>✗ No Dump Data</div>
               <div style={{ fontSize: 12, color: 'var(--frost-muted)' }}>You must dump a game on the Dump page before generating a boilerplate.</div>
             </div>
           )}
        </div>
      </div>

      <div className="sidebar-label">Generation Log</div>
      <div className="log-console" style={{ height: '300px' }}>
        {logs.length === 0 && <div className="log-line dim">Awaiting generation start...</div>}
        {logs.map((log, i) => (
          <div key={i} className={`log-line ${log.type}`}>
            <span className="dim">[{log.time}]</span> {log.text}
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
