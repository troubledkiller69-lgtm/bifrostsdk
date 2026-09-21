// Auto-generated from contracts/bifrost_protocol.json — do not edit by hand.
// Run `python scripts/gen_protocol_types.py` to regenerate.

export type BifrostCommand =
  | 'ping'
  | 'list_processes'
  | 'bridge_info'
  | 'read_memory'
  | 'write_memory'
  | 'ac_detect'
  | 'analyze_probe'
  | 'decompile_fn'
  | 'analyzer_hexdump'
  | 'analyzer_disasm_at'
  | 'analyzer_xrefs'
  | 'analyzer_symbols'
  | 'analyzer_strings'
  | 'debug_snapshot'
  | 'driver_list'
  | 'driver_test'
  | 'cancel'
  | 'test_webhook';

export type BifrostStreamingCommand = 'dump' | 'generate' | 'analyze' | 'analyze_export';

export interface ReadMemoryArgs { pid: number; address: number; size: number; }
export interface WriteMemoryArgs { pid: number; address: number; bytes: number[]; }
export interface AnalyzerHexdumpArgs { addr: number; size?: number; }
export interface AnalyzerDisasmArgs { addr: number; size?: number; }
export interface AnalyzerXrefsArgs { addr: number; }
export interface AnalyzeArgs {
  source: { type: 'file' | 'module'; path?: string; pid?: number; module?: string; engine?: 'auto' | 'rizin' | 'ida' | 'iced' };
  engine?: 'auto' | 'rizin' | 'ida' | 'iced';
  limit?: number;
}

export type BridgeResult<T> = { type: 'result'; data: T; _id?: string } | { error: string; code: string };
export type AnalyzerProbeResult = {
  rizin: { available: boolean; exe: string | null; version: string; decompiler: boolean };
  ida: { available: boolean; exe: string | null; version: string };
  iced: { available: boolean };
  default_engine: string;
};

export interface WindowBifrost {
  command: (name: BifrostCommand, args?: unknown) => Promise<BridgeResult<unknown>>;
  // streaming
  startDump: (args: unknown) => void; stopDump: () => void;
  startAnalyze: (args: AnalyzeArgs) => void; stopAnalyze: () => void;
  startAnalyzeExport: (args: { limit: number }) => void; stopAnalyzeExport: () => void;
  // listeners return unsubscribe
  onAnalyzeLog: (cb: (data: unknown) => void) => () => void;
  onAnalyzeProgress: (cb: (data: unknown) => void) => () => void;
  onAnalyzeComplete: (cb: (data: unknown) => void) => () => void;
  onAnalyzeError: (cb: (data: unknown) => void) => () => void;
  analyzeProbe: () => Promise<BridgeResult<AnalyzerProbeResult>>;
  analyzerHexdump: (addr: number, size?: number) => Promise<BridgeResult<unknown>>;
  analyzerDisasmAt: (addr: number, size?: number) => Promise<BridgeResult<unknown>>;
  analyzerXrefs: (addr: number) => Promise<BridgeResult<unknown>>;
  analyzerCallgraph: (addr: number) => Promise<BridgeResult<unknown>>;
  analyzerSearch: (query: string, cap?: number) => Promise<BridgeResult<unknown>>;
  analyzerSymbols: () => Promise<BridgeResult<unknown>>;
  analyzerStrings: (minLen?: number, cap?: number) => Promise<BridgeResult<unknown>>;
  debugSnapshot: (includeThreads?: boolean) => Promise<BridgeResult<unknown>>;
  driverList: () => Promise<BridgeResult<{ drivers: unknown[]; count: number }>>;
  driverTest: (driver: string, force?: boolean) => Promise<BridgeResult<unknown>>;
}
