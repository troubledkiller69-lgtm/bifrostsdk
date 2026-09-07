import json
import sys
import os
import threading

_BUILD_STAMP = "4.0.0"

# Import existing logic
from gui_bridge import (
    KNOWN_GAME_EXES, list_processes, run_dump, run_spoof, run_spoof_info,
    run_spoof_restore, run_generate, run_hunt, run_read_memory, run_ac_detect,
    run_test_webhook, cancel_operation,
    run_analyze_probe, run_analyze, run_decompile_fn, run_analyze_export,
    run_hexdump_at, run_disasm_at, run_xrefs_at, run_symbols, run_strings,
)

# Council remediation: protocol enforcement (Cluster 1)
from contracts.validate import validate_command, validate_protocol_document, KNOWN_STREAMING

def emit_ipc(obj):
    try:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()
    except Exception:
        pass

def process_command(cmd_line):
    try:
        req = json.loads(cmd_line)
    except Exception as e:
        print(f"[WARN] Malformed IPC line dropped: {e}", file=sys.stderr)
        return

    command = req.get('command')
    args = req.get('args', {})
    req_id = req.get('id', None)
    incoming_version = req.get('protocol_version')

    # === Council remediation (Cluster 1): receive-side version awareness ===
    # The JS side now always sends protocol_version. We currently only warn on
    # missing/old versions instead of rejecting (soft transition).
    if not incoming_version or not (str(incoming_version).startswith("1.1") or str(incoming_version).startswith("1.2") or str(incoming_version).startswith("1.3")):
        print(f"[WARN] Received request without 1.1+ protocol_version "
              f"(got {incoming_version!r}). Envelope support is active but not yet enforced.",
              file=sys.stderr)

    # === Council remediation (Cluster 1): early protocol validation ===
    # Reject unknown commands before any dispatch or emit hooking.
    ok, reason = validate_command(command or "", args)
    if not ok:
        err = {"type": "result", "data": {"error": reason, "code": "UNKNOWN_COMMAND"}}
        if req_id is not None:
            err["_id"] = req_id
        emit_ipc(err)
        return

    import gui_bridge
    original_emit = gui_bridge.emit

    # If it's a streaming command
    if command in KNOWN_STREAMING:
        stream_tag = req.get("stream") or command

        def tagged_emit(obj):
            if isinstance(obj, dict) and "stream" not in obj:
                obj["stream"] = stream_tag
            emit_ipc(obj)

        gui_bridge.emit = tagged_emit
        try:
            if command == 'dump':
                run_dump(args)
            elif command == 'spoof':
                run_spoof(args)
            elif command == 'generate':
                run_generate(args)
            elif command == 'hunt':
                run_hunt(args)
            elif command == 'analyze':
                run_analyze(args)
            elif command == 'analyze_export':
                run_analyze_export(args)
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            # ONE terminal signal per failure. The result error is what the
            # UI surfaces (main.js mirrors it into the op.error channel);
            # the traceback goes to stderr where the dev console reads it.
            # Emitting error-level log lines here too made every failed
            # operation render 2-3 error entries in the GUI.
            emit_ipc({'type': 'result', 'data': {'error': str(exc)}, 'stream': stream_tag})
            print(f"[!] {command} failed: {exc}", file=sys.stderr)
            print(tb, file=sys.stderr)
        finally:
            gui_bridge.emit = original_emit
        return

    if command == 'cancel':
        gui_bridge.cancel_operation(args.get('operation', ''))
        response = {'status': 'ok', 'cancelled': args.get('operation', '')}
        if req_id is not None:
            response['_id'] = req_id
        emit_ipc(response)
        return

    # Normal JSON API calls
    captured = []
    def capture_emit(obj):
        captured.append(obj)
    gui_bridge.emit = capture_emit

    def _pick_result(captured_list):
        """
        Pull the actual response out of captured emits. Request-response
        commands may emit log lines BEFORE the result (e.g. webhook send
        logs the redacted URL). Picking captured[0] would return the log,
        not the result. Prefer the last "type": "result", else fall back
        to the last entry, else {}.

        Forward any log lines to the renderer so they're not silently
        dropped — the log channel still exists for these commands.
        """
        result = None
        for entry in captured_list:
            if isinstance(entry, dict):
                if entry.get("type") == "result":
                    result = entry
                else:
                    # Replay log/progress to the renderer's log stream
                    emit_ipc(entry)
        if result is not None:
            return result
        return captured_list[-1] if captured_list else {}

    response = {}
    try:
        if command == 'list_processes':
            list_processes()
            response = _pick_result(captured)
        elif command == 'spoof_info':
            run_spoof_info(args)
            response = _pick_result(captured)
        elif command == 'spoof_restore':
            run_spoof_restore(args)
            response = _pick_result(captured)
        elif command == 'read_memory':
            run_read_memory(args)
            response = _pick_result(captured)
        elif command == 'ac_detect':
            run_ac_detect(args)
            response = _pick_result(captured)
        elif command == 'test_webhook':
            run_test_webhook(args)
            response = _pick_result(captured)
        elif command == 'analyze_probe':
            run_analyze_probe(args)
            response = _pick_result(captured)
        elif command == 'decompile_fn':
            run_decompile_fn(args)
            response = _pick_result(captured)
        elif command == 'analyzer_hexdump':
            run_hexdump_at(args)
            response = _pick_result(captured)
        elif command == 'analyzer_disasm_at':
            run_disasm_at(args)
            response = _pick_result(captured)
        elif command == 'analyzer_xrefs':
            run_xrefs_at(args)
            response = _pick_result(captured)
        elif command == 'analyzer_symbols':
            run_symbols(args)
            response = _pick_result(captured)
        elif command == 'analyzer_strings':
            run_strings(args)
            response = _pick_result(captured)
        elif command == 'ping':
            response = {
                'status': 'ok',
                'version': globals().get('_BUILD_STAMP', '4.0.0'),
                'protocol_version': '1.3',
            }
        elif command == 'bridge_info':
            # Build stamp + key feature flags so the UI can verify which
            # backend revision is actually running. If the user reports a
            # stale-looking error, asking for this stamp is one click.
            response = {
                'type': 'result',
                'data': {
                    'build_stamp': globals().get('_BUILD_STAMP', 'unknown'),
                    'protocol_version': '1.3',
                    'features': {
                        'webhook_curl_fallback': True,
                        'webhook_powershell_fallback': True,
                        'webhook_strict_validation': True,
                        'webhook_discord_bot_ua': True,
                        'analyzer': True,
                    },
                },
            }
        else:
            response = {'type': 'result', 'data': {'error': f'Unknown command: {command}'}}
    finally:
        gui_bridge.emit = original_emit

    if req_id is not None:
        response['_id'] = req_id

    emit_ipc(response)

def _backend_build_stamp():
    """
    Return a short build signature so the UI can prove which backend is live.

    Dev mode: "<gui_bridge mtime ISO>+<8-char sha1>". Cheap and unambiguous —
    if you edit gui_bridge.py the stamp changes; if you forgot to restart
    the Python subprocess, the stamp is stale and the UI shows it.

    Frozen mode (PyInstaller): "<exe mtime>+<8-char sha1 of the exe>".
    __file__-relative paths don't exist inside the bundle.
    """
    import datetime
    import hashlib
    import sys
    try:
        if getattr(sys, "frozen", False):
            exe_path = sys.executable
            st = os.stat(exe_path)
            with open(exe_path, "rb") as f:
                digest = hashlib.sha1(f.read()).hexdigest()[:8]
            mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%dT%H:%M:%S")
            return f"{mtime}+{digest}"
        bridge_path = os.path.join(os.path.dirname(__file__), "gui_bridge.py")
        st = os.stat(bridge_path)
        with open(bridge_path, "rb") as f:
            digest = hashlib.sha1(f.read()).hexdigest()[:8]
        mtime = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%dT%H:%M:%S")
        return f"{mtime}+{digest}"
    except Exception as e:
        return f"unknown ({e})"


def run_server():
    # stdout is reserved for the JSON IPC protocol. Any stray print() from
    # core/engines/drivers modules would corrupt the line protocol, so
    # redirect print to stderr for the lifetime of the bridge.
    import builtins as _builtins
    _original_print = _builtins.print

    def _stderr_print(*args, **kwargs):
        kwargs.setdefault("file", sys.stderr)
        _original_print(*args, **kwargs)

    _builtins.print = _stderr_print

    # Fail fast if the protocol document itself is invalid (enforcement gate)
    ok, msg = validate_protocol_document()
    if not ok:
        print(f"[FATAL] Protocol validation failed at startup: {msg}", file=sys.stderr)
        sys.exit(2)

    build = _backend_build_stamp()
    # The Electron main process pipes stderr to its own console, so this line
    # is visible in dev tools. It also lets `bridge_info` echo the same value
    # so we never debug a stale backend again.
    globals()["_BUILD_STAMP"] = build
    print(f"[*] BIFROST IPC API Server (protocol v1.3) - build {build}", file=sys.stderr)
    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break # EOF, parent closed
            line = line.strip()
            if not line:
                continue

            process_command(line)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Fatal IPC error: {e}", file=sys.stderr)

if __name__ == '__main__':
    # Force stdin and stdout to be unbuffered binary wrapped in utf-8
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    run_server()

