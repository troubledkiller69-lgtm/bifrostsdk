"""
BIFROST SDK — Decompiler / Analyzer engine package.

Adds an IDA-style reverse-engineering surface to the SDK:

  * rizin + rz-ghidra (pdg/pdgj) as the full decompiler engine — bundled in
    gui/extra/rizin when provisioned (see tools/provision_rizin.ps1)
  * iced-x86 linear disassembly as the fallback engine when rizin is absent

Engine availability is deliberately non-fatal: the analyzer degrades from
"decompiled C" to "disassembly only" and says so loudly in the UI. Nothing
auto-downloads at runtime.
"""
