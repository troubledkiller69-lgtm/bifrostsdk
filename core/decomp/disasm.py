"""
BIFROST SDK — iced-x86 linear disassembly engine.

Fallback engine when rizin is not provisioned. No decompilation here — just
honest, fast linear disassembly of a byte region. The UI labels it clearly:
"engine: iced-x86 (disassembly only)".

Linear windows are stateless: any byte offset can be decoded, so callers can
page through a file or a module dump without keeping a session alive.
"""

from __future__ import annotations

from dataclasses import dataclass

_MAX_WINDOW_BYTES = 0x10000  # 64 KB decode cap per request

_ARCH_BITNESS = {
    "x86": 32,
    "x86_64": 64,
    "arm64": 64,
}


@dataclass
class InsnLine:
    address: int
    bytes_hex: str
    text: str


class IcedError(RuntimeError):
    """Raised on unsupported arch or empty decode window."""


def bitness_for(arch: str) -> int:
    bitness = _ARCH_BITNESS.get(arch or "x86_64")
    if bitness is None:
        raise IcedError(f"Unsupported arch for iced fallback: {arch!r}")
    return bitness


def disasm_region(data: bytes, base: int, arch: str = "x86_64") -> list[dict]:
    """Decode *data* (assumed to start at virtual address *base*) linearly.

    Returns [{address, bytes, text}] with byte-perfect instruction widths.
    Stops on the first truly undecodable byte rather than erroring out —
    a bad tail byte after a clean run is normal in scanned buffers.
    """
    import iced_x86  # lazy: optional dependency for the fallback engine

    bitness = bitness_for(arch)
    decoder = iced_x86.Decoder(bitness, bytes(data), ip=base)
    formatter = iced_x86.Formatter(iced_x86.FormatterSyntax.NASM)

    lines: list[dict] = []
    for insn in decoder:
        if insn.is_invalid:
            break
        raw = data[insn.ip - base: insn.next_ip - base]
        lines.append({
            "address": insn.ip,
            "bytes": raw.hex(),
            "text": formatter.format(insn),
        })
        if len(lines) >= 4096:  # hard cap per request, safety first
            break
    return lines


def disasm_file(
    file_path: str,
    offset: int = 0,
    size: int = 0x1000,
    arch: str = "x86_64",
    file_base: int = 0,
) -> dict:
    """Decode a byte window of a file on disk.

    *offset* is a file offset (the thing a hex editor shows); addresses in
    the result are `file_base + offset` so module dumps can carry their real
    image base through to the UI.
    """
    if offset < 0:
        raise IcedError("offset must be >= 0")
    if size <= 0 or size > _MAX_WINDOW_BYTES:
        raise IcedError(f"size must be 1..{_MAX_WINDOW_BYTES}")
    with open(file_path, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    if not data:
        raise IcedError("nothing to decode at that offset (end of file?)")
    return {
        "engine": "iced-x86",
        "offset": offset,
        "size": len(data),
        "file_base": file_base,
        "lines": disasm_region(data, file_base + offset, arch),
    }
