"""Wave-1 driver strategies: verify IOCTL wire layouts against the documented
protocols (SIV/ThrottleStop/Lenovo) using an emulated DeviceIoControl.

These tests prove our struct packing matches the public PoC specs -- they do
NOT prove the real drivers behave (that needs Admin + the .sys on a test box).
"""
import ctypes
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import core.stealth.driver as drvmod
from core.stealth.driver import (
    LenovoMsrStrategy, SivStrategy, ThrottleStopStrategy,
)
from drivers.mapper import DRIVER_PROFILES, DriverType


class FakeK32:
    """Emulates the three drivers' IOCTL protocols over a physmem dict."""

    def __init__(self):
        self.mem = {}
        self.calls = []

    def _r(self, addr, n):
        return bytes(self.mem.get(addr + i, 0xAB) for i in range(n))

    def _w(self, addr, data):
        for i, b in enumerate(data):
            self.mem[addr + i] = b

    def DeviceIoControl(self, handle, code, in_p, in_n, out_p, out_n, br_p, _ov):
        in_b = ctypes.string_at(in_p, in_n) if in_n else b""
        self.calls.append((code, in_b, out_n))
        out = None
        if code == 0x80006498:  # TS read: <Q phys
            (phys,) = struct.unpack("<Q", in_b[:8])
            out = self._r(phys, out_n)
        elif code == 0x8000649C:  # TS write: <QQ phys+value
            phys, val = struct.unpack("<QQ", in_b[:16])
            self._w(phys, struct.pack("<Q", val))
        elif code == 0x9C406104:  # Lenovo read: <QII phys,op,size
            phys, op, size = struct.unpack("<QII", in_b[:16])
            assert op == 1
            out = self._r(phys, size)
        elif code == 0x9C40A108:  # Lenovo write: <QII + data
            phys, op, _var = struct.unpack("<QII", in_b[:16])
            assert op == 1
            self._w(phys, in_b[16:])
        elif code == 0x10:  # SIV scatter: <Q phys
            (phys,) = struct.unpack("<Q", in_b[:8])
            out = self._r(phys, out_n)
        elif code == 0x14:  # SIV map+write: header + entries
            phys, size, _rsv, flags, _r2, count = struct.unpack("<QIHHIH", in_b[:22])
            assert flags & 0x02
            for i in range(count):
                reg, mask, val = struct.unpack("<III", in_b[0x30 + i * 0x18:0x30 + i * 0x18 + 12])
                cur = struct.unpack("<I", self._r(phys + reg, 4))[0]
                self._w(phys + reg, struct.pack("<I", (cur & mask) | val))
            out = in_b  # in-place buffer
        else:
            return 0
        if out is not None and out_n:
            ctypes.memmove(out_p, out[:out_n], min(len(out), out_n))
        try:
            ctypes.cast(br_p, ctypes.POINTER(ctypes.c_ulong))[0] = len(out) if out else 0
        except Exception:
            pass
        return 1


def _patch(monkeypatch):
    fake = FakeK32()
    monkeypatch.setattr(drvmod, "k32", fake)
    return fake


def test_throttlestop_roundtrip(monkeypatch):
    fake = _patch(monkeypatch)
    s = ThrottleStopStrategy()
    fake.mem.update({0x1000 + i: i for i in range(16)})
    assert s.read_physical(1, 0x1000, 16) == bytes(range(16))
    # wire check: read input is exactly <Q phys
    assert fake.calls[0][0] == 0x80006498
    assert fake.calls[0][1] == struct.pack("<Q", 0x1000)
    assert s.write_physical(1, 0x2000, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    assert fake.calls[-1][0] == 0x8000649C
    assert s.read_physical(1, 0x2000, 9) == b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"


def test_lenovo_roundtrip(monkeypatch):
    fake = _patch(monkeypatch)
    s = LenovoMsrStrategy()
    data = bytes((i * 7) & 0xFF for i in range(64))
    for i, b in enumerate(data):
        fake.mem[0x5000 + i] = b
    assert s.read_physical(1, 0x5000, 64) == data
    # wire check: <Q phys, op=1, size
    code, buf, _ = fake.calls[0]
    assert code == 0x9C406104
    assert struct.unpack("<QII", buf) == (0x5000, 1, 64)
    assert s.write_physical(1, 0x6000, b"ABCDEFGH12345678")
    assert s.read_physical(1, 0x6000, 16) == b"ABCDEFGH12345678"


def test_siv_roundtrip(monkeypatch):
    fake = _patch(monkeypatch)
    s = SivStrategy()
    data = bytes((i * 13) & 0xFF for i in range(300))
    for i, b in enumerate(data):
        fake.mem[0x9000 + i] = b
    assert s.read_physical(1, 0x9000, 300) == data
    code, buf, _ = fake.calls[0]
    assert code == 0x10 and buf == struct.pack("<Q", 0x9000)
    # dword write within one page + unaligned tail crossing dword boundary
    assert s.write_physical(1, 0xA002, b"\xDE\xAD\xBE\xEF\x11")
    assert s.read_physical(1, 0xA002, 5) == b"\xDE\xAD\xBE\xEF\x11"


def test_strategy_map_wiring():
    from core.stealth.driver import DriverInterface
    di = object.__new__(DriverInterface)
    di._handle = 0
    di._set_strategy(DriverType.SIV_SIVX64)
    assert isinstance(di._strategy, SivStrategy)
    di._set_strategy(DriverType.THROTTLESTOP_TS)
    assert isinstance(di._strategy, ThrottleStopStrategy)
    di._set_strategy(DriverType.LENOVO_LNVMSRIO)
    assert isinstance(di._strategy, LenovoMsrStrategy)


def test_builtin_and_byo_profiles():
    for key, dtype, r, w in (
        ("siv", DriverType.SIV_SIVX64, 0x10, 0x14),
        ("throttlestop", DriverType.THROTTLESTOP_TS, 0x80006498, 0x8000649C),
        ("lenovo", DriverType.LENOVO_LNVMSRIO, 0x9C406104, 0x9C40A108),
    ):
        p = DRIVER_PROFILES[key]
        assert p.driver_type == dtype, key
        assert p.ioctl_read == r and p.ioctl_write == w, key
        assert p.device_path.startswith("\\\\.\\"), key
