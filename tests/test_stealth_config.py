"""
Stealth transport config + attach-trace regression tests (v2 layer).

Guarantees: no AUTO ladder exists, kernel transports are explicit,
STEALTH_OFF stays equality-compatible with engines.base, and attach
failures carry a readable step chain.
"""
from core.stealth.config import AccessMethod, StealthConfig, STEALTH_OFF
from core.stealth.reader import StealthReader


def test_no_auto_method_exists():
    names = {m.name for m in AccessMethod}
    assert "AUTO" not in names
    assert "PT_WALKER" not in names
    assert names == {"DIRECT", "HIJACK", "DRIVER", "CR3"}


def test_kernel_transports_are_explicit_and_labeled():
    assert not AccessMethod.DIRECT.requires_kernel()
    assert not AccessMethod.HIJACK.requires_kernel()
    assert AccessMethod.DRIVER.requires_kernel()
    assert AccessMethod.CR3.requires_kernel()
    assert AccessMethod.DRIVER.label == "Kernel Driver (Physical)"
    assert AccessMethod.CR3.label == "PT Walker (Physical CR3)"


def test_stealth_off_is_plain_default_instance():
    assert STEALTH_OFF == StealthConfig()
    assert STEALTH_OFF.method is AccessMethod.DIRECT


def test_explicit_kernel_config_differs_from_off():
    assert StealthConfig(method=AccessMethod.DRIVER) != STEALTH_OFF
    assert StealthConfig(method=AccessMethod.HIJACK) != STEALTH_OFF


def test_failure_chain_only_lists_failed_steps():
    reader = StealthReader.__new__(StealthReader)
    reader.attach_steps = [
        ("map driver", False, "access denied"),
        ("resolve cr3", True, "cr3=0x1234"),
        ("read probe", False, "timeout"),
    ]
    chain = reader._format_failure_chain()
    assert "map driver: access denied" in chain
    assert "read probe: timeout" in chain
    assert "resolve cr3" not in chain


def test_failure_chain_empty_when_no_steps():
    reader = StealthReader.__new__(StealthReader)
    reader.attach_steps = []
    assert reader._format_failure_chain() == ""
