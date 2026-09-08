# Adding a dump engine — authoring guide

How a dumper gets written, registered, detected, and tested. Written against the
live code, so every file and function name below is real and greppable. The
reference implementation is `engines/source/dumper.py` (single file, both Source
generations, pattern + structure walk); alternate shapes live under
`engines/unreal/`, `engines/unity/`, and `engines/blizzard/`. A scratch skeleton
is at `engines/template/` — copy that directory and rename.

A "new engine" here means a new class of target (idTech, Treyarch, whatever),
not a new game for an engine we already cover. New games for existing engines
are usually a profile struct plus a registry entry (see "Variants" below).

## Where things plug in

```text
gui/src (Electron UI)  --engine string-->  gui_bridge.py:run_dump()
                                                |
                                                v
                               engines/registry.py  ENGINE_REGISTRY  (lazy import)
                                                |
                                                v
                            engines/<name>/dumper.py  <Name>Dumper(BaseDumper)
                                                |
                    validate() -> bool   dump() -> list[SDKPackage]
                                                |
                            core/generator/SDKGenerator  (headers + offsets.json)
                                                |
                            contracts/sdk_output_schema.json  (validates output)
```

The backend never hardcodes an engine list. `run_dump` resolves everything
through `engines/registry.py`; the registry keys are also what the diagnostics
snapshot reports (`gui_bridge._engine_registry_names()`). Detection (the "what
is this process" question) lives in `core/process.py` plus two auto-correct
passes inside `run_dump`. Each layer below is the contract you code against.

## The dumper contract — `engines/base.py`

Every dumper subclasses `BaseDumper` (`engines/base.py`). The ABC is small on
purpose: one identity constant and two abstract methods.

```python
class YourDumper(BaseDumper):
    ENGINE_NAME = "Your Engine"       # shown in logs + _meta.engine in offsets.json

    def validate(self) -> bool:
        # True iff the attached process is really your engine.
        ...

    def dump(self) -> list[SDKPackage]:
        # Full structure walk. Returns SDK packages ready for header gen.
        ...
```

`__init__(reader, output_dir="output", stealth_config=None, target_module=None,
logger=None)` is already implemented in the base and subclasses add their own
optional kwargs on top (config structs, profiles — see Unreal/Blizzard).
Notes on what the base gives you:

- `self.reader` — the attached process reader. Duck-typed; see next section.
- `self.scanner` — a `PatternScanner` built for you with the right stealth
  chunk/delay knobs from `stealth_config`. Use it for AOB scans; it keeps its
  own stats (`get_stats()`). Don't construct your own.
- `self.target_module` — the process name the user picked (e.g. `game.exe`).
  Optional; engines that switch on per-game layout read it.
- `self._stealth_config` — `STEALTH_OFF` when attached directly.
- Progress: call `self._update_progress(stage, detail, percent)` (percent
  optional, `-1` leaves it alone). Count as you walk: increment
  `self.progress.classes_found` / `self.progress.fields_found`. These counters
  drive the UI results line AND the empty-dump guard — a dump that completes
  with 0 classes and 0 fields is treated as `EMPTY_DUMP` failure by
  `run_dump`. A dumper that never increments them will always fail loud.
- Warnings/errors: `self._log_warn(msg)`, `self._log_error(msg)`,
  `self._log(msg)`. Everything lands in `DumpProgress.errors` and the progress
  stream. `_log_error` alone doesn't fail validation — returning `False` from
  `validate()` does.
- `dump_and_generate()` is the full pipeline the bridge calls: `validate()` ->
  `dump()` -> `SDKGenerator.write_all(packages)`. It raises `RuntimeError` on
  validate failure and `SchemaValidationError` on schema violations (surfaced
  to the UI as `SCHEMA_VIOLATION` with the offending JSON path). You implement
  `validate` and `dump`; you never call the generator yourself.
- `get_debug_info()` — used by the diagnostics panel; free.

`DumpProgress` fields the UI reads: `stage`, `detail`, `percent`,
`classes_found`, `fields_found`, `errors`, `elapsed`.

## Registration — `engines/registry.py`

`ENGINE_REGISTRY` maps an engine key string to an `EngineEntry`:

```python
@dataclass(frozen=True)
class EngineEntry:
    dumper_import: str                       # "engines.unreal.dumper.UnrealDumper"
    extra_imports: dict[str, str] = {}       # kwarg name -> dotted path (resolved to an object)
    extra_kwargs: dict[str, Any] = {}        # static kwargs
```

```python
"your_engine": EngineEntry(
    dumper_import="engines.your.dumper.YourDumper",
),
```

Rules of this file:

- Imports are lazy. `create_dumper` imports the class only when the key is
  requested (`_import_attr`). Your module's heavy imports (pefile, ctypes
  structs) never load until a dump actually starts. Keep it that way — don't
  import engines at the top of registry.py.
- `create_dumper(engine_key, reader, output_dir, stealth_config, **extra)`
  builds kwargs in this order: `reader`, `output_dir`, `stealth_config`,
  then resolved `extra_imports`, then `extra_kwargs`, then caller extras. The
  bridge passes `target_module=name` and `logger=_log` through `**kwargs` —
  accept `**kwargs` in your `__init__` or explicitly accept both.
- `is_known_engine()` gates the dump before construction. Unknown key =
  terminal "Unknown engine" result from the bridge.
- This file is the ONLY registration point. No elif chains in the bridge, no
  side-channel lists.

### Variants (one class, several keys)

Keys are cheap; classes are not. Real examples:

- `unreal5`, `unreal`, `unreal5_marvel` all construct `UnrealDumper`, differing
  only in `extra_imports={"profile": "engines.unreal.structs.UE5_MARVEL_RIVALS"}`.
- `source` and `source_eac` both construct `SourceDumper`.
- `unity` is a legacy alias for `unity_mono` (the ambiguity that `_resolve_unity_ambiguity`
  exists to unpick — see below).

If your engine has per-game layout drift (Treyarch titles sharing one codebase,
idTech 4 vs idTech 7), ship a `StructsConfig`/profile dataclass per game and a
registry key per game, exactly like `unreal5_marvel`. Apex-style deep variants
that stop resembling the parent walk (`engines/source/apex.py`) are still one
registry entry — the dumper branches internally.

## Selection — `gui_bridge.py:run_dump`

`run_dump(args)` receives `engine` from the GUI. The string can be:

1. `"auto"` — the only case that does detection. Calls
   `ProcessEnumerator.detect_engine_from_modules(reader.list_modules())`
   (`core/process.py`), which matches module names against hardcoded rules
   (engine2.dll -> source, GameAssembly.dll -> unity_il2cpp, r5apex.exe ->
   source_eac, ...). No match falls back to `unreal5` with a warning.
2. An explicit key — `"source"`, `"unreal5_marvel"`, whatever the UI sends.

After that, two auto-correct passes run before construction:

- **By process name**: `unreal5`/`unreal` + a `marvel`-containing exe name ->
  re-keyed to `unreal5_marvel`.
- **Unity Mono/IL2CPP**: `_resolve_unity_ambiguity(engine, loaded_module_names)`
  cross-checks the pick against actual loaded modules — `gameassembly.dll`
  present without mono runtime DLLs forces `unity_il2cpp`; mono runtime present
  without GameAssembly forces `unity_mono`. It returns `(engine, note)`; an
  empty note means nothing changed. This is the pattern to copy when your
  engine has a two-variant ambiguity (Mono vs IL2CPP is structurally identical
  to, say, two D3D11 games sharing one engine DLL name).

Then the guard and construction:

```python
from engines.registry import create_dumper, is_known_engine
if not is_known_engine(engine):
    ...  # terminal error result

dumper = create_dumper(engine, reader, output_dir,
                       stealth_config=stealth_config,
                       target_module=name, logger=_log)
dumper.set_progress_callback(on_progress)
result = dumper.dump_and_generate()
```

`output_dir` is always `output/<sanitized_exe_name>` (sanitized via
`sanitize_process_name`; a real function with its own unit tests). The result
payload carries `headers`, `json` (path to offsets.json), `classes`, `fields`,
`engine`, `output_dir`.

Detection hooks for a new engine, in order of where they belong:

1. `core/process.py` — `ENGINE_SIGNATURES` (used by the psutil-based
   `detect_engine`) and the `detect_engine_from_modules()` rule chain (used by
   `run_dump`'s auto path). Your key returned here MUST be a registered key or
   auto-detection routes into "Unknown engine".
2. `KNOWN_GAME_EXES` (top of `gui_bridge.py`) — labels processes in
   `list_processes` and feeds the per-name re-keying style logic. Add known
   exes for your engine here so the GUI shows the right engine before attach.
3. Auto-correct passes in `run_dump` — only if your engine has an ambiguity
   worth correcting (copy `_resolve_unity_ambiguity`, add a unit test mirroring
   `tests/test_unity_ambiguity.py`).

A new engine typically needs 1 and 2; 3 only for ambiguity cases.

## Reader API (what dumpers may call)

`BaseDumper.__init__` types the reader as `ReaderProtocol` (`core/memory.py`) —
a `runtime_checkable` Protocol, not an enforcement gate. Both `MemoryReader`
and `StealthReader` implement it; dumpers duck-type and may call anything on
the surface. Verified surface (identical on both readers):

```python
read_bytes(addr, size) -> bytes
read_bool / read_int8 / read_uint8 / read_int16 / read_uint16 / read_int32
read_uint32 / read_int64 / read_uint64 / read_float / read_double (addr) -> T
read_ptr(addr) -> int                  # 64-bit pointer
read_string(addr, max_len=256, encoding="utf-8") -> str
read_wstring(addr, max_len=256) -> str
read_pointer_chain(base, offsets) -> int
module_base(name) -> int               # raises RuntimeError if missing
module_size(name) -> int
list_modules() -> list[{"name", "base", "size"}]
get_module_sections(name) -> list[{"name", "rva", "size"}]   # PE sections
resolve_rip_relative(pattern_addr, rip_offset_pos=3, insn_len=7) -> int
close()
```

`StealthReader` adds `get_debug_stats()`, `pid`/`handle` properties, and a
`method_name`; `MemoryReader` exposes `pid`/`handle`. The base dumper's
`get_debug_info()` picks up stealth stats when present.

Everything is a plain integer address — no pointer wrappers. Reads raise on
bad addresses; wrap per-record walks in try/except and continue, like
`_walk_recv_table` does. Note `module_base` raises where `list_modules` is
lenient; the validation idiom used by Source/Blizzard is to scan
`list_modules()` first and only touch `module_base` for modules you confirmed.

For pattern scanning use `self.scanner`:

```python
hits = self.scanner.scan_module("client.dll", "48 89 05 ?? ?? ?? ??", return_first=True)
# hits: list[ScanResult]; hit.address = start of match
addr = self.scanner.find_address("schemasystem.dll", pattern)  # int or None
```

`scan_module` returns all matches by default (that's what `PatternScanner`
gives you); engines use `return_first=True` or iterate. Stealth chunking is
handled inside the scanner — don't gate scans on stealth yourself.

## Output contract

Your `dump()` returns `list[SDKPackage]`. The dataclasses
(`core/generator/__init__.py`):

```python
SDKPackage(name, classes=[], enums=[])          # name -> one .h per package
SDKClass(name, full_name, super_name="", size=0, fields=[], package="")
SDKField(name, type_name, offset, size, array_dim=1, bit_offset=-1, comment="")
```

- `full_name` is the offsets.json key (e.g. `Source2.CExampleSchemaVData...`,
  `Blizzard.MovementComponent`). Namespace it with your engine prefix.
- `SDKGenerator` sorts fields by offset and inserts `_pad` arrays; class
  `size` feeds the trailing pad and a `static_assert(sizeof == size)`.
  Report sizes honestly or the generated C++ lies.
- `type_name` is engine-native and passes through `TYPE_MAP` untouched when
  unknown — `TYPE_MAP` only knows UE property names. Source emits C++ types
  directly (`int32_t`, `Vector2D`); do the same and it just works.
- `enums` is a list of `{"name", "members": [{"name", "value"}]}` dicts —
  used only by Unreal today.

`write_all(packages)` produces:

- one header per package with classes: `output_dir/<pkg name>.h`
- `offsets.json`:

```json
{
  "_meta": { "generator": "BIFROST SDK", "engine": "Source Engine",
             "timestamp": "...", "total_classes": 3224, "total_fields": 16428 },
  "offsets": {
    "Source2.CExampleSchemaVData_PolymorphicDerivedA": {
      "size": "0x18", "super": "",
      "fields": { "m_nDerivedA": { "offset": "0x10", "size": 4, "type": "int32" } }
    }
  }
}
```

Sizes/offsets are hex strings in JSON (canonical form per schema) — the
`SDKGenerator` handles the conversion; you keep ints in the dataclasses.

The JSON is validated against `contracts/sdk_output_schema.json` on every
`write_json` call — `_meta` requires `generator/engine/timestamp/
total_classes/total_fields`, and every class record requires `size`/`super`/
`fields`. A dump that violates it raises `SchemaValidationError` and the dump
fails with `SCHEMA_VIOLATION`, not a partial success. `engine` in `_meta` is
NOT enum-constrained ("not enum-constrained so new engines don't break the
schema" — the schema authors designed for this). This contract file is
engine-agnostic by intent; do not edit it.

Reference real output: `output/cs2/offsets.json` plus the per-package
`*.h` files in the same directory (gitignored, regenerated by dumps).

## Protocol/contract rules (what you may not touch)

- `contracts/bifrost_protocol.json` describes the IPC surface: commands,
  args, events. The `dump` command's `engine` arg is a free-form string
  documented with examples — adding an engine does NOT change the protocol
  document. You only touch it if you add a new command or a new arg to an
  existing command. For an engine PR: don't.
- `contracts/validate.py` + `tests/test_validate.py` enforce drift between
  the JSON and the Python side. `contracts/` is out of scope for engine work.
- Backend engine knowledge lives in exactly three places: `ENGINE_REGISTRY`
  (construction), `core/process.py` (detection), `KNOWN_GAME_EXES` (process
  listing labels + name hints). Adding a key to one without the others is a
  half-integration: registry alone means the engine works when selected
  explicitly but never auto-detects; detection alone means auto mode can
  return a key the registry rejects.
- The GUI engine dropdown options live in `gui/src/` (React) — backend keys
  are not auto-derived into that list, so a new engine also needs its GUI
  option added there (renderer-side change, separate from this backend flow).

## Reference shapes

- **`engines/source/`** — the one to copy for structure. `dumper.py` has
  config dataclasses (`SourceConfig`, `Source2Config`) in `structs.py`, one
  `validate()` that branches Source1 vs Source2 by module presence, and a
  `dump()` dispatch. Reads are guarded per-record, patterns live as constants
  or in structs, progress updates happen at phase boundaries, counters
  increment per class/field. `apex.py` shows the pattern library for a
  heavily-modified variant.
- **`engines/unreal/`** — the modular shape. `dumper.py` orchestrates;
  `names.py`/`objects.py`/`properties.py` are per-phase walkers; `structs.py`
  holds profile dataclasses (`UE5Profile`, `UE5_DEFAULT`, ...). Per-game
  profiles are injected via registry `extra_imports`, so the dumper class
  itself never hardcodes a game. It also shows `target_module` tiered
  resolution (`_detect_target_module`).
- **`engines/unity/`** — the variant shape. Two completely different dumpers
  (`mono.py`, `il2cpp.py`) under one engine, keyed separately
  (`unity_mono`/`unity` vs `unity_il2cpp`).
- **`engines/blizzard/`** — smallest live example: `GAME_MODULE` constant,
  `validate()` = module presence check, five dump phases, single package.

For a hypothetical CoD/Treyarch engine: Treyarch titles ship
`blackops*.exe`/`t9_*` styles with a small set of core DLLs — expect
`validate()` to check for your known module set via `list_modules()`, dumpers
for MW/BO generations to be one class + config structs + registry keys, and
per-patch function/pattern churn to live in `structs.py`, per the README's
known-limits note.

## Testing conventions

Suite layout (all offline unless noted; no game required):

- **Config/unit tests** — registry entries resolve, struct dataclass defaults
  are sane, pure functions behave. See `tests/test_unity_ambiguity.py`:
  imports the bridge function directly, no fixtures, no mocks.
- **Mock-memory dump tests** — the bread and butter. A dict-backed
  `MockMemoryReader` (implementing only the surface your dumper touches) with
  `write_*` helpers to plant fake structures, plus `patch("core.scanner.
  PatternScanner", return_value=scanner_mock)` where the dumper pattern-scans.
  See `tests/test_blizzard_mock.py` and `tests/test_unreal_mock.py`: they
  build fake module lists, write structs at fake addresses, wire scan hits to
  RIP-relative resolutions, then assert on `validate()`, returned packages,
  class names, sizes, and field offsets.
- **Schema round-trip** — `tests/test_sdk_output_schema.py` validates output
  shapes against `contracts/sdk_output_schema.json` (the same validator
  `SDKGenerator` runs).
- **Live tests** — real process/backend tests that cannot run in CI skip
  themselves with `pytest.skip(...)` when the prerequisite is absent
  (`tests/test_explorer_live.py` skips when rizin isn't provisioned).
  `tests/test_backend_live.py` spawns the real `api_server.py` as a
  subprocess and talks stdio JSON. There is no special marker for
  "target game not running" — the convention is: mock tests always run,
  live tests skip when their target isn't there. `tests/conftest.py` does
  nothing but put the project root on `sys.path`; mock reader classes are
  defined per test file, not shared.

Expected test set for a new engine (`tests/test_your_engine_mock.py`):

1. config-only: registry key exists and `create_dumper` builds the dumper
   from a mock reader (`assert is_known_engine("your_engine")`);
2. mock-memory: planted modules pass `validate()`;
3. mock-memory: planted structure walk yields expected packages/classes/
   field offsets/sizes (dict-backed reader + planted structs, no scanner
   needed if your walk is pure pointer chasing);
4. schema: run `SDKGenerator(tmp_dir, ...).write_all(packages)` from the
   mock dump and assert it doesn't raise — proves output conforms;
5. negative: wrong modules fail `validate()` and `dump_and_generate()`
   raises `RuntimeError`;
6. optional live test, skipped when the target exe isn't running (follow the
   `test_explorer_live.py` skip style) — attach, dump, assert counters > 0.

## Step-by-step checklist

1. Copy `engines/template/` to `engines/<your_engine>/`. Rename the class to
   `<Name>Dumper`, set `ENGINE_NAME`.
2. Fill `structs.py` with the in-memory layout dataclasses (module names,
   struct field offsets, AOB patterns) — config lives here, never hardcoded
   in the dumper body. For per-game drift, add one dataclass per game.
3. Implement `validate()` — module-presence check against
   `self.reader.list_modules()` first, cheap pattern confirmation second.
   Return False (with `_log_error` context) when wrong.
4. Implement `dump()` — resolve globals/bases, walk structures, append
   `SDKClass`/`SDKField` into one or more `SDKPackage`s. Set `full_name`
   with your engine prefix. Increment `self.progress.classes_found` /
   `fields_found` as you go.
5. Phase the walk with `_update_progress(stage, detail, percent)` calls and
   wrap per-record reads in try/except + `_log_warn`, per Source/Blizzard.
6. Add registry entries in `engines/registry.py`: the base key, plus one key
   per variant sharing the class. Mind `extra_imports` for profiles.
7. Add detection to `core/process.py`: `detect_engine_from_modules()` rule
   (the path `run_dump("auto")` actually uses) and optionally an
   `ENGINE_SIGNATURES` entry for the psutil path.
8. Add known exes to `KNOWN_GAME_EXES` in `gui_bridge.py` so `list_processes`
   labels them and the engine shows up pre-attach.
9. If your engine has a Mono/IL2CPP-style ambiguity, add the auto-correct
   pass in `run_dump` + tests like `tests/test_unity_ambiguity.py`.
10. Add `tests/test_<your_engine>_mock.py` following the template above
    (dict-backed reader; skip live parts when no target).
11. Contracts: do NOT edit `contracts/`. Only if the GUI needs a new dump
    arg would `bifrost_protocol.json` + `validate.py` change — coordinate
    that as a separate change.
12. If the GUI dropdown needs your engine, add the option under `gui/src/`
    (renderer-side; the backend snapshots already list your registry key).
13. Update `README.md`: engines table row (key + note), and mention in the
    "Adding an engine" paragraph if behavior changed.
14. Verify — repo root:

    ```
    & "C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pytest tests -q
    ```

    Run the new file first while iterating:

    ```
    & "C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pytest tests/test_<your_engine>_mock.py -q
    ```

15. If anything under `gui/` was touched, verify the JSX grammar gate:

    ```
    npx.cmd vite build
    ```

    (from `gui/`). Then a real attach-and-dump against a live target —
    compile-only is not done; log lines and a non-empty offsets.json are done.

## Canonical interpreter

All pytest/pyinstaller runs use the 3.14 canonical python
(`C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64\python.exe`). The
`python` on PATH is a different install missing deps like `iced_x86`. Never
invoke bare `pyinstaller` or bare `python` for this repo's verification.
