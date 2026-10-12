# FRINET

**F**rida + Te**net** — a multi-platform execution tracer, and an IDA Pro trace
explorer that keeps the disassembly *and* the Hex-Rays pseudocode in sync with
the trace timeline.

<p align="center">
<img alt="FRINET" src="screenshots/frinet.png"/>
</p>

Trace a function on a live process with Frida, then load the trace into IDA and
scrub through time: the instruction pointer follows the trace in the listing,
the decompiled view highlights the most precise expression it can find, and
the register, memory and event panels all follow.

This repository is a fork of
[Synacktiv's FRINET](https://github.com/synacktiv/frinet), which extends
[gaasedelen/tenet](https://github.com/gaasedelen/tenet) with new trace formats
and views. Upstream documentation that still applies has been preserved and
updated rather than discarded.

* [Synacktiv blogpost](https://www.synacktiv.com/publications/frinet-reverse-engineering-made-easier)
  — the design and motivation behind the FRINET additions.
* [Tenet blogpost](http://blog.ret2.io/2021/04/20/tenet-trace-explorer/) — the
  original tool this plugin is built on.

---

## Contents

* [Tracer](#tracer)
* [Installing the IDA plugin](#installing-the-ida-plugin)
* [Loading a trace](#loading-a-trace)
* [The FRINET trace format](#the-frinet-trace-format)
* [Pseudocode synchronisation](#pseudocode-synchronisation)
* [Panels](#panels)
* [Navigation](#navigation)
* [Supported versions](#supported-versions)
* [Testing](#testing)
* [Debugging](#debugging)
* [Limitations](#limitations)
* [Repository layout](#repository-layout)

---

## Tracer

`tracer/trace.py` instruments a module in a running (or newly spawned) process
and writes an execution trace. Output is written once per thread, to
`tracer/traces/`.

### Platform and architecture support

| | Status |
|---|---|
| **Platforms** | Windows, Linux, Android, iOS (anything Frida runs on) |
| **Fully supported** | `arm64`, `x64` |
| **Partially supported** | `arm`, `x86` — slower and less precise memory tracking, but usually good enough |

### Dependencies

Python 3 and Frida:

```
pip install frida
```

### Usage

```
usage: trace.py [-h] [-v] [-D DEVICE] [-U] [-R] [-H HOST] [-m] [-a ARGS] [-e]
                [-s] [-E END] [-F FLUSHADDR]
                {spawn,attach} ... process module addr

positional arguments:
  {spawn,attach}
    spawn               Spawn process
    attach              Attach to process
  process               attach:[process name or PID]; spawn:[binary path or
                        package name]
  module                module name to instrument
  addr                  entrypoint function address

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -D DEVICE, --device DEVICE
                        connect to device with the given ID
  -U, --usb             connect to USB device
  -R, --remote          connect to remote frida server
  -H HOST, --host HOST  connect to remote frida server on host
  -m, --multirun        do not unhook after first execution
  -a ARGS, --args ARGS  comma-separated argument list for spawn (including
                        binary name) : "/bin/sh,-c,ls"
  -e, --exclude         exclude all other modules (memory tracing will be
                        inaccurate)
  -s, --slow            use slower JS implementation (multiarch)
  -E END, --end END     specify end address instead of function exit (-1 to
                        never end)
  -F FLUSHADDR, --flushaddr FLUSHADDR
                        Address of instruction that will force a trace flush
                        (useful when investigating a crash)
```

`FUNC_ADDR` is the **entrypoint of the trace**, not the origin of the offsets
in the file. Offsets are always measured from the traced module's runtime base
(see [the format](docs/frinet-format.md)).

### Example: spawn a new process and trace

```
python3 trace.py spawn /bin/ls ls 0x1234 -a '/bin/ls,-la'
```

Traces one execution of the function at `0x1234`, until it returns. Use `-E` to
set an explicit end address, or `-m` to keep tracing across repeated calls.

### Example: attach to a process on an Android device

```
python3 trace.py attach sh sh 0x1234 -U
```

On Android the process environment is deliberately **not** forwarded to the
spawned process: `env` is omitted entirely, so the app gets the environment its
own zygote would give it rather than whatever the host happened to export.
Detection is based on the device reported by Frida, not on the host OS — which
is what made the old behaviour wrong when tracing an Android device from
Linux or macOS.

### Slow mode

`-s` selects the pure-JavaScript tracer, which works on every architecture but
is slower and records memory less precisely. The FRINET `off=` conversion runs
in both modes.

---

## Installing the IDA plugin

The plugin lives in the `tenet/` submodule (a fork of Tenet with the FRINET
additions). It still reads legacy `.tenet` traces, so it can replace a stock
Tenet installation outright.

1. Clone **recursively** — the plugin is a submodule:

   ```
   git clone --recursive https://github.com/staleroot/frinet.git
   ```

   If you already cloned without it: `git submodule update --init --recursive`.

2. Copy the plugin into IDA's plugin directory:

   ```
   cp tenet/plugins/tenet_plugin.py <IDA>/plugins/
   cp -R tenet/plugins/tenet       <IDA>/plugins/
   ```

   Find the directory from IDA's Python console:

   ```python
   import idaapi, os; os.path.join(idaapi.get_user_idadir(), "plugins")
   ```

3. Restart IDA.

---

## Loading a trace

With the matching binary open in IDA:

```
File -> Load file -> Tenet / FRINET trace
```

The file dialog lists both `*.frinet` (the new format, with per-event offsets)
and `*.tenet` (legacy, still fully supported).

The plugin needs to know which image the trace belongs to. It identifies it
from the database's own segment layout and validates the result against the
offsets actually present in the trace. When the evidence is genuinely
ambiguous it asks rather than guessing — see
[Addressing](docs/architecture.md#addressing-pc-off-static_ea-and-why-they-stay-distinct).

Then: **scroll on the timeline** to step forward and backwards in time, hold
`SHIFT` while scrolling to step over calls. Everything below follows.

---

## The FRINET trace format

Upstream Tenet traces carry a runtime instruction pointer per event. That is
enough to navigate only as long as the process layout matches the database's —
which is exactly what stops being true once ASLR, a rebase or a stripped
`.so` dump gets involved.

FRINET adds one thing to the header and one thing to each event:

```
slide=0x779684f000
off=0x59294,x13=0xe3,pc=0x77968b2294
```

* `slide=` is the traced module's **runtime base**.
* `off=` is `pc - slide`, present only for events that executed inside the
  traced module.

`off` is the plugin's **primary navigation key**, which makes navigation
independent of the runtime layout:

```
static_ea = idb_module_start + off
```

Events that executed outside the traced module keep their original line
unchanged — they stay in the timeline, and are never *falsely* mapped into the
database by a guess.

Full specification: **[docs/frinet-format.md](docs/frinet-format.md)** — the
header, the event grammar, per-thread files, record boundaries, and exactly
what is *not* changed relative to legacy traces.

---

## Pseudocode synchronisation

The disassembly has always followed the trace. FRINET makes the **Hex-Rays
pseudocode follow it too**, highlighting the most precise expression it can
find rather than just the line.

```
static_ea  =  idb_module_start + off
                 |
                 v
   ctree item  ->  rendered line  ->  column + span
```

* **Five explicit precision levels** — `expr` → `item` → `line` → `nearest` →
  `none` — and the level used is *reported*, so an approximate highlight never
  looks like an exact one.
* **No guessing.** Events without an `off=`, and addresses outside the traced
  module, are never mapped into the pseudocode.
* **Responsive while scrubbing.** Coalesced updates, stale-result rejection,
  bounded LRU caches, and prefetch that never forces a decompilation you did
  not ask for.
* **Main-thread only.** Every IDA and Hex-Rays call runs on the main thread;
  nothing reaches into the UI from a worker.

### How a view gets opened

The panel only ever follows the function it is showing. Stepping into another
function retargets it, and stepping back retargets it again:

1. A view already shows the traced function → used untouched.
2. A view is open on another function → **retargeted**, so one window follows
   the trace instead of the trace dropping a window per function.
3. Nothing is open → **opened**.
4. Nothing is open, but one was opened earlier → the user closed it, so it is
   opened **once** more and then left closed (`pseudocode-closed-by-user`).
5. A function that fails to open is retried up to three times, then skipped
   (`pseudocode-open-failed`).

Set `TENET_NO_PSEUDOCODE_OPEN=1` to disable auto-open entirely, restoring the
stricter "decline unless a view already shows the function".

---

## Panels

**Event Info** — a dockable panel showing, for the selected event: index,
thread, `pc` (runtime), `off` (module offset), `static_ea` (address in the
IDB), whether it is mapped, the pseudocode precision, the registers that
changed, and the memory read/written. Values are copyable; the address row is
navigable.

**Registers** — gains a hexadecimal/decimal toggle and base-aware copy. A
register with no recorded value renders as `?` and copies nothing; it is never
shown or copied as `0`.

**Memory views** — read *exclusively from the trace*. They never fall back to
live process memory or to the IDB's static bytes, because either would
fabricate a history the trace does not contain. Unrecorded bytes render as
`??`, which is the truth.

All panels are dockable, are created at most once per session, and shut down
cleanly when a trace is unloaded or replaced.

---

## Navigation

Beyond stepping the timeline:

| Action | How |
|---|---|
| Back / forward history | the toolbar arrows |
| Bookmarks | bookmark the current position and return to it later |
| Previous / next occurrence | of the address currently under the cursor |
| Jump to index | the timestamp shell (also accepts `!50` for "50% into the trace", `!last`) |
| Search by address or offset | from the timeline |
| Execution breakpoints | double-click the instruction pointer in the registers view |
| Memory breakpoints | double-click a byte in a memory view |
| Search bytes | memory view context menu — searches across space **and** time |

The upstream navigation walkthrough in
[tenet/README.md](tenet/README.md#tenet-usage-guide) still applies to all of these.

---

## Supported versions

| Component | Status |
|---|---|
| **IDA Pro 9.4** | Primary target. Every new API here was verified against the 9.4 SDK and a live 9.4 + Hex-Rays session. |
| IDA Pro 8.x | Plugin loads; existing `8.+`/`9.+` compatibility paths are preserved. Pseudocode sync is newer and less exercised. |
| **Hex-Rays** | Required for pseudocode synchronisation. Without it the plugin loads and traces are fully browsable; only the pseudocode highlighting is inert. |
| Qt bindings | IDA **≤ 9.1** ships Qt5/PyQt5; IDA **9.2+** (including 9.4) ships Qt6/PySide6 (Qt 6.8). The shim resolves whichever binding the host already has loaded and normalises the Qt6 differences (`QAction`/`QActionGroup`/`QShortcut` moved to `QtGui`, `exec_()` renamed `exec()`, `QStandardItem` living in `QtGui`) so the same call sites work on both. PySide2 is also accepted. Mixing two bindings in one process is unsafe, so the already-loaded binding always wins. |
| Python | IDA's bundled Python 3. |

---

## Documentation

| Document | What it answers |
|---|---|
| **[docs/frinet-format.md](docs/frinet-format.md)** | The `.frinet` format: the `slide=` header, the `off=` field, per-thread files, record boundaries, legacy compatibility. |
| **[docs/architecture.md](docs/architecture.md)** | How a trace becomes a highlighted expression, why `pc` / `off` / `static_ea` are never interchangeable, what register and memory data actually exists, and where the limits are. |
| **[docs/manual-testing.md](docs/manual-testing.md)** | The procedure for verifying everything that needs a real IDA, Hex-Rays or a device. It is a *plan*, not a test suite — parts of it have been executed against a live IDA 9.4 session (notably the pseudocode cursor sync, which is confirmed working there), and the rest has not. |
| **[tenet/README.md](tenet/README.md)** | The plugin itself: upstream Tenet's full usage guide, plus this fork's additions. |

---

## Testing

```
python3 -m pytest tests/ -q
```

| Configuration | Result |
|---|---|
| No Qt binding installed | **305 passed, 8 skipped** |
| With PySide6 installed | **306 passed, 7 skipped** |

Of the skips, **one** is the Qt smoke test, which only runs when PySide6 is
available. The other **seven** are end-to-end tests built on `example.tenet`,
a real trace that is deliberately **not** checked in — a clone simply does not
have it, so those tests skip rather than fail on a file the repository never
shipped. Every rule they exercise (the header, the `off=` arithmetic, the
reference offset table, legacy traces carrying no offsets, the sample bound)
is also covered individually by tests that build their own traces.

### What is covered

* **The FRINET conversion** — the header, the `off=` computation, field
  ordering, out-of-module events, partial and malformed records, idempotency,
  per-thread files.
* **The Android spawn fix** — kwargs construction, Android detection from
  `query_system_parameters()`, case-insensitivity, stdout forwarding.
* **The trace parser** — offsets, missing registers and memory, legacy
  `.tenet`.
* **Address resolution** — image identity, ambiguity handling, rebased
  databases, `idb_module_start` derived from the real segment layout.
* **The pseudocode lexer and expression map**, the caches, and the prefetch
  planner.
* **The synchronisation controller**, driven with injected fakes:
  coalescing, cancellation, exception isolation, and the contract that a
  controller cannot be built without a scheduler.
* **Cursor navigation** — a refused `jumpto` and a *raising* one both surface
  as `applied=False` rather than escaping. The route that IDA 9.4 actually
  allows is pinned explicitly: every `*place_t` class there is abstract, so
  the view's own place is cloned and the clone retargeted. Tests assert it
  moves the cursor, that the view's own place is *never* mutated, that a clean
  success still logs itself, and that a missing clone API falls through to
  construction instead of giving up.
* **Place-class discovery** — `place_t_as_*` downcast helpers are recognised
  as helpers rather than offered as places (they return `None` instead of
  raising, so a `None` would otherwise reach `jumpto` and report success while
  moving nothing); every refusal records *why*; a remembered class resolves
  back to its owning module; a stale cache falls back to full discovery;
  construction is answered once rather than re-noting the same refusals on
  every trace event; and the one-shot navigation-surface dump is printed once.
* **The view registry** — distinct wrappers of one window are recognised as
  one, retargeting does not record it again, and the list cannot grow without
  bound.
* **The Qt layer** — binding resolution, the Qt5→Qt6 normalisation, the
  `exec_`/`exec` fallback, the IDA `TWidget`→Qt bridge selection, and the
  theme-hint fallback that keeps a failed bridge from aborting a trace load.
* **A static audit** that every name referenced by the plugin is actually
  bound.

### What these tests do not prove

The non-Qt tests run without IDA, without Hex-Rays and without a device. They
claim **nothing** about a live IDA session, real decompiler output, real
docking behaviour, or real device tracing. The Qt smoke test proves the views
*import and construct* under PySide6 — it does not prove they dock, paint or
behave correctly inside IDA.

In particular:

* The **Android spawn fix** is verified here by mocked unit tests. Confirming
  it on hardware is step 2 of the manual plan.
* **Pseudocode highlighting precision and docking** require a live IDA 9.4 +
  Hex-Rays and are steps 5–7 of the manual plan.

### Why `tests/conftest.py` plants IDA and Qt stubs

`tenet.util.log` imports the disassembler API unconditionally, while
`tenet/ui/__init__.py` only imports the Qt views when `QT_AVAILABLE`. The two
gates line up such that with **no** Qt binding installed the entire IDA chain
is skipped, every test passes, and the suite has quietly never exercised the
import path IDA will take.

Install PySide6 — exactly what the Qt smoke-test section below tells you to
do — and `pytest tests/` stopped collecting altogether with
`No module named 'ida_ua'`. A suite that only passes because its dependencies
are absent is not passing. `conftest.py` therefore plants the `ida_*` stubs
(and, when no binding is installed, a permissive Qt stand-in) at collection
time, so both configurations import `ida_api` the way IDA will.

Two tests were broken by that same gap and fixed alongside it: the
"no bindings ⇒ unavailable" pair popped `sys.modules` and reloaded the shim,
which does a real `import PySide6` — so the module came straight back and the
test asserted on a state it never created. They now block the import mechanism
instead, which is what "not installed" means.

### Static name audit (always on)

Three separate IDA-side failures in this project were the same class of bug: a
Qt (or IDA) name that imports fine and then raises `NameError` the moment a
code path actually executes inside IDA — invisible to a unit test and to
`pyflakes`, which gives up on any file with a star import (and nearly every
view here has one).

```
python3 -m pytest tests/test_frinet_undefined_names.py -q    # 5 passed
```

The audit parses the plugin and reports any name that resolves to nothing,
resolving `from X import *` against the *source* of `X` recursively and
delegating scoping to the stdlib's `symtable`. It is fully static: no IDA, no
Qt binding, and no execution. Two of its own tests pin its behaviour — one
that it still catches a bare `Qt.<enum>` with no binding, and one that it
stays quiet about locals and star-imported names — because an audit that
silently reports nothing is worse than no audit at all.

### Qt smoke test (optional, but recommended)

Most Qt breakage is **not** caught by fake-module tests: Qt6 moved classes
between modules, and those moves surface as an `AttributeError` inside a
view's `__init__` at runtime — i.e. the plugin loads, the trace opens, and
then no UI appears.

```
pip install PySide6
python3 -m pytest tests/test_frinet_qt_smoke.py -q     # 1 passed
python3 -m pytest tests/ -q                            # 306 passed, 7 skipped
```

Point it at an existing copy instead of installing:

```
FRINET_PYSIDE_PATH=/path/to/pyside python3 -m pytest tests/ -q
```

It builds `EventInfoView`, `RegisterView`, `MyTreeView`, `HexView` and
`TraceDock` under a real PySide6 on Qt's `offscreen` platform, in a
subprocess, and asserts `QtWidgets.QAction` was aliased. It is verified to
fail on the real bug: reintroducing `QtWidgets.QStandardItem` (a `QtGui`
class) makes it fail with the same message IDA printed.

---

## Debugging

Every failure reported so far has happened *inside IDA*, where neither the unit
tests nor a file log can see what the UI actually decided. There are two
separate switches, and they answer different questions:

| Variable | Where it goes | Answers |
|---|---|---|
| `TENET_DEBUG` | disassembler **output window** | "what is the plugin deciding, right now?" |
| `TENET_DEV` | `tenet_logs/tenet.<pid>.log` | "what did the plugin do, overall?" |

`TENET_NO_PSEUDOCODE_OPEN` is not a logging switch — it changes what sync
*does*.

For a session that misbehaves, use `TENET_DEBUG`. On Windows:

```
set TENET_DEBUG=1
"C:\Program Files\IDA Professional 9.4\ida.exe"
```

(`setx TENET_DEBUG 1` persists it; delete with `setx TENET_DEBUG ""`.) Restart
IDA after setting it — the plugin reads it once at import.

### Message legend

| Message | Meaning |
|---|---|
| `trace: arch=… has_offsets=… slide=…` | `has_offsets=False` means the file contains **no `off=` fields at all** — a legacy `.tenet`, or every event fell outside the traced module. Navigation then uses the ASLR heuristic only. |
| `offsets: this trace carries no off= fields…` | Same, stated at the point it is decided. |
| `offsets: N db segments, imagebase=…, M sampled offsets` | What the resolver had to work with. A low `M` means the trace is small. |
| `offsets: trace image … vs database image …` | The two names. A mismatch is not fatal (structural evidence wins) but is worth eyeballing. |
| `offsets: resolved to Resolution(origin=…)` | The final decision, with its reason. |
| `step idx=… ip=… off=… -> rebased=… mapped=…` | One line per timeline step. This is the key one: it separates *"the offset did not map"* from *"we jumped, but to an address the database does not contain"*. |
| `step: falling back to idx=…` | The address was unmapped, so the nearest earlier mapped event is used instead. |
| `step: not navigating` | Nothing in the trace maps into this database — no jump will ever happen. |
| `paint: hook fired, idx=… current=…` | The disassembly repaint hook is alive. **If this never appears, the highlighter is not running at all**, whatever the addresses say. |
| `pseudocode sync attached (hex-rays available=…)` | Whether the Hex-Rays side is wired. `False` means pseudocode highlighting is inert (expected without Hex-Rays). |
| `sync: queued flush for idx=…` → `sync: flush idx=…` | **The pair to check when "nothing happened".** Both appear → the sync ran and the `SyncEvent` that follows says what it decided. Only *queued* appears → the position change reached the sync but its timer never fired. Neither → the change never reached the sync layer at all, so the problem is upstream of it. |
| `sync SyncEvent(idx=…, ea=…, applied=…, reason=…)` | Every pseudocode sync attempt, with why it did or did not apply. **`applied=False` next to an empty `reason` and `precision='expr'` means every stage resolved and only the cursor move was refused** — check that against the `pseudocode jump …` line below. `no-ctree-item` means a view is showing the function but nothing in it maps to that address. |
| `pseudocode: … -> target=… open=[…]` | A view had to be obtained, and how. `target=` is the function the trace is in, `open=[…]` every pseudocode view we can see. **This line separates "nothing was open" from "it was open on a different function"**, which from `SyncEvent` alone are indistinguishable and need different fixes. |
| `pseudocode jump to line … (x=…) via …` / `… failed: …` | The cursor move itself. `via … line_place(clone)` is the route that works on IDA 9.4: every `*place_t` class there is abstract, so a place cannot be *constructed* — the view's own place is cloned and the clone retargeted (`n` is the line field). A refused `jumpto` *returns* `False` rather than raising, so without this line a sync that maps perfectly is indistinguishable from one that never ran — and a **clean success logs too**, because silence and failure otherwise look identical. On failure the line carries the attempt list: which getter, which downcast, which place class, and every refusal or exception in order. |
| `pseudocode nav surface: …` | A one-shot block printed after a failed jump where nothing could be built: every `*place_t` the build exposes, which navigation APIs are present, and the full member list of `ida_hexrays.vdui_t`. Printed once per trace, never once per event. |

When reporting a problem, the whole output window from a `TENET_DEBUG=1`
session — load the trace, step a few times, scrub the timeline — plus the trace
file and the IDB's image name, is enough to localise it.

---

## Limitations

* **Expression nesting is inferred from token order, not a ctree walk.** Items
  that render on the same line are ordered correctly; two items at the same
  address on *different* lines cannot be distinguished. Span widths are
  approximate (they run to the next token, not the item's true extent).
  Sufficient to place a cursor, not to compute an exact selection.
* **`nearest` is approximate by definition** and is always labelled as such.
* **Registers are a sparse delta.** A register never written during the traced
  region has no value and shows as `?`.
* **Memory is what the tracer captured, and nothing more.** Bytes written
  before tracing began, or outside the traced region, may be absent and render
  as `??`. The plugin will not fill the gap from the IDB or a live process.
* **Without `off=`**, addressing falls back to the ASLR-slide heuristic, which
  is less precise — particularly on rebased or partially-loaded images.
* **The prefetch index is bounded** (`MAX_PREFETCH_SCAN`); on traces larger
  than that it covers the beginning only, and the plugin reports the
  truncation rather than silently doing less.
* **Threads are not cross-correlated.** Each per-thread file is independent;
  there is no global ordering between threads.
* **An image-name mismatch can be overridden.** When the structural evidence is
  overwhelming (one candidate, every sampled offset mapped, plenty of them in
  code) the trace is mapped even if the trace filename and the IDB's root
  filename disagree — with a loud console warning instead of a prompt. If that
  judgement call is ever wrong, open the matching binary and reload the trace.
* **Qt is verified up to "the widgets build", not further.** The Qt5→Qt6
  normalisation and the `TWidget`→Qt bridge are checked against a real PySide6
  by the optional smoke test, plus a stubbed `ida_kernwin` for the bridge.
  Docking, painting and interaction inside a live IDA are still manual-test
  territory.
* **The bridge deliberately avoids IDA's `TWidgetToPySideWidget`.** On IDA 9.4
  that function resolves `ctx.QtGui` on `sys.modules['__main__']`, which is the
  plugin module rather than IDA's console — so it raises for every plugin.
  `TWidgetToQtPythonWidget` is used instead (IDA's own recommended workaround),
  and every candidate is *called* rather than trusted by name, so a future IDA
  change degrades into a readable error listing each attempt instead of an
  obscure `AttributeError`.
* **IDA-dependent behaviour is claimed only where it has actually been run.**
  Cursor navigation, view acquisition and the `place_t` clone route were
  verified on a live IDA 9.4 + Hex-Rays session. Everything else marked
  "manual" in `docs/manual-testing.md` remains unexecuted.

---

## Repository layout

```
tracer/
  trace.py             The CLI tracer (Frida)
  trace.js             CModule-mode instrumentation; reports slide + size
  frinet.py            Pure FRINET conversion (.tenet text -> .frinet)
  slow/                The multi-architecture JavaScript fallback
  trace_arm64.c        Per-architecture CModule sources
  trace_x64.c

tenet/                 The IDA plugin (submodule — see tenet/README.md)
  plugins/tenet_plugin.py
  plugins/tenet/
    trace/             Trace parsing and address resolution (addressing.py)
    sync/              Pseudocode synchronisation
      lexer.py           COLOR_ADDR tokens out of rendered pseudocode
      pseudomap.py       ea -> most precise expression (5 levels)
      controller.py      coalescing, caching, stale-result rejection
      hexrays_api.py     decompile, find/open pseudocode widgets, cursor
    event_info.py       The Event Info model
    ui/                 Views (event_info_view, reg_view, hex_view, tree_view)
    util/qt/            The Qt binding shim (PySide6 / PyQt5 / PySide2)

tests/                 Automated tests — no IDA, Qt or device required
docs/                  Format spec, architecture, manual test plan
tools/                 IDA-side probes used during development
```

---

## Credits and license

FRINET builds directly on two projects, and this fork would not exist without
either:

* **[Tenet](https://github.com/gaasedelen/tenet)** by
  [Markus Gaasedelen](https://twitter.com/gaasedelen) — the trace explorer.
* **[Synacktiv's FRINET](https://github.com/synacktiv/frinet)** — the tracer
  and the original plugin extensions.

This fork is not submitted upstream. The new features break some legacy
Tenet behaviour (the compressed trace format is currently removed), and the
plugins were kept separate rather than merged until those are restored and the
changes are better tested across IDA versions.

MIT licensed — see [LICENSE](LICENSE).
