# Manual test plan

This file is a **procedure**, not a result.

Everything below needs a live IDA, a live Hex-Rays decompiler, a real Qt
event loop, or a real device — none of which exist in the environment where
the automated tests run. **Nothing in this file has been executed by the
author of these changes.** Treat every checkbox as unchecked until *you* have
run it on your own IDA and your own trace.

Run the automated suite first; it is the only part that is claimed to pass:

```
python3 -m pytest tests/ -q
```

## 0. Prerequisites

| Item | Version tested against | Notes |
|---|---|---|
| IDA Pro | **9.4** (target). Plugin also supports 8.x paths where noted. | The SDK in the workspace is 9.4. |
| Hex-Rays | Ships with IDA 9.4, matching arch (x64 / arm64). | Sync is inert without it, and degrades to no highlighting. |
| Python | IDA's bundled Python 3. | |
| Qt binding | **PySide6** (IDA 9.2+, including 9.4 — the version under test). IDA ≤ 9.1 is Qt5/PyQt5 and also supported. | See §7. |
| Device | Any Frida-supported Android / Linux target. | For tracer tests only. |

Install:

```
cp tenet/plugins/tenet_plugin.py ~/.idapro/plugins/
cp -R tenet/plugins/tenet       ~/.idapro/plugins/
```

## 1. Trace generation (tracer)

### 1.1 `.frinet` output and header

```
python3 trace.py spawn /bin/ls ls 0x<entry> -a '/bin/ls,-la'
```

- [ ] A `traces/ls_<epoch>_<tid>.frinet` file appears (not `.tenet`).
- [ ] Its **first line** is exactly `slide=0x...` — one line, no `module=`,
      no `func=`.
- [ ] The slide value equals the runtime base of `ls` (check with
      `readelf -l` / `cat /proc/<pid>/maps` while it runs, or log it).
- [ ] Subsequent lines are `off=0x...,<original fields>` — `off=` first,
      original field order preserved, IP field name unchanged (`pc` on
      arm64, `rip` on x64).

### 1.2 Offsets are correct

Take three events near the start of the trace and verify by hand:
`off == pc - slide`.

- [ ] `off=0x0` appears for an event at exactly the module base (if the
      entry point is the base).
- [ ] Offsets increase monotonically within a basic block.
- [ ] The reference values from `example.tenet` reproduce:
      `0x77968b2290 - 0x7796859000 = 0x59290`.

### 1.3 Out-of-module events get no `off=`

Trace something that calls into libc, and inspect events inside libc:

- [ ] Events with a PC outside `[slide, slide+size)` have **no** `off=`
      field, and their line is byte-for-byte the original.
- [ ] They are still present in the trace (not dropped).

### 1.4 Per-thread files

Trace a multi-threaded target:

- [ ] One file per thread, named `<proc>_<epoch>_<tid>.frinet`.
- [ ] **Each** file starts with its own `slide=` header.
- [ ] Events within a file are in execution order; no duplicates, no gaps.

### 1.5 Slow mode (`-s`)

```
python3 trace.py spawn /bin/ls ls 0x<entry> -s -a '/bin/ls,-la'
```

- [ ] Output is still `.frinet` with `slide=` and `off=`.
- [ ] Field order matches the CModule output convention (regs, then pc last,
      then mw/mr).
- [ ] No duplicated `off=`, no corrupted lines.

### 1.6 Partial records / shutdown flush

Trace a very short function that returns immediately, or kill the target
mid-trace:

- [ ] No line is truncated mid-record (every line parses as `k=v` pairs).
- [ ] The last record of the file is complete (the final flush ran).
- [ ] No record appears twice.

### 1.7 Idempotency

Re-run the conversion over an already-converted file (or reload and
re-export):

- [ ] Lines that already carry `off=` are unchanged — no `off=0x..,off=0x..`.

## 2. The Android spawn fix

This is the bug fix most worth verifying, because it fails *silently* on a
device you do not have in front of you.

**What was wrong:** `Device.spawn()` was passed `env={...}` unconditionally.
Frida on Android rejects or mishandles `env`, so spawning an Android app
failed while the identical command worked on Linux.

**The fix:** `env` is omitted entirely on Android. The Android decision comes
from `Device.query_system_parameters()` (the *target*), never from the host
OS.

### 2.1 Spawn on Android (the actual regression)

On a real Android device with a Frida server running:

```
python3 trace.py spawn com.example.app libnative.so 0x<entry> -U
```

- [ ] The app spawns (previously: frida error about `env`).
- [ ] The trace is produced and non-empty.
- [ ] Spawned app's **stdout is still forwarded** to your terminal
      (`stdio="pipe"` is retained — verify by tracing something that prints).

### 2.2 Spawn on Linux (no regression)

```
python3 trace.py spawn /bin/ls ls 0x<entry> -a '/bin/ls,-la'
```

- [ ] Spawns fine, trace produced, stdout forwarded.
- [ ] (`env` *is* passed on desktop; add a temporary print of the spawn
      kwargs if you want to confirm.)

### 2.3 Attach on Android

```
python3 trace.py attach <proc_or_pid> libnative.so 0x<entry> -U
```

- [ ] Attaches to the running process.
- [ ] No `env` is passed (attach never passes it, but confirm no crash).

### 2.4 Verify the decision source

If you have a frida REPL, check what `device.query_system_parameters()`
returns on your device — confirm it reports `os.name`/`os.id` containing
`"Android"` (either case; the helper is case-insensitive). The unit tests
cover `"Android"` and `"android"`; confirm your frida build's actual value.

## 3. Loading in IDA

- [ ] `File -> Load file -> Tenet / FRINET trace` lists **both** `*.frinet`
      and `*.tenet`.
- [ ] Loading a `.frinet` trace prints the slide and event count.
- [ ] Loading a legacy `.tenet` trace still works (no crash, no offsets).
- [ ] Loading a **second** trace over an open one replaces it cleanly: the
      old timeline, registers, memory views, history, and bookmarks are all
      gone; no stale state.

## 4. Addressing and image identity

### 4.1 Correct mapping (the happy path)

- [ ] Timeline scrubbing moves the disassembly to the right instruction.
- [ ] The address shown in the Event Info panel satisfies
      `static_ea == idb_module_start + off`, and `idb_module_start` matches
      the **first executable segment**, not necessarily `get_imagebase()`.

### 4.2 Rebased / non-zero-base image (the interesting case)

Load a PIE binary that IDA has rebased to a non-default base, and trace it
at runtime:

- [ ] Events still map to the correct instructions.
- [ ] Confirm `idb_module_start != get_imagebase()` in this IDB, and that
      mapping is nonetheless correct.

### 4.3 Ambiguity prompt

Construct a trace whose sampled offsets do not discriminate between two
candidate origins (or temporarily lower `MIN_ACCEPT_SCORE` to force it):

- [ ] A confirmation dialog appears listing the candidates.
- [ ] Choosing a candidate maps accordingly.
- [ ] **Cancelling leaves the trace unmapped** — no guessing, and the plugin
      still works for browsing.

### 4.4 Image identity (mismatch, and when it does *not* block)

The image name is a **soft** signal (binaries get renamed, the IDB gets
saved under another name, Android libs carry a `lib` prefix), while offsets
that land squarely in the database are **hard** evidence.

Load a trace of `libfoo.so` while `libbar.so` is open in IDA:

- [ ] **Weak evidence** (few sampled offsets, or some of them fall outside
      the database): a confirmation dialog appears listing the candidates.
      Cancelling leaves the trace unmapped.
- [ ] **Overwhelming evidence** — a single candidate, every sampled offset
      mapped, and a good number of those on *code* (this is what a normal
      trace looks like: e.g. 403/403 offsets mapped, 363 in code) — no
      dialog appears. Instead the output window shows a clearly delimited
      warning naming both images, and the mapping proceeds.
- [ ] Confirm the warning names the *trace* image and the *database* image
      separately, and that navigation still lands in the right place.

This is the case a real session hit: a `PerfectPiano_*.frinet` trace opened
against a database whose root filename did not match was previously stopped
for confirmation even though all 403 sampled offsets mapped.

### 4.5 External events are never falsely mapped

- [ ] Events with no `off=` (libc, linker) stay in the timeline.
- [ ] Selecting one does **not** move the pseudocode to a wrong expression.
- [ ] The disassembly may fall back to the last mapped address (existing
      Tenet behaviour), but pseudocode highlighting must not appear.

## 5. Pseudocode synchronisation

Requires an IDB with Hex-Rays.

### 5.1 Obtaining a view

Run with `TENET_DEBUG=1` and watch for `pseudocode: … -> target=… open=[…]`.

- [ ] **Nothing open:** close every pseudocode window, then step. One window
      opens showing the traced function, and the `SyncEvent` reports
      `applied=True`.
- [ ] **Open on another function:** open pseudocode for an unrelated
      function, then step. That window is *reloaded* with the traced
      function — **no second window appears**, and the log says
      `retargeting the open pseudocode view`.
- [ ] **Step back** into the first function: the same window follows. Over a
      whole trace exactly one pseudocode window should exist.
- [ ] **Closed by the user:** close that window, then step again. It stays
      closed, the `SyncEvent` says `pseudocode-closed-by-user`, and nothing
      reappears.
- [ ] The `open=[…]` list in the log matches the windows you can actually
      see. A window you can see but the log does not list means the tracking
      hooks missed it — worth reporting, since that is invisible otherwise.
- [ ] **With `TENET_NO_PSEUDOCODE_OPEN=1` set, nothing** is opened or
      retargeted: `SyncEvent` says `no-pseudocode-widget` and every window
      is left exactly as it was.
- [ ] **The cursor actually moves, every time.** Step to an index whose
      `SyncEvent` reports `precision='expr'` or `'nearest'` and an empty
      `reason`. Two things must then be true: the cursor lands on that
      statement, **and** the event says `applied=True`.
      `applied=False` with an empty `reason` means everything resolved —
      address, function, ctree item — and only the cursor move was refused.
      On a working setup the companion line reads
      `pseudocode jump to line … via jumpto(ct, line_place(clone), x=…)` —
      that is the route IDA 9.4 allows (see §10), and a *clean* success
      prints it too, so an absence of any `pseudocode jump …` line is itself
      a failure. When it does fail, the line carries the attempt list: which
      getter, which downcast, which place class, and every refusal or
      exception in order. Paste that line whole; it is the entire diagnosis.
      If nothing could be built at all, a one-shot `pseudocode nav surface:`
      block follows it, listing every place class this build exposes and the
      members of `ida_hexrays.vdui_t`. Paste that too — it *is* the answer,
      and `tools/probe_hexrays_place.py` (§10) becomes unnecessary.
- [ ] **It keeps working, not just the first time.** From a *different*
      position, go back to the same index (e.g. 14) at least three times in
      a row, and try at least three different indexes — each time the view
      must move and highlight exactly as it did the first. If it stops,
      note **which of `sync: queued flush` / `sync: flush` /
      `sync SyncEvent` stops appearing**: that is the whole localisation.
      Worked-once-then-never has happened before and is not reproducible
      without that.
- [ ] **A retarget does not stand in for a cursor move.** When the trace
      crosses into another function the window reloads, and IDA scrolling to
      the new function is *not* the same as FRINET placing the cursor — only
      the `applied=True` plus `pseudocode jump … via …` pair counts as the
      navigation working. Watch for that distinction when the trace keeps
      crossing call boundaries.
- [ ] **The `open=[…]` list stays the length of the window count.** It must
      not grow by one per retarget. It listed a single window eleven times
      over before the view registry compared wrappers instead of object
      identity — a leak, and a log line that could not be trusted.

### 5.2 Expression-level highlighting

- [ ] With pseudocode open for the traced function, scrubbing moves the
      cursor to an **expression**, not just the line — e.g. a specific
      operand inside a larger statement.
- [ ] The Event Info panel's "Pseudocode" row names a precision (`expr`,
      `item`, `line`, `nearest`, `none`) that matches what you see.
- [ ] Multi-instruction-to-one-expression cases land on the expression and
      do not flicker between candidates.

### 5.3 The five levels are honest

Force each level if you can (by editing an address in the model, or by
tracing code the decompiler optimised):

- [ ] `expr` — innermost expression highlighted.
- [ ] `item` — a statement highlighted.
- [ ] `line` — the line is selected, no specific column.
- [ ] `nearest` — highlighted, and the panel says **`nearest`** (approximate),
      not `expr`.
- [ ] `none` — **nothing is highlighted**. This is the important one: an
      address the decompiler has no item for must never highlight a guess.

### 5.4 Optimised / un-decompiled code

- [ ] Trace an address inside a function that will not decompile: no crash,
      no highlight, the timeline still works.
- [ ] Trace an address the decompiler inlined away: `none`, no crash.
- [ ] Trace in a *library* function with no pseudocode: no crash.

### 5.5 Reverse sync (pseudocode -> trace)

- [ ] Clicking an expression in the pseudocode seeks the trace to the
      matching event (where an occurrence exists).
- [ ] Where no occurrence exists, nothing happens (no crash, no jump to an
      unrelated index).

### 5.6 Responsiveness

Scrub the timeline quickly across a call boundary (several functions):

- [ ] The UI stays responsive; IDA does not freeze for seconds.
- [ ] The pseudocode view does not flicker through intermediate positions
      (stale results are rejected, so only the final position is applied).
- [ ] Watch the console: no unbounded memory growth over a long session
      (LRU caches are bounded).
- [ ] Close the pseudocode window, then scrub the whole trace: it is **not**
      reopened, and no decompilation is attempted (no waitbox, no repeated
      `open_pseudocode_widget`). Only the timeline moves.

### 5.7 Un-decompiled / failing decompiler

Temporarily make `decompile()` raise (patch `hexrays_api.decompile` in the
console):

- [ ] The plugin keeps working; a debug message is logged; no traceback
      dialog, no hung UI.

## 6. Panels

### 6.0 Panels actually come up

This is the step that fails first if the Qt layer is wrong — a crash here
leaves the trace loaded but with **no UI at all**.

- [ ] `show_ui()` completes: `CPU Registers`, `Event Info`, `Memory View`
      and the timeline all appear.
- [ ] The output window contains `Loaded trace ...` followed by the panel
      banners, with no traceback in between.
- [ ] Re-opening a second trace replaces the panels rather than raising.

### 6.1 Event Info (new)

- [ ] `Event Info` docks alongside `CPU Registers` (tabbed), and can be
      closed and re-docked.
- [ ] Shows: index, thread, `pc`, `off`, `static_ea`, mapped, pseudocode
      precision, changed registers, memory read/written.
- [ ] Right-click a row -> **Copy value** copies that row only.
- [ ] Right-click with nothing selected -> copies the whole event as
      `field=value` lines.
- [ ] **Navigate in disassembler** jumps to the `static_ea` row.
- [ ] For an external event: `off` reads `external (outside module)`, and
      `static_ea` reads `n/a` (not a translated guess).
- [ ] For a legacy `.tenet` trace: `off` reads
      `no offsets (legacy trace)`.

### 6.2 Registers

- [ ] Right-click -> **Display decimal** switches values to decimal;
      clicking again switches back (the action label always describes the
      *next* click).
- [ ] Right-click a register -> **Copy value** copies the rendered value in
      the current base.
- [ ] A register with no recorded value renders as `?` — **never as `0`**.
- [ ] Right-click **Copy value** on such a register copies nothing (does not
      copy `?` or `0` as if it were a value).
- [ ] Existing behaviour intact: arrows seek to prev/next register change,
      double-click IP sets an execution breakpoint, follow-in-dump works.

### 6.3 Memory / Stack

- [ ] Hex + ASCII rendering intact.
- [ ] **Copy** (normal and reversed) works on a selection.
- [ ] Bytes absent from the trace render as `??` — and confirm they are
      *not* silently filled from the IDB or a live process.
- [ ] Existing behaviour intact: search bytes, find strings, pin memory,
      follow-in-dump.

### 6.4 No duplicate windows

- [ ] Each panel appears **once**. Loading a new trace does not create a
      second `CPU Registers`, `Event Info`, or `Memory View N`.
- [ ] Closing a dock and scrubbing does not resurrect it unexpectedly.

## 7. Qt bindings (Qt5 vs Qt6)

IDA 9.2 moved from Qt5/PyQt5 to Qt6/PySide6 (Qt 6.8); 9.1 and earlier are
Qt5. Only the PySide6 path (IDA 9.4) is exercised here.

The first two items below are covered by `tests/test_frinet_qt_smoke.py`
against a real PySide6 — run it (`pip install PySide6`) so this section only
has to check what genuinely needs IDA.

- [ ] Plugin loads with **no "enable PyQt5 shims?" prompt** from IDA. That
      prompt appears whenever something imports `PyQt5` directly, which
      `ui/tree_view.py` used to do on every load.
- [ ] All panels construct without an `AttributeError`. The concrete Qt6
      regressions this guards against:
  - [ ] `QtWidgets.QAction` — Qt6 moved it to `QtGui`. Every context menu
        (registers, hex view, timeline, event info) died here.
  - [ ] `menu.exec_()` — Qt6 renamed it `exec()`. Every popup menu and
        modal dialog now goes through `run_exec()`.
  - [ ] `QStandardItem` / `QStandardItemModel` — these are **`QtGui`**
        classes, not `QtWidgets`. Addressing this is what `qt_class()`
        exists for; the smoke test re-resolves every name `tree_view.py`
        asks for against a real Qt6 layout.
- [ ] Right-click the register table, hex view, timeline and event info
      panel: each context menu opens and its entries fire.
- [ ] Panels **dock and re-dock** (drag to another area, close, re-open).
      On IDA 9.2+ the bridge uses `TWidgetToQtPythonWidget`
      (`FormToPyQtWidget`), which is binding-agnostic. It must **not** use
      `TWidgetToPySideWidget` / `FormToPySideWidget`: those end in
      `ctx.QtGui.QWidget.FromCapsule(tw)` with `ctx` defaulting to
      `sys.modules['__main__']`, which inside a plugin is the plugin module
      and has no `QtGui`. Confirmed still broken on IDA 9.4 (Hex-Rays
      community thread 560). Every converter is tried in turn, so a build
      where one is missing or raises falls through, and a total failure
      names each attempt with its exception.
- [ ] Loading a trace works even though the **theme hint** goes through that
      same bridge. Reading the disassembly background colour is cosmetic
      (dark vs light palette); if it fails the plugin logs it and defaults
      to dark rather than aborting the load. This was the second wall: the
      palette warm-up aborted `get_context`, so the file dialog opened and
      the trace silently never loaded.
- [ ] With **both** PyQt5 and PySide6 installed: the plugin still uses the
      binding IDA loaded (PySide6 on 9.2+). Mixing bindings would crash on
      the first docked widget — this is the case the shim specifically
      guards.

## 8. Secondary navigation

- [ ] **History back / forward** walks visited positions; going *back* then
      *forward* does not wipe the forward stack.
- [ ] **Bookmarks**: add at the current position, seek next/prev, remove.
- [ ] **Next / previous occurrence** of the current address jumps between
      executions. Confirm it keys off `off` when present.
- [ ] **Search by address** prompts, and seeks to the first execution of the
      entered address *or* module offset.
- [ ] On a large trace, the first "next occurrence" shows a wait box while
      the index builds; subsequent ones are instant.
- [ ] Selecting an address with no executions reports it rather than doing
      nothing.

## 9. Shutdown / unload

- [ ] Closing the database with a trace loaded: no crash, no traceback.
- [ ] `Edit -> Plugins ->` unload path (if exercised): no crash.
- [ ] Loading a trace, closing its docks, then loading another trace: the
      new trace's panels appear and track correctly.

## 10. Reporting a failure

When filing an issue found via this plan, include:

1. IDA version (`Help -> About`) and Hex-Rays version.
2. OS, and target device/OS for tracer issues.
3. The exact command line used to produce the trace.
4. The first ~10 lines of the `.frinet` file.
5. Whether the trace was `.frinet` or legacy `.tenet`.
6. The console output (including any plugin debug messages).

### Pseudocode cursor specifically

FRINET positions the pseudocode cursor with
`ida_kernwin.jumpto(vdui.ct, place, x, 0)`, which needs a `place_t`.

**A place cannot be constructed on IDA 9.4 — but it can be cloned.** Every
`*place_t` class this build exposes (`idaplace_t`, `place_t`,
`simpleline_place_t`, `tiplace_t`) is abstract, and the module-level
`place_t_as_*` names are *downcast helpers*, not constructors: they take an
existing `place_t*` and return `None` for an argument they cannot convert,
rather than raising. So the working recipe is the one IDA's own examples
and the idavim plugin use:

```python
place, cur_x, cur_y = ida_kernwin.get_custom_viewer_place(vdui.ct, False)
target = ida_kernwin.place_t_as_simpleline_place_t(place.clone())
target.n = line          # `n` is the line field, not `at`
ida_kernwin.jumpto(vdui.ct, target, x, 0)
```

The clone is mandatory — `place` is shared view state, and mutating it in
place would corrupt every later jump. FRINET tries this route first, and
falls back to offering every constructible `*place_t` (from `ida_kernwin`
*and* `ida_hexrays`) for builds where cloning needs a view that already has
a place, remembering whichever class the viewer takes. Because a failed
construction produces the identical refusal on every trace event, that
answer is cached after the first failure instead of being re-printed until
the trace ends.

Three IDA API guesses in a row were wrong on this build, so the plugin does
not guess silently. On a jump where nothing could be built it prints a
one-shot `pseudocode nav surface:` block containing:

* every attempt that was tried, and why each was refused
* every `*place_t` name `ida_kernwin` and `ida_hexrays` expose
* whether `jumpto`, `activate_widget`, `get_custom_viewer_place` and
  `custom_viewer_place_t` are present at all
* the complete member list of `ida_hexrays.vdui_t`, plus the
  place/jump/nav/cursor-named members of `ida_hexrays`
* the member list of the live `vdui_t` object

That block already did its job once: the version on IDA 9.4 named
`get_custom_viewer_place` as present, `place_t_as_simpleline_place_t` as a
function rather than a class, and showed that `vdui_t` carries no cursor
setter of its own — which is what rules *in* the clone recipe above and
rules out every "construct a place" strategy. Paste the block whole if a
jump still fails; it prints once per trace, not once per event.

#### Fallback: the standalone probe

Only if that block is missing, truncated, *or* the clone route itself fails
(the attempt list would read `get_custom_viewer_place(…) returned nothing`
or `…'s place is not a simpleline_place_t`):

1. Open any function's pseudocode and click into it, so it is the current
   widget.
2. `File -> Script file...` → `tools/probe_hexrays_place.py`.
3. Paste the entire Output window.

Section 6 is the experiment: it lists every constructible place class and
what `jumpto` returned for each. Exactly one `True` is the answer. All
`False` means the answer is in section 1 — the dump of `ida_hexrays.vdui_t`
names the real cursor API on your build.
