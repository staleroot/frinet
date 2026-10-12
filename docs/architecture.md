# FRINET architecture

FRINET is a tracer (`tracer/`) plus an extended Tenet plugin
(`tenet/plugins/tenet/`). This document explains how a trace becomes a
highlighted expression in Hex-Rays pseudocode, and where the honest limits
are.

## The pipeline

```
tracer/frinet.py          tenet/trace/file.py        tenet/trace/addressing.py
  .tenet text   ----->     parsed TraceFile   ----->   off -> static_ea
  + slide + off=                                       (idb_module_start + off)
                                                              |
                                                              v
tenet/sync/controller.py  <----  tenet/sync/hexrays_api.py
  coalesce / cache /             decompile, harvest ctree items,
  reject stale                   find / open pseudocode widgets
         |
         v
tenet/sync/pseudomap.py  ->  tenet/sync/lexer.py
  ea -> most precise             lex COLOR_ADDR tokens out of
  expression (5 levels)          the rendered pseudocode text
```

## Addressing: `pc`, `off`, `static_ea`, and why they stay distinct

These four values are **never** used interchangeably. Confusing any pair of
them produces confidently wrong navigation.

| Term | Meaning | Example |
|---|---|---|
| `pc` | The instruction pointer exactly as executed on the device. | `0x77968b2294` |
| `slide` | The runtime base of the traced module (the `slide=` header). | `0x7796859000` |
| `off` | `pc - slide`, defined **only** when `module_start <= pc < module_end`. | `0x59294` |
| `idb_module_start` | The address of `off == 0` in the *open* database. | `0x400000` |
| `static_ea` | `idb_module_start + off` — where the event lives in the IDB. | `0x459294` |

`off` is the **primary navigation key**. `pc` is only used to *compute*
`off`, and as a fallback for events that have none.

### Why `idb_module_start` is not `get_imagebase()`

ELF and Android images frequently have segments whose real origin differs
from the nominal imagebase: rebases, partial loaders, headers that are not
mapped as segments, and PIE images loaded at a non-zero offset. Assuming
`idb_module_start == ida_nalt.get_imagebase()` is exactly the kind of
off-by-a-header-size error that makes every address in a trace subtly wrong.

Instead `addressing.py` derives the origin from the *actual* IDB segment
layout: for each executable segment it hypothesises
`imagebase + (segment.start - segment.filepos)` and scores the candidate
against sampled `off` values from the trace (do they land on code?).

**Ambiguity is never guessed away.** A candidate is rejected — and the user
prompted to choose — when:

* a runner-up scores within `0.90` of the winner (a tie),
* the best candidate scores below `0.50`,
* several unvalidated candidates exist, or
* the trace's image name and the open database's image name disagree.

If no candidate survives, `origin` stays `None` and **no event is mapped**.
An unmapped trace is a usable trace; a mis-mapped one is actively harmful.

### Events without an `off`

An event executed outside the traced module (libc, the dynamic linker, JIT'd
code) has no `off`. Such events:

* stay in the timeline (they are real execution),
* are **never** mapped into pseudocode by the offset path,
* fall back to the legacy ASLR-slide rebase, and only if that result is an
  address the database actually contains.

The plugin never invents an address for them.

## Image identity

`addressing.identify_image()` compares the traced image (recovered from the
trace filename `<procname>_<epoch>_<tid>.frinet`) against
`ida_nalt.get_root_filename()`, and returns one of four verdicts:

| Verdict | Meaning |
|---|---|
| `exact` | Same basename. |
| `possible` | One is a prefix of the other, both at least 4 chars (e.g. `libfoo.so` / `libfoo.so.1`). |
| `mismatch` | Different images — the user is told before trusting any mapping. |
| `unknown` | Either name is missing. |

A `mismatch` does not block the plugin; it triggers a confirmation prompt,
because silently mapping a trace of `libfoo.so` onto `libbar.so` is the
worst possible outcome.

## Pseudocode synchronisation (`tenet/sync/`)

The hard part is not navigating — it is deciding *what to highlight*. One
instruction can correspond to a whole statement, a sub-expression, or (when
the decompiler optimised it away) nothing addressable at all.

### Precision hierarchy

`pseudomap.py` models this as an explicit five-level fallback, best first:

| Level | Meaning |
|---|---|
| `expr` | The deepest expression whose `ea` is exactly the target address. |
| `item` | Some other (shallower) ctree item at exactly the target address. |
| `line` | The decompiled line that renders the address; the column is unknown (the decompiler declined to give coordinates). |
| `nearest` | The closest addressable item in the same function — **flagged as approximate**, never passed off as exact. |
| `none` | Nothing maps to the address. **Nothing is highlighted.** |

`none` is a real answer and is used: a false highlight is worse than no
highlight.

### How the expression is located — and its limit

Hex-Rays embeds hidden address tokens in its rendered output:
`COLOR_ON COLOR_ADDR <16 hex digits>` followed by the item's text (verified
against the SDK's `lines.hpp` and against Tenet's own `lex_citem_indexes`).

`lexer.py` extracts these tokens and the column each starts at. It is
robust by construction:

* a bare `0x28` is the character `(`, **not** a tag (only bytes `0x01..0x04`
  are escaped per `requires_color_esc()`), so parentheses are never eaten;
* a truncated or non-hex payload drops that one token and keeps lexing the
  rest of the line — one clipped token cannot lose a whole line;
* unbalanced `COLOR_OFF` and stray `COLOR_ESC` do not raise.

**The documented limitation:** nesting depth is inferred from *preorder
emission order* (a later token at the same address is more deeply nested),
not from a ctree walk. This is exact for items that render on the same line,
but **cannot order two items at the same address on different lines**. Span
`length` is likewise an approximation (it runs to the next token, not to the
item's true extent) — sufficient to place a cursor, not to compute an exact
selection rectangle.

### Responsiveness

`controller.py` is built around the fact that scrubbing the timeline fires
dozens of index changes per second while the decompiler cannot keep up:

1. **Coalescing** — bursts collapse into one update per tick (40 ms
   default). Only the last position matters.
2. **Staleness rejection** — a `Generation` token is bumped on every index
   change; anything computed against an older token (a decompilation, a
   cursor jump) is *discarded*, never applied.
3. **Bounded LRU caches** — decompilations and ctree maps are cached by
   function entry, with fixed capacities, so a long session cannot grow
   without bound.
4. **Prioritised, deduplicated prefetch** — the functions the trace is about
   to visit are warmed *only when idle*, and *only from already-cached
   decompilations*. Prefetch never forces a fresh decompilation.
5. **No unconditional decompilation** — nothing is decompiled unless the
   pseudocode is already on screen, or the user explicitly asked.

All IDA and Qt calls run on the main thread; no background thread touches
the decompiler.

`describe_target()` — used by the Event Info panel — reads the cache
**only**. Displaying a trace position can never trigger a decompilation.

## What register and memory data actually exists

This matters more than it sounds, because the UI can only ever show what the
tracer recorded.

### Registers

The trace stores a **sparse delta**: the registers that changed at each
step, plus the IP. Values are reconstructed by walking backwards from the
nearest cached full register state.

Consequences:

* A register that was never written during the traced region has **no
  recorded value**. It is shown as unavailable (`?`), never as `0`.
* Only registers the *tracer* knows about appear. Frida's `CpuContext`
  fields define the set; architecture-specific extras (e.g. `nzcv` on
  arm64) are not recorded.
* Register *names* follow the tracer's architecture, not the IDB's.

### Memory

Memory is read **exclusively from the trace** — from the recorded `mw=`/`mr=`
deltas. The plugin never reads live process memory, and never reads bytes
from the IDB to fill a gap. Two reasons:

1. A trace is a *historical record*. Live memory is the *present*. Showing
   present-day bytes in a historical view is a correctness lie, and on a
   detached/dead target the process may not even exist any more.
2. The IDB's bytes are the *static* image, which differs from runtime
   memory (relocations, GOT/PLT resolution, decrypted buffers, heap, stack).

Unrecorded bytes therefore render as `??` — genuinely unknown, which is the
truth.

One caveat worth stating plainly: the tracer has a **finite memory budget**.
Bytes written before the trace began, or outside the traced region, may not
be captured. `??` means "not in this trace", which is not quite the same as
"did not exist".

### Reading memory at all

`reader.get_memory()` answers from the trace's own address→data index. No
IDA debuggee is required, and none is contacted.

## Threading and lifecycle

* Traces are per-thread; the plugin keeps the per-thread split and never
  reorders events across threads.
* Each opened database gets its own `TenetContext` (in IDA only one database
  is open at a time, but the structure does not assume it).
* On trace replacement, the previous trace's caches, history, bookmarks, and
  occurrence index are all discarded — no stale state leaks into the new
  trace.
* On shutdown, the sync controller detaches *before* the reader is
  discarded, so no pending scheduled update can touch a dead reader.

## Testing posture

Unit tests cover everything that is pure Python: the tracer conversion, the
parser, the addressing logic, the lexer, the expression map, the caches, the
prefetch planner, the navigation aids, the controller (with injected
fakes), the event info model, and the Qt binding resolution.

**Nothing that requires a live IDA, a live Hex-Rays decompiler, a live Qt
event loop, or a real Android/iOS device is claimed to pass.** Those are
covered by `docs/manual-testing.md`, which is a procedure, not a result.
