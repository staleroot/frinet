# The FRINET trace format

FRINET is a small, backwards-compatible extension of the Tenet text trace
format. Every `.frinet` file is a valid Tenet trace that any existing Tenet
tracer (or plugin) can still read; the extensions only add addressing
information that makes navigation precise.

A `.frinet` file is plain UTF-8 text: one header line, then one line per
event.

```
slide=0x7796859000
off=0x59290,x13=0xe2,pc=0x77968b2290
off=0x59294,x13=0xe3,pc=0x77968b2294
x13=0xe4,pc=0x778ed5f010
```

## The header

```
slide=0x7796859000
```

`slide` is the **runtime base address of the traced module**, as reported by
the injected script. It is the only thing the header carries.

Deliberately *not* in the header:

| Never written | Why |
|---|---|
| `module=` | The traced module's name is already known from the command line and the output filename. Duplicating it in the file creates a second source of truth that can disagree with the first. |
| `func=` | `[FUNC_ADDR]` is the *trace entry point* — the address at which tracing starts. It is **not** the origin for offsets. Conflating the two is the single most common way to get every address in a trace wrong by a constant. |

An offset is always relative to `slide`, never to the entry point.

The header appears exactly once, as the **first line of each per-thread
file**. If the slide is unknown when the first bytes of a thread are
written, no header is written at all (and a warning is printed once): a
header cannot be retrofitted into the middle of a file.

## Events

```
off=0x59294,x13=0xe3,pc=0x77968b2294
```

Fields are comma separated `name=value` pairs, exactly as in Tenet. FRINET
adds one field:

* **`off=0x...`** — the module offset of the event: `pc - slide`.

### Where `off=` goes

`off=` is **prepended to the front** of the line. Every other field keeps
its original name, value, and order; the instruction pointer is never
reordered or renamed.

```
x13=0xe3,pc=0x77968b2294   ->   off=0x59294,x13=0xe3,pc=0x77968b2294
```

The instruction-pointer field is architecture dependent and is left exactly
as the tracer emitted it:

| Architecture | IP field |
|---|---|
| `arm`, `arm64` | `pc` |
| `x64` | `rip` |
| `ia32` | `eip` |

### When `off=` is omitted

An event gets **no** `off=` field, and its line is left completely
untouched, when:

* **The PC is outside the traced module.** An event that executed in libc,
  the dynamic linker, a JIT region, the stack, or unmapped memory has no
  meaningful module offset. Giving it one would map it into the middle of
  the module's pseudocode — a confidently wrong answer, which is worse than
  no answer.
* **The module range is unknown.** The size is announced by the injected
  script; without it there is no way to know which PCs are in-module, and
  guessing is not acceptable.
* **The architecture is unknown**, so the IP field name cannot be
  determined. (A warning is printed once.)

The consequence: in a mixed trace, some lines carry `off=` and some do not,
and the difference is meaningful — "in the traced module" vs "not".

### `off=0x0` is a real offset

`off=0x0` means "the very first byte of the module". It is **not** the same
as "no offset". Code that confuses the two shifts every address in the
trace by one module.

### Idempotency

A line that already carries an `off=` field is returned unchanged, so
re-converting a trace never doubles the field.

## The reference table

With `slide=0x7796859000`:

| `pc` | `off` |
|---|---|
| `0x77968b2290` | `0x59290` |
| `0x77968b2294` | `0x59294` |
| `0x77968b22b0` | `0x592b0` |
| `0x778ed5f010` | *(omitted — outside the module)* |

## Per-thread files

The tracer writes one file per thread, named

```
<procname>_<epoch>_<tid>.frinet
```

(e.g. `ls_1712345678_4242.frinet`). The name is sanitized by replacing every
character outside `[a-zA-Z_0-9.]` with nothing.

Each file is independent: its own header, its own event stream, and its own
event ordering. Events within a file are never reordered.

## Record boundaries

The CModule tracer emits records with a leading comma (`,pc=...`). Exactly
**one** leading comma is stripped per complete record.

Records can span several Frida messages. The writer buffers per thread until
a newline arrives, so a record split across messages is emitted exactly once,
complete, in order — never truncated, duplicated, or reordered. Any partial
record still buffered at shutdown is flushed on exit.

## Legacy `.tenet` traces

`.tenet` traces have no header and no `off=` fields. They remain fully
supported: the plugin falls back to the ASLR-slide heuristic for addressing,
which is less precise (see `docs/architecture.md`).

The distinction is visible in the UI rather than silently absorbed: the
Event Info panel reports `no offsets (legacy trace)` for a legacy trace and
`external (outside module)` for a `.frinet` event that happened to execute
outside the traced module. These are different situations and are not
conflated.

## What FRINET does *not* change

* Register and memory field names, values, and semantics.
* The per-thread split, and the ordering of events within a thread.
* Memory deltas (`mw=`/`mr=`) — they are still recorded, and still read
  *only from the trace*, never from a live process or the IDB.
* Compatibility with existing Tenet tracers: `.tenet` input still produces
  `.tenet`-shaped output.
