"""
FRINET trace-format helpers.

This module contains everything that turns a raw ``.tenet``-style trace stream
into a ``.frinet`` trace:

* the ``slide=0x...`` header (runtime module base, and nothing else),
* the per-event ``off=0x...`` field (``pc - slide``, only for PCs that fall
  inside the traced module),
* per-thread line buffering so that records that are split across Frida
  messages are never truncated, duplicated or reordered,
* the platform aware ``Device.spawn()`` kwargs (Android bug fix).

It is intentionally **frida-free** and **IDA-free** so that it can be imported
and unit tested anywhere (``python -m pytest tests``).

Format (see docs/frinet-format.md):

    slide=0x7796859000
    off=0x59294,x13=0xe3,pc=0x77968b2294
    x13=0xe4,pc=0x778ed5f010            <- outside module: line untouched

``off=`` is prepended to the front of the line; every other field keeps its
original name, value and order.
"""

import re
import time

#: Extension of FRINET traces (legacy Tenet traces use ``.tenet``).
FRINET_EXT = ".frinet"

#: Instruction-pointer field name per Frida architecture name. The offset is
#: always computed from the instruction pointer of the event.
IP_FIELD = {
    "arm": "pc",
    "arm64": "pc",
    "x64": "rip",
    "ia32": "eip",
}

#: Field that carries the module offset (always lowercase in the trace file).
OFF_FIELD = "off"

_TRACE_NAME_RE = re.compile(r"[^a-zA-Z_0-9.]")


#-------------------------------------------------------------------------
# Small parsing helpers
#-------------------------------------------------------------------------

def to_int(value):
    """
    Best-effort conversion of a Frida/JSON value into an ``int``.

    Frida serializes ``NativePointer`` values as ``"0x..."`` strings and plain
    numbers as ints; ``None``/garbage become ``None`` instead of raising, so
    that a malformed message can never kill the message callback.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return int(text, 16)
            except ValueError:
                return None
    return None


def ip_field_for_arch(arch):
    """Return the instruction-pointer field name for a Frida arch name."""
    try:
        return IP_FIELD[arch]
    except KeyError:
        raise ValueError(f"Unsupported architecture: {arch!r}")


def find_field(line, name):
    """
    Return the raw value of ``name`` in a comma separated event line.

    Field boundaries are respected: ``xpc=1`` never matches ``pc``.  Returns
    ``None`` when the field is absent (or when *line* is empty).
    """
    if not line:
        return None
    prefix = name + "="
    for item in line.split(","):
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def parse_event_pc(line, ip_field="pc"):
    """Return the instruction pointer of an event line as an ``int`` (or None)."""
    return to_int(find_field(line, ip_field))


def module_range(slide, size):
    """
    Return ``(start, end)`` for the traced module, or ``(None, None)``.

    ``end`` is exclusive: valid PCs satisfy ``start <= pc < end``.
    """
    start = to_int(slide)
    length = to_int(size)
    if start is None or length is None or length <= 0:
        return (None, None)
    return (start, start + length)


def compute_offset(pc, slide, size):
    """
    Return ``pc - slide`` when ``slide <= pc < slide + size``, else ``None``.

    Events that live outside the traced module (libc, the dynamic linker,
    JIT'd code, ...) must never be given an ``off=``: the plugin would map
    them into the middle of the module's pseudocode.
    """
    if pc is None:
        return None
    start, end = module_range(slide, size)
    if start is None:
        return None
    if not (start <= pc < end):
        return None
    return pc - start


def add_module_offset(line, ip_field="pc", slide=None, size=None):
    """
    Return *line* with ``off=0x..`` prepended, or *line* unchanged.

    The line is never rewritten otherwise: field order, values and the exact
    spelling of every other field are preserved.  Lines that already carry an
    ``off=`` field are returned untouched (conversion is idempotent).
    """
    if not line:
        return line
    if find_field(line, OFF_FIELD) is not None:
        return line
    off = compute_offset(parse_event_pc(line, ip_field), slide, size)
    if off is None:
        return line
    return f"{OFF_FIELD}=0x{off:x},{line}"


def strip_record_comma(line):
    """
    Drop the single leading ``,`` that the CModule tracer puts in front of
    every record (``trace_arm64.c`` / ``trace_x64.c`` emit ``",pc=..."``).

    Only one comma is removed and only at the very beginning of the line, so
    continuation lines (a record split across two Frida messages) are joined
    exactly as the original code did with ``re.sub("^,", "", data, re.M)``.
    """
    if line.startswith(","):
        return line[1:]
    return line


def frinet_header(slide):
    """Return the FRINET header line for a module base (``slide=`` only)."""
    start = to_int(slide)
    if start is None:
        return ""
    return f"slide=0x{start:x}\n"


def trace_filename(procname, epoch, tid, ext=FRINET_EXT):
    """
    Return the sanitized per-thread trace file name (``.frinet``).

    Kept here so the naming rule is unit tested and shared with the docs.
    """
    return _TRACE_NAME_RE.sub("", f"{procname}_{epoch}_{tid}{ext}")


#-------------------------------------------------------------------------
# Platform detection / spawn arguments (Android spawn fix)
#-------------------------------------------------------------------------

def is_android_system_parameters(sysenv):
    """
    Return ``True`` when a ``Device.query_system_parameters()`` result
    describes an Android target.

    The decision is taken from the *target device* parameters -- never from
    the host OS -- and is case insensitive because frida has reported both
    ``"Android"`` and ``"android"`` depending on the version/source of the
    ``os.name`` value.
    """
    if not isinstance(sysenv, dict):
        return False

    os_info = sysenv.get("os")
    if isinstance(os_info, dict):
        for key in ("name", "id"):
            value = os_info.get(key)
            if isinstance(value, str) and "android" in value.lower():
                return True

    platform = sysenv.get("platform")
    if isinstance(platform, str) and platform.lower() == "android":
        return True

    return False


def build_spawn_kwargs(argv=None, is_android=False):
    """
    Build the keyword arguments for ``Device.spawn()``.

    * ``stdio="pipe"`` is always kept so the target's stdout/stderr is
      forwarded by the ``output`` handler.
    * ``env`` is passed on desktop platforms only: frida refuses (or breaks)
      ``env`` on Android, which is the spawn bug this fixes.
    * ``argv`` is omitted when there is nothing to pass instead of sending an
      explicit ``None`` (frida then uses the default argument vector).
    * ``cwd`` is omitted: the default (the target's own directory) is what we
      want, and an explicit ``None`` is just noise.
    """
    kwargs = {"stdio": "pipe"}
    if argv:
        kwargs["argv"] = argv
    if not is_android:
        kwargs["env"] = {}
    return kwargs


#-------------------------------------------------------------------------
# Per-thread conversion
#-------------------------------------------------------------------------

def _decode(data):
    """Coerce a frida message payload into ``str`` without ever raising."""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode("latin-1")
    return str(data)


class FrinetTraceWriter:
    """
    Converts raw per-thread trace chunks into FRINET text.

    Responsibilities:

    * buffer partial records that span several frida messages (a record is
      only emitted once, complete, and exactly once),
    * strip the leading ``,`` of every CModule record,
    * prepend ``off=`` when the event PC lies inside the traced module,
    * emit the ``slide=`` header exactly once, as the first line of each
      per-thread file.

    The writer only *returns* text; the caller decides where to append it
    (``trace.py`` appends to ``traces/<proc>_<epoch>_<tid>.frinet``).
    """

    def __init__(self, ip_field=None, warn=None):
        self.ip_field = ip_field
        self.slide = None
        self.size = None
        self._warn = warn or (lambda msg: None)
        self._buffers = {}
        self._headers = set()
        self._ip_warned = False

    def set_arch(self, arch):
        """Set the instruction-pointer field name from a Frida arch name."""
        self.ip_field = ip_field_for_arch(arch)

    #-- module info ------------------------------------------------------
    def set_slide(self, slide, size=None):
        """Record the runtime module base/size announced by ``trace.js``."""
        self.slide = to_int(slide)
        self.size = to_int(size)
        if self.size is not None and self.size <= 0:
            self.size = None

    @property
    def has_module_range(self):
        return self.slide is not None and self.size is not None

    def header(self):
        """Header text for this run (empty when the slide is unknown)."""
        return frinet_header(self.slide)

    #-- conversion -------------------------------------------------------
    def _convert_line(self, line):
        line = strip_record_comma(line)
        if self.ip_field is None:
            # The architecture is not known yet: never guess, emit the line
            # untouched (a trace without off= is still a valid Tenet trace).
            if not self._ip_warned:
                self._ip_warned = True
                self._warn("Architecture unknown: off= fields are disabled.")
            return line
        return add_module_offset(
            line,
            ip_field=self.ip_field,
            slide=self.slide,
            size=self.size,
        )

    def _header_for(self, tid, first_write):
        """
        Header text to emit before the first bytes written for *tid*.

        The header must be the very first line of the file, so it can only be
        written when the slide is known *and* nothing has been written yet.
        """
        if tid in self._headers:
            return ""
        self._headers.add(tid)
        if self.slide is None:
            if first_write:
                self._warn(f"ASLR slide is not known (thread {tid}): no header, no off= fields.")
            return ""
        return self.header()

    def convert(self, tid, data):
        """
        Feed a raw chunk of a thread and return the text to append (may be ``""``).

        Complete lines are returned; the trailing partial record stays
        buffered until the rest of it arrives or :meth:`flush` is called.
        """
        buf = self._buffers.get(tid, "") + _decode(data)
        if "\n" not in buf:
            self._buffers[tid] = buf
            return ""

        lines = buf.split("\n")
        self._buffers[tid] = lines.pop()  # trailing partial record ("" if none)

        out = [self._header_for(tid, first_write=True)]
        for line in lines:
            out.append(self._convert_line(line))
            out.append("\n")
        return "".join(out)

    def flush(self, tid=None):
        """
        Return the pending partial records (``{tid: text}``).

        Calling it twice yields nothing the second time: partial records are
        neither lost nor duplicated.
        """
        tids = [tid] if tid is not None else list(self._buffers.keys())
        out = {}
        for one_tid in tids:
            partial = self._buffers.get(one_tid, "")
            if not partial:
                continue
            self._buffers[one_tid] = ""
            out[one_tid] = (
                self._header_for(one_tid, first_write=True)
                + self._convert_line(partial)
                + "\n"
            )
        return out

    def pending(self, tid=None):
        """Length of the buffered partial record (for tests/debugging)."""
        if tid is None:
            return sum(len(v) for v in self._buffers.values())
        return len(self._buffers.get(tid, ""))


def wait_for_quiet(get_count, quiet=0.3, timeout=5.0, sleep=None, now=None):
    """
    Wait until ``get_count()`` stops changing for *quiet* seconds.

    Used after ``Script.end()`` so the final flush messages (which frida
    delivers asynchronously) are still processed before the script is
    unloaded.  Returns the final counter value.  *sleep*/*now* are
    injectable so the helper can be unit tested without real time.
    """
    sleep = sleep or time.sleep
    now = now or time.monotonic
    deadline = now() + timeout
    last = get_count()
    last_change = now()
    while now() < deadline:
        sleep(quiet / 5.0)
        current = get_count()
        current_time = now()
        if current != last:
            last = current
            last_change = current_time
        elif current_time - last_change >= quiet:
            break
    return last
