"""
Tests for the FRINET tracer side (``tracer/frinet.py``).

These run entirely without frida / a device / IDA:

* header rules (``slide=`` only),
* ``off = pc - slide`` including the reference offset table,
* in-range / out-of-range / boundary PCs,
* field order preservation,
* partial & malformed records (no loss, no duplication, no reordering),
* platform aware spawn kwargs (Android ``env`` bug fix).
"""

import os

import pytest

from frinet import (
    FRINET_EXT,
    FrinetTraceWriter,
    add_module_offset,
    build_spawn_kwargs,
    compute_offset,
    find_field,
    frinet_header,
    ip_field_for_arch,
    is_android_system_parameters,
    module_range,
    parse_event_pc,
    strip_record_comma,
    to_int,
    trace_filename,
    wait_for_quiet,
)

# Reference values from the specification.
SLIDE = 0x7796859000
SIZE = 0x100000  # 1MB module

# Real trace shipped with the repository.
EXAMPLE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "example.tenet"
)

REFERENCE_TABLE = [
    (0x77968b2290, 0x59290),
    (0x77968b2294, 0x59294),
    (0x77968b2298, 0x59298),
    (0x77968b229C, 0x5929C),
    (0x77968b22A0, 0x592A0),
    (0x77968b22A4, 0x592A4),
    (0x77968b22A8, 0x592A8),
    (0x77968b22AC, 0x592AC),
    (0x77968b22B0, 0x592B0),
]


#-------------------------------------------------------------------------
# Header
#-------------------------------------------------------------------------

def test_header_is_slide_only():
    header = frinet_header(SLIDE)
    assert header == "slide=0x7796859000\n"
    # header must never carry module=/func= and must be a single line
    assert "module=" not in header
    assert "func=" not in header
    assert header.count("\n") == 1


def test_header_without_slide_is_empty():
    assert frinet_header(None) == ""
    assert frinet_header("nonsense") == ""


def test_header_normalizes_value_forms():
    assert frinet_header("0x1000") == frinet_header(4096) == "slide=0x1000\n"


#-------------------------------------------------------------------------
# Offset computation
#-------------------------------------------------------------------------

@pytest.mark.parametrize("pc,off", REFERENCE_TABLE)
def test_reference_offset_table(pc, off):
    assert compute_offset(pc, SLIDE, SIZE) == off
    assert pc - SLIDE == off


def test_module_range_is_half_open():
    assert module_range(SLIDE, SIZE) == (SLIDE, SLIDE + SIZE)


def test_offset_requires_known_size():
    # unknown size -> no range -> no off= (never guess)
    assert compute_offset(SLIDE + 0x59290, SLIDE, None) is None
    assert compute_offset(SLIDE + 0x59290, None, SIZE) is None


def test_offset_requires_known_slide():
    assert compute_offset(0x77968b2290, None, SIZE) is None


def test_pc_inside_module_gets_offset():
    assert compute_offset(0x77968b2290, SLIDE, SIZE) == 0x59290


def test_pc_outside_module_has_no_offset():
    # below the module
    assert compute_offset(SLIDE - 1, SLIDE, SIZE) is None
    # libc / linker / JIT
    assert compute_offset(0x778ED5F010, SLIDE, SIZE) is None
    assert compute_offset(SLIDE + SIZE + 0x1000, SLIDE, SIZE) is None


def test_boundaries():
    # first byte of the module -> off=0x0
    assert compute_offset(SLIDE, SLIDE, SIZE) == 0
    # last valid byte
    assert compute_offset(SLIDE + SIZE - 1, SLIDE, SIZE) == SIZE - 1
    # one past the end is *outside* (end is exclusive)
    assert compute_offset(SLIDE + SIZE, SLIDE, SIZE) is None


def test_missing_pc_gives_no_offset():
    assert compute_offset(None, SLIDE, SIZE) is None
    assert parse_event_pc("x0=0x1,mr=0x2:aa", "pc") is None


#-------------------------------------------------------------------------
# Line rewriting / field order
#-------------------------------------------------------------------------

def test_off_is_prepended_and_field_order_is_preserved():
    line = "x13=0xe3,pc=0x77968b2294"
    out = add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE)
    assert out == "off=0x59294,x13=0xe3,pc=0x77968b2294"
    # pc stays where it was: never moved to the front / back
    assert out.split(",") == ["off=0x59294", "x13=0xe3", "pc=0x77968b2294"]


def test_slow_mode_style_line_full_field_order_kept():
    # real example.tenet style: regs..., pc=..., mw=...
    line = "x0=0x1,x13=0xe3,pc=0x77968b2294,mw=0x1000:deadbeef"
    out = add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE)
    assert out == "off=0x59294,x0=0x1,x13=0xe3,pc=0x77968b2294,mw=0x1000:deadbeef"


def test_cmode_style_line_pc_first():
    # CModule arm64/x64 records start with the IP
    line = "pc=0x77968b2290,x0=0x1"
    out = add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE)
    assert out == "off=0x59290,pc=0x77968b2290,x0=0x1"


def test_external_event_is_untouched():
    line = "pc=0x778ed5f010,x0=0x1234"
    assert add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE) == line


def test_line_without_pc_is_untouched():
    line = "Reached end address !"
    assert add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE) == line


def test_conversion_is_idempotent():
    line = "x13=0xe3,pc=0x77968b2294"
    once = add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE)
    twice = add_module_offset(once, ip_field="pc", slide=SLIDE, size=SIZE)
    assert twice == once
    assert once.count("off=") == 1


def test_malformed_pc_never_raises():
    line = "pc=not-a-number,x0=0x1"
    assert add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE) == line
    assert parse_event_pc(line, "pc") is None


def test_find_field_is_boundary_aware():
    line = "xpc=0x1,pc=0x2,rpc=0x3"
    assert find_field(line, "pc") == "0x2"
    assert find_field(line, "xpc") == "0x1"
    assert find_field(line, "nope") is None
    assert find_field("", "pc") is None


def test_off_field_wins_over_pc_arithmetic():
    # a line that already has off= must not gain a second one, even if the
    # arithmetic would say something different
    line = "off=0x1,pc=0x77968b2294"
    assert add_module_offset(line, ip_field="pc", slide=SLIDE, size=SIZE) == line


#-------------------------------------------------------------------------
# Architecture / IP field
#-------------------------------------------------------------------------

@pytest.mark.parametrize(
    "arch,field",
    [("arm", "pc"), ("arm64", "pc"), ("x64", "rip"), ("ia32", "eip")],
)
def test_ip_field_per_arch(arch, field):
    assert ip_field_for_arch(arch) == field


def test_unknown_arch_raises():
    with pytest.raises(ValueError):
        ip_field_for_arch("sparc")


def test_x64_uses_rip_field():
    line = "rip=0x77968b2290,rax=0x1"
    out = add_module_offset(line, ip_field="rip", slide=SLIDE, size=SIZE)
    assert out == "off=0x59290,rip=0x77968b2290,rax=0x1"


def test_ia32_uses_eip_field():
    line = "eip=0x77968b2290,eax=0x1"
    out = add_module_offset(line, ip_field="eip", slide=SLIDE, size=SIZE)
    assert out == "off=0x59290,eip=0x77968b2290,eax=0x1"


def test_x64_rip_is_not_matched_as_pc():
    line = "rip=0x77968b2290"
    assert parse_event_pc(line, "pc") is None


#-------------------------------------------------------------------------
# Record comma / chunking
#-------------------------------------------------------------------------

def test_leading_record_comma_is_stripped_once():
    assert strip_record_comma(",pc=0x1") == "pc=0x1"
    assert strip_record_comma("pc=0x1") == "pc=0x1"
    # inner commas must survive
    assert strip_record_comma(",pc=0x1,x0=0x2") == "pc=0x1,x0=0x2"
    # only one comma is removed
    assert strip_record_comma(",,pc=0x1") == ",pc=0x1"


#-------------------------------------------------------------------------
# FrinetTraceWriter: buffering / headers
#-------------------------------------------------------------------------

def make_writer(arch="arm64", slide=SLIDE, size=SIZE, warn=None):
    writer = FrinetTraceWriter(warn=warn)
    writer.set_arch(arch)
    writer.set_slide(slide, size)
    return writer


def test_writer_emits_header_once_per_thread():
    writer = make_writer()
    out = writer.convert(1, "pc=0x77968b2290\n")
    assert out == "slide=0x7796859000\noff=0x59290,pc=0x77968b2290\n"
    out2 = writer.convert(1, "pc=0x77968b2294\n")
    assert out2.startswith("off=")
    assert "slide=" not in out2


def test_writer_header_for_every_thread():
    writer = make_writer()
    a = writer.convert(1, "pc=0x77968b2290\n")
    b = writer.convert(2, "pc=0x77968b2290\n")
    assert a.startswith("slide=0x7796859000\n")
    assert b.startswith("slide=0x7796859000\n")


def test_writer_no_header_when_slide_unknown():
    warnings = []
    writer = FrinetTraceWriter(warn=warnings.append)
    writer.set_arch("arm64")
    out = writer.convert(1, "pc=0x77968b2290\n")
    # header must be the first line of the file: without a slide we cannot
    # write one, so the file simply starts with the event
    assert not out.startswith("slide=")
    assert out == "pc=0x77968b2290\n"
    assert warnings, "a warning must be emitted when the slide is unknown"


def test_writer_off_disabled_when_size_unknown():
    writer = FrinetTraceWriter()
    writer.set_arch("arm64")
    writer.set_slide(SLIDE, None)
    out = writer.convert(1, "pc=0x77968b2290\n")
    assert out == "slide=0x7796859000\npc=0x77968b2290\n"


def test_writer_off_disabled_when_arch_unknown():
    writer = FrinetTraceWriter()
    writer.set_slide(SLIDE, SIZE)  # no set_arch() call
    out = writer.convert(1, "pc=0x77968b2290\n")
    assert out.startswith("slide=0x7796859000\n")
    assert "\noff=" not in out


def test_writer_strips_record_comma_and_keeps_continuations():
    writer = make_writer()
    out = writer.convert(1, ",pc=0x77968b2290,x0=0x1\n,pc=0x77968b2294,x0=0x2\n")
    assert out == (
        "slide=0x7796859000\n"
        "off=0x59290,pc=0x77968b2290,x0=0x1\n"
        "off=0x59294,pc=0x77968b2294,x0=0x2\n"
    )


def test_slow_mode_lines_without_comma_are_untouched():
    writer = make_writer()
    out = writer.convert(1, "x0=0x1,pc=0x77968b2290\n")
    assert out == "slide=0x7796859000\noff=0x59290,x0=0x1,pc=0x77968b2290\n"


def test_split_record_is_reassembled_without_loss_or_dup():
    writer = make_writer()
    full = ",pc=0x77968b2290,x0=0x1,mw=0x1000:aa\n,pc=0x77968b2294,x0=0x2\n"
    expected = (
        "slide=0x7796859000\n"
        "off=0x59290,pc=0x77968b2290,x0=0x1,mw=0x1000:aa\n"
        "off=0x59294,pc=0x77968b2294,x0=0x2\n"
    )
    # split at every possible position
    for cut in range(len(full) + 1):
        one = make_writer()
        part_a = one.convert(1, full[:cut])
        part_b = one.convert(1, full[cut:])
        tail = "".join(one.flush().values())
        assert part_a + part_b + tail == expected, f"cut={cut}"


def test_split_record_byte_by_byte():
    writer = make_writer()
    data = ",pc=0x77968b2290,x0=0x1\n,pc=0x77968b2294,x0=0x2\n"
    out = "".join(writer.convert(1, ch) for ch in data)
    out += "".join(writer.flush().values())
    assert out == (
        "slide=0x7796859000\n"
        "off=0x59290,pc=0x77968b2290,x0=0x1\n"
        "off=0x59294,pc=0x77968b2294,x0=0x2\n"
    )


def test_flush_writes_pending_partial_exactly_once():
    writer = make_writer()
    writer.convert(7, "pc=0x77968b2290,x0=0x1")  # no newline yet
    assert writer.pending(7) > 0
    first = writer.flush()
    assert set(first) == {7}
    assert first[7].endswith("\n")
    assert first[7] == (
        "slide=0x7796859000\noff=0x59290,pc=0x77968b2290,x0=0x1\n"
    )
    # second flush: nothing left (no duplicate)
    assert writer.flush() == {}
    assert writer.pending(7) == 0


def test_flush_only_returns_threads_with_data():
    writer = make_writer()
    writer.convert(1, "pc=0x77968b2290\n")
    writer.convert(2, "pc=0x77968b2294")  # partial
    assert writer.flush() != {}
    assert 1 not in writer.flush()  # already fully written


def test_records_stay_in_order_across_messages():
    writer = make_writer()
    chunks = [
        "pc=0x77968b2290\n",
        "pc=0x77968b2294\npc=0x77968b2298",
        "\npc=0x77968b229c\n",
    ]
    out = "".join(writer.convert(1, c) for c in chunks) + "".join(
        writer.flush().values()
    )
    offs = [line.split(",")[0] for line in out.strip().split("\n")[1:]]
    assert offs == ["off=0x59290", "off=0x59294", "off=0x59298", "off=0x5929c"]


def test_external_and_internal_events_mixed():
    writer = make_writer()
    out = writer.convert(
        1,
        "pc=0x77968b2290,x0=0x1\npc=0x778ed5f010,x0=0x2\npc=0x77968b2294\n",
    )
    assert out == (
        "slide=0x7796859000\n"
        "off=0x59290,pc=0x77968b2290,x0=0x1\n"
        "pc=0x778ed5f010,x0=0x2\n"
        "off=0x59294,pc=0x77968b2294\n"
    )


def test_non_event_lines_pass_through():
    writer = make_writer()
    out = writer.convert(1, "Reached end address !\nSENT 42\n")
    assert out == "slide=0x7796859000\nReached end address !\nSENT 42\n"


def test_bytes_payload_is_accepted():
    writer = make_writer()
    out = writer.convert(1, b"pc=0x77968b2290\n")
    assert out == "slide=0x7796859000\noff=0x59290,pc=0x77968b2290\n"


def test_blank_lines_are_preserved():
    writer = make_writer()
    out = writer.convert(1, "\npc=0x77968b2290\n\n")
    assert out == "slide=0x7796859000\n\noff=0x59290,pc=0x77968b2290\n\n"


#
# example.tenet is a real trace used as an end-to-end fixture. It is not
# checked in, so a fresh clone simply does not have it -- the test skips
# rather than failing on a file the repository never shipped. Every rule it
# would have exercised is covered individually by the tests above.
#
@pytest.mark.skipif(
    not os.path.exists(EXAMPLE_PATH),
    reason="example.tenet is not shipped with this repository",
)
def test_full_example_tenet_lines_convert():
    """End-to-end conversion of the real example.tenet content."""
    with open(EXAMPLE_PATH, "r") as f:
        lines = f.read().split("\n")
    assert lines[0] == "slide=0x7796859000"
    body = [ln for ln in lines[1:] if ln]

    writer = make_writer()
    out = "".join(writer.convert(1, ln + "\n") for ln in body)
    out += "".join(writer.flush().values())

    converted = out.strip().split("\n")
    assert converted[0] == "slide=0x7796859000"
    assert len(converted) == 1 + len(body)
    for original, new in zip(body, converted[1:]):
        assert new.endswith(original)
        assert new.split(",")[0].startswith("off=0x")


#-------------------------------------------------------------------------
# Filenames
#-------------------------------------------------------------------------

def test_trace_filename_uses_frinet_extension():
    name = trace_filename("libfoo.so", "1700000000", 1234)
    assert name == "libfoo.so_1700000000_1234.frinet"
    assert name.endswith(FRINET_EXT)


def test_trace_filename_is_sanitized():
    name = trace_filename("/data/local/tmp/my-app (1)", "1", 2)
    assert "/" not in name and " " not in name and "(" not in name
    assert name.endswith(FRINET_EXT)


#-------------------------------------------------------------------------
# Spawn (Android env bug fix)
#-------------------------------------------------------------------------

ANDROID_ENVS = [
    {"os": {"name": "Android", "version": "14"}},
    {"os": {"name": "android", "version": "14"}},
    {"os": {"name": "ANDROID"}},
    {"platform": "android", "os": {"name": "weird"}},
]

NON_ANDROID_ENVS = [
    {"os": {"name": "Ubuntu", "version": "24.04"}, "platform": "linux"},
    {"os": {"name": "linux"}, "platform": "linux"},
    {"os": {"name": "Mac OS X"}, "platform": "darwin"},
    {"os": {"name": "Windows"}, "platform": "windows"},
    {"os": {}},
    {},
    None,
    "nonsense",
]


@pytest.mark.parametrize("sysenv", ANDROID_ENVS)
def test_is_android_positive(sysenv):
    assert is_android_system_parameters(sysenv) is True


@pytest.mark.parametrize("sysenv", NON_ANDROID_ENVS)
def test_is_android_negative(sysenv):
    assert is_android_system_parameters(sysenv) is False


def test_spawn_kwargs_android_has_no_env():
    kwargs = build_spawn_kwargs(["arg1", "arg2"], is_android=True)
    assert "env" not in kwargs
    assert kwargs["argv"] == ["arg1", "arg2"]
    assert kwargs["stdio"] == "pipe"
    assert "cwd" not in kwargs  # no pointless None kwarg


def test_spawn_kwargs_desktop_keeps_env_and_stdio():
    kwargs = build_spawn_kwargs(None, is_android=False)
    assert kwargs == {"env": {}, "stdio": "pipe"}
    assert "argv" not in kwargs  # argv=None is not passed


def test_spawn_kwargs_never_pass_none_values():
    for is_android in (True, False):
        for argv in (None, [], ["x"]):
            kwargs = build_spawn_kwargs(argv, is_android)
            assert all(v is not None for v in kwargs.values())
            assert kwargs["stdio"] == "pipe"


def test_spawn_kwargs_empty_argv_is_omitted():
    assert "argv" not in build_spawn_kwargs([], is_android=False)


#-------------------------------------------------------------------------
# misc helpers
#-------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        (4096, 4096),
        ("0x1000", 4096),
        ("1000", 1000),
        ("  0x10  ", 16),
        ("", None),
        (None, None),
        ("zzz", None),
        (True, None),
        (1.5, None),
    ],
)
def test_to_int(value, expected):
    assert to_int(value) == expected


def test_wait_for_quiet_returns_when_counter_stops():
    class Clock:
        def __init__(self):
            self.t = 0.0

        def now(self):
            return self.t

        def sleep(self, seconds):
            self.t += seconds

    clock = Clock()
    result = wait_for_quiet(
        lambda: 7, quiet=0.3, timeout=10.0, sleep=clock.sleep, now=clock.now
    )
    assert result == 7
    assert clock.t < 10.0


def test_wait_for_quiet_times_out_while_messages_keep_arriving():
    class Clock:
        def __init__(self):
            self.t = 0.0

        def now(self):
            return self.t

        def sleep(self, seconds):
            self.t += seconds

    clock = Clock()
    counter = {"n": 0}

    def get_count():
        counter["n"] += 1
        return counter["n"]

    result = wait_for_quiet(
        get_count, quiet=0.3, timeout=1.0, sleep=clock.sleep, now=clock.now
    )
    assert result == counter["n"]
    assert clock.t >= 1.0
