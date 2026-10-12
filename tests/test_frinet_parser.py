"""
Tests for the FRINET plugin side: parser, addressing and reader wiring.

None of these tests need IDA. ``TraceFile`` / ``TraceReader`` are exercised
with a fake disassembler context (``FakeDctx``) so the IDB-facing logic
(segment layout, image identity, ambiguity) can be verified here.

Anything that *does* need a real IDA 9.4 session (docks, timeline, Hex-Rays
highlighting) is covered by ``docs/manual-testing.md`` instead -- those are
**not** claimed as passing here.
"""

import os

import pytest

from frinet import FrinetTraceWriter
from tenet.trace.addressing import (
    MATCH_EXACT,
    MATCH_MISMATCH,
    MATCH_POSSIBLE,
    MATCH_UNKNOWN,
    MATCH_UNKNOWN as UNKNOWN,
    ImageIdentity,
    OffsetResolver,
    Resolution,
    SegmentInfo,
    identify_image,
    module_name_from_trace_filename,
    names_match,
    normalize_image_name,
)
from tenet.trace.arch import ArchAMD64, ArchARM64
from tenet.trace.file import TraceFile
from tenet.trace.reader import TraceReader

SLIDE = 0x7796859000
SIZE = 0x100000

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXAMPLE_TENET = os.path.join(ROOT, "example.tenet")


#-------------------------------------------------------------------------
# Helpers
#-------------------------------------------------------------------------

def write_trace(tmp_path, lines, name="libfoo.so_1700000000_1234.frinet"):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def convert_example(tmp_path):
    """Run the real example.tenet through the tracer converter.

    ``example.tenet`` is a real trace used as an end-to-end fixture, but it
    is **not** checked in -- a clone simply does not have it. The tests that
    need it skip rather than fail on a file the repository never shipped;
    every rule they exercise is also covered individually by tests in this
    file that build their own traces.
    """
    if not os.path.exists(EXAMPLE_TENET):
        pytest.skip("example.tenet is not shipped with this repository")

    with open(EXAMPLE_TENET) as f:
        raw = [line for line in f.read().split("\n") if line]

    assert raw[0] == "slide=0x7796859000"

    writer = FrinetTraceWriter()
    writer.set_arch("arm64")
    writer.set_slide(SLIDE, SIZE)

    out = "".join(writer.convert(1, line + "\n") for line in raw[1:])
    out += "".join(writer.flush().values())

    path = tmp_path / "libfoo.so_1700000000_1.frinet"
    path.write_text(out)
    return str(path), [line for line in out.split("\n") if line]


class FakeDctx(object):
    """Minimal disassembler context: segment layout + image identity."""

    def __init__(self, segments, imagebase=0, root_filename="libfoo.so",
                 instructions=None, prompt=None, is_mapped=None):
        self.segments = segments
        self._imagebase = imagebase
        self._root = root_filename
        self._instructions = instructions or []
        self._prompt = prompt
        self._is_mapped = is_mapped
        self.prompt_calls = []

    # -- FRINET hooks ---------------------------------------------------
    def get_segments(self):
        return self.segments

    def get_imagebase(self):
        return self._imagebase

    def get_root_filename(self):
        return self._root

    def is_mapped(self, ea):
        if self._is_mapped is not None:
            return self._is_mapped(ea)
        return any(seg.contains(ea) for seg in self.segments)

    def is_code_address(self, ea):
        if not self.is_mapped(ea):
            return False
        for seg in self.segments:
            if seg.contains(ea):
                return seg.executable
        return False

    def confirm_offset_origin(self, candidates):
        self.prompt_calls.append(list(candidates))
        if self._prompt is None:
            return None
        return self._prompt(candidates)

    # -- legacy ASLR hooks ----------------------------------------------
    def get_instruction_addresses(self):
        return list(self._instructions)


def elf_segments(imagebase=0, text_filepos=0x1000, text_size=0x60000):
    """
    A plausible ELF-ish layout that covers the example offsets (~0x59290):
    .text at file offset 0x1000, .data right after it. Both segments agree
    on the origin (``start - filepos == imagebase``), so they deduplicate
    into a single candidate.
    """
    return [
        SegmentInfo(".text", imagebase + text_filepos,
                    imagebase + text_filepos + text_size,
                    filepos=text_filepos, executable=True),
        SegmentInfo(".data", imagebase + 0x61000, imagebase + 0x63000,
                    filepos=0x61000, executable=False),
    ]


#-------------------------------------------------------------------------
# Header parsing / legacy traces
#-------------------------------------------------------------------------

def test_example_tenet_header_is_slide_only():
    if not os.path.exists(EXAMPLE_TENET):
        pytest.skip("example.tenet is not shipped with this repository")
    trace = TraceFile(EXAMPLE_TENET, ArchARM64())
    assert trace.slide == SLIDE
    assert trace.length == 99
    assert trace.has_offsets is False
    assert trace.name == "example.tenet"


def test_legacy_tenet_has_no_offsets():
    if not os.path.exists(EXAMPLE_TENET):
        pytest.skip("example.tenet is not shipped with this repository")
    trace = TraceFile(EXAMPLE_TENET, ArchARM64())
    assert trace.get_off(0) is None
    assert trace.get_off(50) is None
    assert trace.sample_offsets() == []


def test_header_line_is_not_an_event(tmp_path):
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "off=0x59290,pc=0x77968b2290",
        "slide=0x7796859000",   # a stray second header must not become an event
    ])
    trace = TraceFile(path, ArchARM64())
    assert trace.slide == SLIDE
    assert trace.length == 1
    assert trace.get_off(0) == 0x59290


def test_frinet_filename_is_loaded(tmp_path):
    path = write_trace(tmp_path, ["off=0x59290,pc=0x77968b2290"])
    assert path.endswith(".frinet")
    trace = TraceFile(path, ArchARM64())
    assert trace.name.endswith(".frinet")
    assert trace.get_ip(0) == SLIDE + 0x59290


def test_tenet_filename_is_loaded(tmp_path):
    path = write_trace(
        tmp_path,
        ["pc=0x77968b2290"],
        name="legacy_1700000000_7.tenet",
    )
    trace = TraceFile(path, ArchARM64())
    assert trace.has_offsets is False
    assert trace.get_ip(0) == SLIDE + 0x59290


def test_trace_without_header_still_loads(tmp_path):
    path = write_trace(tmp_path, ["pc=0x401000"], name="noheader.tenet")
    trace = TraceFile(path, ArchARM64())
    assert trace.slide is None
    assert trace.length == 1


#-------------------------------------------------------------------------
# Offsets
#-------------------------------------------------------------------------

def test_frinet_offsets_match_pc_minus_slide(tmp_path):
    path, lines = convert_example(tmp_path)
    trace = TraceFile(path, ArchARM64())

    assert trace.slide == SLIDE
    assert trace.has_offsets is True
    assert trace.length == 99
    assert lines[0] == "slide=0x7796859000"

    for idx in range(trace.length):
        pc = trace.get_ip(idx)
        off = trace.get_off(idx)
        assert off is not None, f"event {idx} lost its offset"
        assert off == pc - SLIDE
        assert 0 <= off < SIZE


def test_reference_offset_table_in_parsed_trace(tmp_path):
    path, _ = convert_example(tmp_path)
    trace = TraceFile(path, ArchARM64())

    expected = {
        0x77968b2290: 0x59290,
        0x77968b2294: 0x59294,
        0x77968b22B0: 0x592B0,
    }
    seen = {}
    for idx in range(trace.length):
        seen[trace.get_ip(idx)] = trace.get_off(idx)

    for pc, off in expected.items():
        assert pc in seen, f"{pc:#x} not in trace"
        assert seen[pc] == off


def test_event_without_offset_stays_in_timeline(tmp_path):
    external_pc = 0x778ED5F010
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "off=0x59290,pc=0x77968b2290,x0=0x1",
        f"pc={external_pc:x},x0=0x2",          # outside the module: no off=
        "off=0x59294,pc=0x77968b2294,x0=0x3",
    ])
    trace = TraceFile(path, ArchARM64())

    assert trace.length == 3
    assert trace.get_ip(1) == external_pc
    assert trace.get_off(1) is None          # never mapped into the IDB
    assert trace.get_off(0) == 0x59290
    assert trace.get_off(2) == 0x59294
    # index continuity: the external event did not shift anything
    assert trace.get_ip(2) == 0x77968b2294


def test_x64_trace_uses_rip_as_ip(tmp_path):
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "off=0x59290,rip=0x77968b2290,rax=0x1",
    ], name="app_1700000000_1.frinet")
    trace = TraceFile(path, ArchAMD64())
    assert trace.arch.IP == "RIP"
    assert trace.get_ip(0) == SLIDE + 0x59290
    assert trace.get_off(0) == 0x59290


def test_sample_offsets_is_bounded(tmp_path):
    path, _ = convert_example(tmp_path)
    trace = TraceFile(path, ArchARM64())
    samples = trace.sample_offsets(max_samples=4)
    assert 0 < len(samples) <= 4
    assert all(isinstance(off, int) and off >= 0 for off in samples)


#-------------------------------------------------------------------------
# Malformed / partial input
#-------------------------------------------------------------------------

def test_malformed_lines_are_skipped_not_fatal(tmp_path):
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "off=0x59290,pc=0x77968b2290",
        "pc=not-a-hex-value",                  # bad value
        "bogus_field=0x1,pc=0x77968b2294",     # unknown field
        "no_equals_sign_here",                 # not a field at all
        "off=0x59298,pc=0x77968b2298",
    ])
    trace = TraceFile(path, ArchARM64())

    # only the two well formed events survived, indexes stayed contiguous
    assert trace.length == 2
    assert trace.get_ip(0) == SLIDE + 0x59290
    assert trace.get_ip(1) == SLIDE + 0x59298
    assert trace.get_off(1) == 0x59298


def test_event_without_pc_is_dropped(tmp_path):
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "x0=0x1",                              # no instruction pointer
        "off=0x59290,pc=0x77968b2290",
    ])
    trace = TraceFile(path, ArchARM64())
    assert trace.length == 1
    assert trace.get_ip(0) == SLIDE + 0x59290


def test_blank_lines_are_ignored(tmp_path):
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "",
        "off=0x59290,pc=0x77968b2290",
        "",
        "",
    ])
    trace = TraceFile(path, ArchARM64())
    assert trace.length == 1


def test_fields_are_not_reordered_by_the_parser(tmp_path):
    line = "x0=0x1,x13=0xe3,pc=0x77968b2294,mw=0x1000:deadbeef"
    path = write_trace(tmp_path, ["slide=0x7796859000", "off=0x59294," + line])
    trace = TraceFile(path, ArchARM64())

    regs = trace.get_reg_delta(0)
    assert regs["X0"] == 0x1
    assert regs["X13"] == 0xE3
    assert regs["PC"] == 0x77968b2294
    writes = trace.get_write_delta(0)
    assert len(writes) == 1
    address, data = writes[0]
    assert address == 0x1000
    assert bytes(data) == b"\xde\xad\xbe\xef"


#-------------------------------------------------------------------------
# Reader wiring
#-------------------------------------------------------------------------

def make_reader(path, dctx, arch=None):
    return TraceReader(path, arch or ArchARM64(), dctx)


def test_rebased_ip_prefers_offset(tmp_path):
    path, _ = convert_example(tmp_path)
    segments = elf_segments(imagebase=0)
    dctx = FakeDctx(segments, imagebase=0, root_filename="libfoo.so")
    reader = make_reader(path, dctx)

    # a clean resolution must never interrupt the user with a prompt
    assert dctx.prompt_calls == []

    reader.seek(0)
    assert reader.offset == 0x59290
    # static_ea = idb_module_start + off  (origin resolved from .text filepos)
    assert reader.analysis.offset_origin == 0
    assert reader.rebased_ip == segments[0].start - 0x1000 + 0x59290

    reader.seek(1)
    assert reader.rebased_ip == reader.analysis.offset_origin + reader.offset


def test_rebased_ip_falls_back_without_offsets(tmp_path):
    path = write_trace(tmp_path, ["pc=0x77968b2290"], name="legacy_1_1.tenet")
    segments = elf_segments(imagebase=0)
    dctx = FakeDctx(segments, imagebase=0, root_filename="libfoo.so")
    reader = make_reader(path, dctx)

    assert reader.has_offsets is False
    reader.seek(0)
    assert reader.get_offset(0) is None
    assert reader.analysis.offset_origin is None
    # legacy path: without instruction addresses there is nothing to
    # rebase against, so the raw trace address is returned unchanged
    assert reader.rebased_ip == 0x77968b2290


def test_event_without_off_is_not_mapped_by_offset(tmp_path):
    path = write_trace(tmp_path, [
        "slide=0x7796859000",
        "off=0x59290,pc=0x77968b2290",
        "pc=0x778ed5f010",
    ])
    dctx = FakeDctx(elf_segments(), imagebase=0, root_filename="libfoo.so")
    reader = make_reader(path, dctx)

    reader.seek(1)
    assert reader.get_offset(1) is None
    # offset path is unavailable -> legacy rebase (returns the address as is)
    assert reader.analysis.translate_offset(None) is None
    assert reader.rebased_ip == 0x778ed5f010


def test_translate_offset_requires_a_resolution(tmp_path):
    path = write_trace(tmp_path, ["off=0x59290,pc=0x77968b2290"])
    dctx = FakeDctx([], imagebase=0)  # no segments at all
    reader = make_reader(path, dctx)
    assert reader.analysis.offset_resolution is not None
    # imagebase candidate with no segments: validated as unmapped -> refused
    assert reader.analysis.offset_origin is None
    assert reader.analysis.translate_offset(0x59290) is None


#-------------------------------------------------------------------------
# Image identity
#-------------------------------------------------------------------------

@pytest.mark.parametrize(
    "value,expected",
    [
        ("libfoo.so_1700000000_42.frinet", "libfoo.so"),
        ("libfoo.so_1700000000_42.tenet", "libfoo.so"),
        ("/data/local/tmp/libfoo.so_1700000000_42.frinet", "libfoo.so"),
        ("my-app (1)_1700000000_7.frinet", "my-app (1)"),
        ("example.tenet", None),
        ("something.tenet", None),
        (None, None),
    ],
)
def test_module_name_from_trace_filename(value, expected):
    assert module_name_from_trace_filename(value) == expected


def test_normalize_image_name():
    assert normalize_image_name("/a/b/LibFoo.SO") == "libfoo.so"
    assert normalize_image_name("C:\\x\\libfoo.so") == "libfoo.so"
    assert normalize_image_name(None) == ""


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("libfoo.so", "libfoo.so", MATCH_EXACT),
        ("/data/libfoo.so", "libfoo.so", MATCH_EXACT),
        ("libfoo.so", "libfoo.so.1", MATCH_POSSIBLE),
        ("libfoo.so", "libbar.so", MATCH_MISMATCH),
        ("libfoo.so", "", MATCH_UNKNOWN),
        (None, "libfoo.so", MATCH_UNKNOWN),
    ],
)
def test_names_match(left, right, expected):
    assert names_match(left, right) == expected


def test_identify_image():
    identity = identify_image("libfoo.so_1700000000_3.frinet", "libfoo.so")
    assert identity.match == MATCH_EXACT
    assert identity.trusted is True

    identity = identify_image("libbar.so_1700000000_1.frinet", "libfoo.so")
    assert identity.match == MATCH_MISMATCH
    assert identity.trusted is False


def test_image_mismatch_requires_confirmation(tmp_path):
    path = write_trace(tmp_path, ["off=0x59290,pc=0x77968b2290"],
                       name="libbar.so_1700000000_1.frinet")
    dctx = FakeDctx(elf_segments(), imagebase=0, root_filename="libfoo.so")
    reader = make_reader(path, dctx)

    resolution = reader.analysis.offset_resolution
    assert resolution.ambiguous is True
    assert resolution.identity.match == MATCH_MISMATCH
    # no confirmation was possible (prompt returned None) -> refuse to map
    assert resolution.origin is None
    assert len(dctx.prompt_calls) == 1


def test_image_mismatch_does_not_block_overwhelming_evidence():
    """
    A single candidate that maps 64/64 sampled offsets (all of them in code)
    is proof that the mapping is right, even when the image *name* differs.
    Blocking there just asks the user a question whose answer is already
    established -- this is what the real-world PerfectPiano session hit.
    """
    segments = elf_segments(imagebase=0)
    identity = identify_image("libbar.so_1700000000_3.frinet", "libfoo.so")
    assert identity.match == MATCH_MISMATCH

    prompt_calls = []
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(),          # 64 samples, all inside .text
        imagebase=0,
        identity=identity,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
        is_code=lambda ea: any(s.contains(ea) and s.executable for s in segments),
        prompt=lambda candidates: prompt_calls.append(candidates),
    )

    resolution = resolver.resolve()
    assert resolution.resolved is True
    assert resolution.origin == 0
    assert resolution.reason == "image-mismatch-overridden"
    # nothing to ask: the offsets already answer the question
    assert prompt_calls == []


def test_image_mismatch_still_blocks_when_evidence_is_weak():
    """Too few samples to be overwhelming -> the name mismatch must win."""
    segments = elf_segments(imagebase=0)
    identity = identify_image("libbar.so_1700000000_3.frinet", "libfoo.so")
    prompted = []
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(count=4),   # below MIN_TRUST_SAMPLES
        imagebase=0,
        identity=identity,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
        is_code=lambda ea: any(s.contains(ea) and s.executable for s in segments),
        prompt=lambda candidates: prompted.append(candidates),
    )
    resolution = resolver.resolve()
    assert resolution.ambiguous is True
    assert resolution.origin is None
    # it asked, rather than silently overriding the mismatch
    assert len(prompted) == 1
    assert resolution.reason == "cancelled"


def test_image_mismatch_still_blocks_when_scores_imperfect():
    """
    Plenty of samples, but one of them lands outside the database: the
    evidence is not overwhelming, so the mismatch stays blocking.
    """
    segments = elf_segments(imagebase=0)
    identity = identify_image("libbar.so_1700000000_3.frinet", "libfoo.so")
    prompted = []
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs() + [0xDEAD0000],   # one miss -> 64/65
        imagebase=0,
        identity=identity,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
        is_code=lambda ea: any(s.contains(ea) and s.executable for s in segments),
        prompt=lambda candidates: prompted.append(candidates),
    )
    resolution = resolver.resolve()
    assert resolution.ambiguous is True
    assert resolution.origin is None
    assert len(prompted) == 1
    assert resolution.reason == "cancelled"


def test_mismatch_override_reaches_the_reader(tmp_path):
    """
    End to end: a realistic number of offsets, wrong image name, and no
    prompt at all -- the trace still maps.
    """
    lines = [f"off=0x{off:X},pc=0x{SLIDE + off:X}" for off in sample_offs(count=64)]
    path = write_trace(tmp_path, lines, name="libbar.so_1700000000_1.frinet")
    dctx = FakeDctx(elf_segments(), imagebase=0, root_filename="libfoo.so")
    reader = make_reader(path, dctx)

    resolution = reader.analysis.offset_resolution
    assert resolution.resolved is True
    assert resolution.origin == 0
    assert resolution.reason == "image-mismatch-overridden"
    assert dctx.prompt_calls == []
    # and the offsets really do translate: static_ea = origin + off
    reader.idx = 0
    assert reader.rebased_ip == 0 + reader.get_offset(0)


#-------------------------------------------------------------------------
# OffsetResolver (pure)
#-------------------------------------------------------------------------

def sample_offs(start=0x1000, count=64, step=4):
    return [start + i * step for i in range(count)]


def test_resolver_picks_filepos_origin_over_imagebase():
    segments = elf_segments(imagebase=0)
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(),
        imagebase=0,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
        is_code=lambda ea: any(s.contains(ea) and s.executable for s in segments),
    )
    resolution = resolver.resolve()
    assert resolution.resolved is True
    assert resolution.origin == 0
    assert resolution.to_ea(0x59290) == 0x59290


def test_resolver_handles_rebased_database():
    """imagebase lies, the segments tell the truth."""
    imagebase = 0x0
    segments = elf_segments(imagebase=0x400000)  # segments rebased, imagebase not
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(),
        imagebase=imagebase,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
    )
    resolution = resolver.resolve()
    assert resolution.resolved is True
    assert resolution.origin == 0x400000  # = start - filepos for .text
    assert resolution.to_ea(0x1000) == 0x401000


def test_resolver_refuses_when_nothing_maps():
    segments = elf_segments(imagebase=0)
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(),
        imagebase=0,
        is_mapped=lambda ea: False,      # nothing ever lands in the database
    )
    resolution = resolver.resolve()
    assert resolution.resolved is False
    assert resolution.ambiguous is True
    assert resolution.reason == "low-score"


def test_resolver_ambiguous_tie_without_prompt_is_refused():
    #
    # two different origins that *both* explain every sampled offset: no
    # amount of scoring can tell them apart, so the resolver must refuse
    # (rather than guess) when nobody is around to confirm.
    #
    segments = [
        SegmentInfo(".a", 0x10000, 0x20000, filepos=0, executable=True),
        SegmentInfo(".b", 0x80000, 0x90000, filepos=0, executable=True),
    ]

    def mapped(ea):
        return (0x10000 <= ea < 0x10100) or (0x80000 <= ea < 0x80100)

    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(start=0x10, count=32, step=4),
        imagebase=None,
        is_mapped=mapped,
    )
    resolution = resolver.resolve()
    # cannot decide between candidates -> never guess
    assert len(resolution.candidates) == 2
    assert resolution.ambiguous is True
    assert resolution.reason == "tie"
    assert resolution.origin is None


def test_resolver_uses_prompt_when_ambiguous():
    segments = elf_segments(imagebase=0)

    def prompt(candidates):
        # pretend the user picked the imagebase candidate
        for candidate in candidates:
            if candidate.source == "imagebase":
                return candidate
        return candidates[0]

    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(),
        imagebase=0,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
        prompt=prompt,
    )
    #
    # a single sample offset that lands *outside* every segment scores 0
    # for every candidate: the resolver has to ask, and the user's answer
    # wins.
    #
    resolver.sample_offs = sample_offs(start=0, count=1)
    resolution = resolver.resolve()
    assert resolution.ambiguous is True
    assert resolution.origin == 0
    assert resolution.reason == "confirmed"


def test_resolver_cancel_leaves_origin_unresolved():
    segments = elf_segments(imagebase=0)
    resolver = OffsetResolver(
        segments=segments,
        sample_offs=sample_offs(start=0, count=1),
        imagebase=0,
        is_mapped=lambda ea: any(s.contains(ea) for s in segments),
        prompt=lambda candidates: None,
    )
    resolution = resolver.resolve()
    assert resolution.ambiguous is True
    assert resolution.origin is None
    assert resolution.reason == "cancelled"


def test_resolver_without_candidates():
    resolver = OffsetResolver(segments=[], sample_offs=[], imagebase=None)
    resolution = resolver.resolve()
    assert resolution.resolved is False
    assert resolution.reason == "no-candidates"
    assert resolution.to_ea(0x10) is None


def test_resolution_to_ea_is_none_without_origin():
    resolution = Resolution(None, None, [], True, "no-candidates")
    assert resolution.to_ea(0x10) is None
    assert resolution.resolved is False


def test_resolver_without_validation_single_candidate_is_accepted():
    segments = elf_segments(imagebase=0)
    resolver = OffsetResolver(
        segments=[segments[0]],     # only .text -> one candidate (0x0)
        sample_offs=sample_offs(),
        imagebase=None,
    )
    resolution = resolver.resolve()
    assert resolution.resolved is True
    assert resolution.origin == 0


def test_resolver_without_validation_multiple_candidates_refuses():
    segments = elf_segments(imagebase=0)
    resolver = OffsetResolver(
        segments=segments,          # .text -> 0x0, .data -> 0x0 ... 2 candidates
        sample_offs=sample_offs(),
        imagebase=0x1234,
    )
    resolution = resolver.resolve()
    assert len(resolution.candidates) >= 2
    assert resolution.ambiguous is True
    assert resolution.origin is None


def test_segment_origin_and_contains():
    seg = SegmentInfo(".text", 0x401000, 0x441000, filepos=0x1000, executable=True)
    assert seg.origin == 0x400000
    assert seg.size == 0x40000
    assert seg.contains(0x401000) is True
    assert seg.contains(0x441000) is False
    assert seg.offset_to_ea(0x1000) == 0x401000
    assert seg.offset_to_ea(0xFFFFF) is None

    no_filepos = SegmentInfo(".bss", 0x500000, 0x501000, filepos=-1)
    assert no_filepos.origin is None
    assert no_filepos.offset_to_ea(0) is None
