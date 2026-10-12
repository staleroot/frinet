"""
Tests for the FRINET pseudocode synchronisation layer.

Everything here runs without IDA or Qt: the lexer, the expression map, the
caches, the navigation aids and the controller are all pure Python with
their disassembler / GUI dependencies injected as fakes.

The *IDA* half of the same features (real Hex-Rays harvesting, real widget
placement, real dock behaviour) cannot execute in this environment and is
covered by the manual test plan in ``docs/manual-testing.md`` instead. No
test in this file claims anything about a live IDA session.
"""

import logging

import pytest

from tenet.sync import (
    Bookmarks,
    DecompileCache,
    Generation,
    History,
    LRUCache,
    LookupResult,
    NullScheduler,
    OccurrenceIndex,
    PRECISION_EXPR,
    PRECISION_ITEM,
    PRECISION_LINE,
    PRECISION_NEAREST,
    PRECISION_NONE,
    PseudoItem,
    PseudoMap,
    PseudocodeSyncController,
    SyncEvent,
    TaggedSpan,
    lex_tagged_line,
    plan_prefetch,
    strip_tags,
)
from tenet.sync.lexer import COLOR_ADDR, COLOR_ESC, COLOR_OFF, COLOR_ON


#-------------------------------------------------------------------------
# Helpers
#-------------------------------------------------------------------------

def tag(index, text):
    """
    Wrap ``text`` in the address token Hex-Rays emits for one ctree item.

    The real emission (see ``lex_citem_indexes`` in
    ``integration/api/ida_api.py``) is ``COLOR_ON COLOR_ADDR <hex index>``
    followed by the item's rendered text.
    """
    return (chr(COLOR_ON) + chr(COLOR_ADDR) + "%016X" % index + text)


def styled(text, color=0x20):
    """Wrap ``text`` in a purely stylistic span (no address token)."""
    return chr(COLOR_ON) + chr(color) + text + chr(COLOR_OFF) + chr(color)


def make_reader(trace_length=8, offs=None, ips=None, origin=0x401000,
                slide=0x7000000000, mapped=(0x401000, 0x402000)):
    """
    A minimal stand-in for tenet.trace.reader.TraceReader.

    ``mapped`` is the address range the fake database contains; anything
    outside it reports as unmapped so the controller's mapping checks can
    be exercised.
    """

    class Analysis(object):
        def __init__(self, origin):
            self.offset_origin = origin

        def translate_offset(self, off):
            if self.offset_origin is None or off is None:
                return None
            return self.offset_origin + off

        def rebase_pointer(self, address):
            # a legacy 'no idea' rebase returns the address unchanged
            return address

        def _is_mapped(self, address):
            if mapped is None or address is None:
                return None
            low, high = mapped
            return bool(low <= address < high)

    class Trace(object):
        def __init__(self, length):
            self.length = length

    class Reader(object):
        pass

    reader = Reader()
    reader.trace = Trace(trace_length)
    reader.analysis = Analysis(origin)
    reader._offs = list(offs or [None] * trace_length)
    reader._ips = list(ips or [slide + 0x100 * i for i in range(trace_length)])
    reader._callbacks = []

    reader.get_offset = lambda idx: (
        reader._offs[idx] if 0 <= idx < len(reader._offs) else None)
    reader.get_ip = lambda idx: (
        reader._ips[idx] if 0 <= idx < len(reader._ips) else None)

    def idx_changed(callback):
        reader._callbacks.append(callback)

    reader.idx_changed = idx_changed

    def seek(idx):
        reader.idx = idx
        for callback in reader._callbacks:
            callback(idx)

    reader.seek = seek
    reader.idx = -1
    return reader


class FakeHexRays(object):
    """A stand-in for tenet.sync.hexrays_api."""

    def __init__(self, pmap=None, entry_ea=0x401000, widget=True,
                 openable=True, widget_entry=None):
        self.pmap = pmap
        self.entry_ea = entry_ea
        self.widget = widget
        self.openable = openable

        #
        # which function the open view is showing. Defaults to the traced
        # one so a plain fake already has the right view open; a test that
        # wants "a pseudocode window is open, but on some other function"
        # sets it to a different entry.
        #
        self.widget_entry = entry_ea if widget_entry is None else widget_entry

        self.decompile_calls = []
        self.map_calls = []
        self.jump_calls = []
        self.open_calls = []
        self.track_calls = []
        self.decompile_result = object()
        self.map_result = pmap

        # navigation outcomes a test can flip to reproduce a refused or a
        # raising jump
        self.jump_refused = False
        self.jump_raises = None

    def function_entry_ea(self, ea):
        return self.entry_ea if self.entry_ea is not None else None

    def decompile(self, ea):
        self.decompile_calls.append(ea)
        return self.decompile_result

    def build_pseudo_map(self, cfunc):
        self.map_calls.append(cfunc)
        return self.map_result

    def find_pseudocode_widget(self, ea=None):
        if self.widget is None:
            return None
        if ea is None:
            return self.widget
        # only a view already showing the requested function counts
        if self.entry_ea is None or self.widget_entry is None:
            return self.widget
        return self.widget if self.widget_entry == self.entry_ea else None

    def open_pseudocode_widget(self, ea):
        """
        Stand in for ``open_pseudocode(ea, OPF_REUSE)``: reuse the existing
        window, now showing ``ea`` -- so the fake's view ends up on the
        requested function either way.
        """
        self.open_calls.append(ea)
        if not self.openable:
            return None
        if self.widget is None:
            self.widget = object()
        self.widget_entry = self.entry_ea
        return self.widget

    def ensure_widget_tracking(self):
        self.track_calls.append(True)
        return True

    def describe_open_pseudocode(self):
        if self.widget is None:
            return "(none)"
        if self.widget_entry is None:
            return "(unknown)"
        return "0x%X" % self.widget_entry

    def jump_to_item(self, vdui, line, x=0, length=1, activate=True, ea=None):
        """
        Stand in for the real navigation.

        ``self.jump_refused`` / ``self.jump_raises`` reproduce the two ways a
        jump can fail, which are otherwise indistinguishable from the
        controller's side -- the second is the one that used to be invisible.
        """
        self.jump_calls.append((vdui, line, x, length, ea))
        if self.jump_raises is not None:
            raise self.jump_raises
        return not self.jump_refused

    def function_name(self, ea):
        return "sub_%X" % ea


#-------------------------------------------------------------------------
# Color tag lexer
#-------------------------------------------------------------------------

def test_lexer_finds_single_tagged_span():
    line = "    " + tag(7, "v1 + 2")
    spans = lex_tagged_line(line)

    assert len(spans) == 1
    span = spans[0]
    assert span.index == 7
    assert span.x == 4                       # after the leading indent
    assert span.length == len("v1 + 2")
    assert span.order == 0                   # the only token on the line


def test_lexer_reports_preorder_nesting():
    #
    # Hex-Rays prints a ctree in preorder, so in 'a + b * c' the token for
    # the multiplication comes *after* the addition's. The later token is
    # the inner one: that is what FRINET uses to prefer the operand over
    # the whole statement.
    #
    line = "  " + tag(1, "a + ") + tag(3, "b * c")

    spans = lex_tagged_line(line)
    by_index = {span.index: span for span in spans}

    assert by_index[1].order == 0            # printed first == outermost
    assert by_index[3].order == 1            # printed later == inner
    assert by_index[3].x == by_index[1].x + len("a + ")
    assert by_index[3].length == len("b * c")
    # a span runs to the *next* token, so lengths partition the visible
    # line (an approximation of the item's real extent -- see lexer.py)
    assert by_index[1].length == len("a + ")


def test_lexer_ignores_purely_styled_spans():
    # a keyword carries color but no COLOR_ADDR token: no ctree identity
    line = styled("if") + " (v1)"
    assert lex_tagged_line(line) == []
    assert strip_tags(line) == "if (v1)"


def test_lexer_skips_truncated_addr_payload():
    # only 4 of the 16 hex digits: the token is dropped, the rest survives
    broken = chr(COLOR_ON) + chr(COLOR_ADDR) + "00AB"
    line = broken + tag(1, "x")
    spans = lex_tagged_line(line)
    assert [span.index for span in spans] == [1]


def test_lexer_skips_non_hex_addr_payload():
    line = (chr(COLOR_ON) + chr(COLOR_ADDR) + "ZZZZZZZZZZZZZZZZ" +
            tag(1, "x"))
    assert [span.index for span in lex_tagged_line(line)] == [1]


def test_lexer_tolerates_unbalanced_color_off():
    # more COLOR_OFF (tag + colour byte) than COLOR_ON must not raise
    line = (chr(COLOR_OFF) + chr(0x20)) * 4 + "abc"
    assert strip_tags(line) == "abc"
    assert lex_tagged_line(line) == []


def test_lexer_treats_escape_sequences_as_visible_text():
    # COLOR_ESC + <byte> renders as that literal byte
    line = "a" + chr(COLOR_ESC) + chr(COLOR_ON) + "b"
    assert strip_tags(line) == "a\x01b"


def test_strip_tags_hides_addr_payload():
    line = tag(0x2A, "result")
    assert strip_tags(line) == "result"


def test_lexer_handles_two_sibling_spans():
    line = "  " + tag(1, "a") + " + " + tag(2, "b")
    spans = lex_tagged_line(line)
    # 'b' starts at column 6 of "  a + b"; its token is the second address
    # token of the line, hence order 1 (siblings never share an x, so the
    # order only breaks ties among tokens rendering at the same column)
    assert [(s.index, s.x, s.order) for s in spans] == [(1, 2, 0), (2, 6, 1)]
    assert spans[0].length == len("a + ")   # runs to the next token


def test_lexer_mixed_styled_and_addressed_text():
    line = styled("if", 0x20) + "(" + tag(4, "v1") + ")"
    assert [span.index for span in lex_tagged_line(line)] == [4]
    assert strip_tags(line) == "if(v1)"
    # the address token starts right after 'if('
    assert lex_tagged_line(line)[0].x == 3


def test_tagged_span_equality():
    assert TaggedSpan(1, 2, 3, 0) == TaggedSpan(1, 2, 3, 0)
    assert TaggedSpan(1, 2, 3, 0) != TaggedSpan(9, 2, 3, 0)
    assert TaggedSpan(1, 2, 3, 0) != "not a span"


#-------------------------------------------------------------------------
# Expression map / precision hierarchy
#-------------------------------------------------------------------------

def item(ea, line=0, x=0, order=0, is_expr=True, has_coords=True, length=1):
    return PseudoItem(ea=ea, line=line, x=x, length=length, order=order,
                      is_expr=is_expr, has_coords=has_coords)


def test_lookup_prefers_deepest_expression():
    pmap = PseudoMap(entry_ea=0x401000)
    pmap.add(item(0x401100, line=5, x=4, order=0, is_expr=False))  # statement
    pmap.add(item(0x401100, line=5, x=4, order=1, is_expr=True))   # operator
    pmap.add(item(0x401100, line=5, x=8, order=2, is_expr=True))   # operand

    result = pmap.lookup(0x401100)
    assert result.precision == PRECISION_EXPR
    assert result.item.order == 2
    assert result.item.x == 8
    assert result.line == 5
    assert result.exact is True


def test_lookup_falls_back_to_statement_when_no_expression():
    pmap = PseudoMap()
    pmap.add(item(0x401100, line=2, x=0, order=0, is_expr=False))

    result = pmap.lookup(0x401100)
    assert result.precision == PRECISION_ITEM
    assert result.item.is_expr is False


def test_lookup_uses_line_precision_without_column_info():
    pmap = PseudoMap()
    pmap.add(item(0x401100, line=9, x=0, order=1, has_coords=False))

    result = pmap.lookup(0x401100)
    assert result.precision == PRECISION_LINE
    assert result.line == 9
    assert result.exact is True      # the address is certain, the column is not


def test_lookup_never_mixes_column_aware_and_line_only_items():
    # a line-only item must not shadow a precise one at the same address
    pmap = PseudoMap()
    pmap.add(item(0x401100, line=1, has_coords=False))
    pmap.add(item(0x401100, line=1, x=6, order=2, is_expr=True))

    assert pmap.lookup(0x401100).precision == PRECISION_EXPR


def test_lookup_nearest_is_reported_as_approximate():
    pmap = PseudoMap()
    pmap.add(item(0x401100, line=3, x=0, order=0))

    result = pmap.lookup(0x401110)      # 0x10 away, not exactly mapped
    assert result.precision == PRECISION_NEAREST
    assert result.exact is False
    assert result.item.ea == 0x401100


def test_lookup_returns_none_when_nothing_is_close():
    pmap = PseudoMap()
    pmap.add(item(0x401100, line=0))

    result = pmap.lookup(0x500000)
    assert result.precision == PRECISION_NONE
    assert result.found is False
    assert result.item is None
    assert result.line is None


def test_lookup_respects_max_distance():
    pmap = PseudoMap()
    pmap.add(item(0x401100, line=0))

    # just inside the default window
    assert pmap.lookup(0x401100 + 0x4000).precision == PRECISION_NEAREST
    # just outside
    assert pmap.lookup(0x401100 + 0x4001).precision == PRECISION_NONE


def test_empty_map_never_maps_anything():
    pmap = PseudoMap()
    result = pmap.lookup(0x401000)
    assert result.precision == PRECISION_NONE
    assert pmap.mapped_addresses() == []
    assert pmap.nearest(0x401000) is None


def test_items_at_and_mapped_addresses():
    pmap = PseudoMap()
    pmap.add(item(0x10, line=0))
    pmap.add(item(0x10, line=1))
    pmap.add(item(0x20, line=2))

    assert len(pmap.items_at(0x10)) == 2
    assert pmap.items_at(0x99) == []
    assert pmap.mapped_addresses() == [0x10, 0x20]
    assert len(pmap) == 3


def test_lookup_result_exact_flag():
    assert LookupResult(PRECISION_EXPR).exact is True
    assert LookupResult(PRECISION_ITEM).exact is True
    assert LookupResult(PRECISION_LINE).exact is True
    assert LookupResult(PRECISION_NEAREST).exact is False
    assert LookupResult(PRECISION_NONE).exact is False
    assert LookupResult(PRECISION_NONE).found is False


#-------------------------------------------------------------------------
# LRU cache / generation tokens / prefetch planner
#-------------------------------------------------------------------------

def test_lru_cache_evicts_least_recently_used():
    cache = LRUCache(2)
    cache.put("a", 1)
    cache.put("b", 2)
    assert cache.get("a") == 1        # 'a' becomes most recently used
    cache.put("c", 3)                 # evicts 'b'

    assert "b" not in cache
    assert cache.get("a") == 1
    assert cache.get("c") == 3
    assert len(cache) == 2


def test_lru_cache_peek_does_not_change_recency():
    cache = LRUCache(2)
    cache.put("a", 1)
    cache.put("b", 2)
    assert cache.peek("a") == 1       # peek: no recency change
    cache.put("c", 3)                 # evicts 'a'

    assert "a" not in cache
    assert cache.get("b") == 2


def test_lru_cache_replaces_existing_key():
    cache = LRUCache(2)
    cache.put("a", 1)
    cache.put("a", 2)
    assert cache.get("a") == 2
    assert len(cache) == 1


def test_lru_cache_rejects_zero_capacity():
    with pytest.raises(AssertionError):
        LRUCache(0)


def test_lru_cache_clear_and_pop():
    cache = LRUCache(4)
    cache.put("a", 1)
    assert cache.pop("a") == 1
    assert cache.pop("a") is None
    cache.put("b", 2)
    cache.clear()
    assert len(cache) == 0
    assert bool(cache) is False


def test_generation_token_detects_staleness():
    generation = Generation()
    token = generation.current()
    assert generation.is_current(token)

    generation.bump()
    assert not generation.is_current(token)
    assert generation.is_current(generation.current())


def test_decompile_cache_is_bounded_and_separate():
    cache = DecompileCache(decompile_size=2, map_size=1)
    cache.put_cfunc(0x1000, "f1")
    cache.put_cfunc(0x2000, "f2")
    cache.put_cfunc(0x3000, "f3")
    assert cache.get_cfunc(0x1000) is None      # evicted
    assert cache.get_cfunc(0x3000) == "f3"

    cache.put_map(0x1000, "m1")
    cache.put_map(0x2000, "m2")
    assert cache.get_map(0x1000) is None        # maps bounded separately
    assert cache.get_map(0x2000) == "m2"

    cache.invalidate(0x2000)
    assert cache.get_cfunc(0x2000) is None
    cache.clear()
    assert len(cache.cfuncs) == 0 and len(cache.maps) == 0


def test_plan_prefetch_is_nearest_first_and_alternating():
    mapped = [0, 10, 20, 30, 40, 50]
    assert plan_prefetch(25, mapped, budget=4) == [30, 20, 40, 10]


def test_plan_prefetch_excludes_center_and_dedupes():
    mapped = [5, 5, 10, 10, 15]
    result = plan_prefetch(10, mapped, budget=10)
    assert 10 not in result
    assert len(result) == len(set(result))


def test_plan_prefetch_bounds_the_result():
    mapped = list(range(0, 1000, 10))
    assert len(plan_prefetch(500, mapped, budget=3)) == 3


def test_plan_prefetch_handles_empty_and_zero_budget():
    assert plan_prefetch(0, [], budget=8) == []
    assert plan_prefetch(0, [1, 2, 3], budget=0) == []


def test_plan_prefetch_at_the_edges():
    mapped = [10, 20, 30]
    assert plan_prefetch(5, mapped, budget=2) == [10, 20]
    assert plan_prefetch(100, mapped, budget=2) == [30, 20]


#-------------------------------------------------------------------------
# Navigation aids
#-------------------------------------------------------------------------

def test_history_records_and_walks_back_and_forward():
    history = History()
    assert history.record(100) is True
    assert history.record(200) is True
    assert history.current == 200

    assert history.can_go_back is True
    assert history.back() == 100
    assert history.can_go_forward is True
    assert history.forward() == 200


def test_history_record_clears_the_forward_stack():
    history = History()
    for position in (1, 2, 3):
        history.record(position)
    history.back()                     # at 2

    history.record(9)                  # new visit
    assert history.can_go_forward is False
    assert history.current == 9


def test_history_ignores_repeated_and_none_positions():
    history = History()
    assert history.record(5) is True
    assert history.record(5) is False      # already there
    assert history.record(None) is False
    assert len(history) == 1


def test_history_is_bounded():
    history = History(max_entries=3)
    for position in range(10):
        history.record(position)
    assert len(history) == 3
    assert history.current == 9
    assert history.can_go_back is True
    history.back()
    history.back()
    assert history.can_go_back is False    # dropped the oldest entries


def test_history_edges_return_none():
    history = History()
    assert history.back() is None
    assert history.forward() is None
    history.record(1)
    assert history.forward() is None


def test_bookmarks_add_list_and_remove():
    bookmarks = Bookmarks()
    bookmarks.add("start", 0)
    bookmarks.add("crash", 1234)

    assert bookmarks.names() == ["crash", "start"]
    assert bookmarks.items() == [("crash", 1234), ("start", 0)]
    assert "crash" in bookmarks
    assert len(bookmarks) == 2
    assert bookmarks.get("crash") == 1234
    assert bookmarks.remove("crash") is True
    assert bookmarks.remove("crash") is False
    assert bookmarks.names() == ["start"]


def test_bookmarks_require_a_name_and_position():
    bookmarks = Bookmarks()
    with pytest.raises(ValueError):
        bookmarks.add("", 1)
    with pytest.raises(ValueError):
        bookmarks.add("x", None)
    bookmarks.clear()
    assert len(bookmarks) == 0


def test_occurrence_index_next_and_prev():
    index = OccurrenceIndex()
    for idx in (10, 20, 30):
        index.add(0x401000, idx)

    assert index.occurrences(0x401000) == [10, 20, 30]
    assert index.count(0x401000) == 3
    assert index.next_occurrence(0x401000, 10) == 20
    assert index.prev_occurrence(0x401000, 30) == 20

    # edges
    assert index.next_occurrence(0x401000, 30) is None
    assert index.prev_occurrence(0x401000, 10) is None


def test_occurrence_index_inclusive_mode():
    index = OccurrenceIndex()
    for idx in (10, 20):
        index.add(0x401000, idx)

    assert index.next_occurrence(0x401000, 10, inclusive=True) == 10
    assert index.prev_occurrence(0x401000, 20, inclusive=True) == 20
    assert index.next_occurrence(0x401000, 10) == 20


def test_occurrence_index_separates_offsets_from_addresses():
    index = OccurrenceIndex()
    index.add(0x401000, 0, off=0x1000)
    index.add(0x401000, 5, off=0x1000)
    index.add(0x778ED5F010, 7, off=None)     # external: no offset

    assert index.occurrences(0x1000) == [0, 5]
    assert index.occurrences(0x401000) == [0, 5]
    assert index.occurrences(0x778ED5F010) == [7]
    assert index.has(0x1000) is True
    assert index.has(0x999) is False


def test_occurrence_index_build_from_reader():
    reader = make_reader(
        trace_length=4,
        offs=[0x10, None, 0x10, 0x20],
        ips=[0x401000, 0x778ED5F010, 0x401000, 0x401010],
    )
    index = OccurrenceIndex.build(reader)

    assert index.truncated is False
    assert index.occurrences(0x10) == [0, 2]
    assert index.occurrences(0x20) == [3]
    # the external event is in the address index but not the offset one
    assert index.occurrences(0x778ED5F010) == [1]
    assert index.size == 3


def test_occurrence_index_build_is_truncated_when_bounded():
    reader = make_reader(trace_length=10, offs=list(range(10)))
    index = OccurrenceIndex.build(reader, max_events=4)

    assert index.truncated is True
    assert index.count(3) == 1
    assert index.count(9) == 0


#-------------------------------------------------------------------------
# Sync controller
#-------------------------------------------------------------------------

def make_pmap():
    pmap = PseudoMap(entry_ea=0x401000)
    pmap.add(item(0x401100, line=4, x=6, order=2, is_expr=True))
    return pmap


def make_controller(hexrays=None, reader=None, scheduler=None, **kwargs):
    hexrays = hexrays or FakeHexRays(pmap=make_pmap())
    reader = reader or make_reader(offs=[0x100, 0x200, 0x300],
                                   ips=[0x7000000100, 0x7000000200, 0x7000000300])

    #
    # the controller refuses to be built without a scheduler, precisely
    # because the default used to be one that quietly never ran anything --
    # so tests say so explicitly, exactly like the plugin does
    #
    if scheduler is None:
        scheduler = NullScheduler()

    controller = PseudocodeSyncController(hexrays, scheduler=scheduler, **kwargs)
    controller.attach_reader(reader)
    return controller, hexrays, reader


#-------------------------------------------------------------------------
# The scheduler contract
#
# this is here because of a real defect: the controller used to default to a
# NullScheduler, whose schedule() stores a callback and never runs it. The
# plugin never passed one, so updates were queued forever. The timeline moved,
# the disassembly moved, the debug log showed addresses resolving correctly,
# and the pseudocode simply never followed -- with nothing anywhere to
# indicate a fault.
#-------------------------------------------------------------------------

def test_controller_refuses_to_be_built_without_a_scheduler():
    """No silent default: every construction site must say what runs its work."""
    with pytest.raises(ValueError) as excinfo:
        PseudocodeSyncController(FakeHexRays(pmap=make_pmap()), scheduler=None)

    assert "scheduler" in str(excinfo.value)


def test_a_starved_scheduler_reports_itself(caplog, monkeypatch):
    """
    NullScheduler is correct in tests and a no-op in the plugin, so the first
    callback it swallows is reported instead of vanishing.
    """
    import tenet.sync.controller as controller_module

    monkeypatch.setattr(controller_module, "_warned_starved_scheduler", False)

    scheduler = NullScheduler()
    with caplog.at_level(logging.WARNING, logger="Tenet.Sync.Controller"):
        scheduler.schedule(lambda: None, 40)

    assert scheduler.scheduled == 1
    assert "nothing will run it" in caplog.text


def test_the_starvation_warning_is_reported_only_once(caplog, monkeypatch):
    """
    A timeline scrub fires one schedule per step. One line about the class of
    problem is useful; fifty a second is noise, and a noisy log gets ignored.
    """
    import tenet.sync.controller as controller_module

    monkeypatch.setattr(controller_module, "_warned_starved_scheduler", False)

    with caplog.at_level(logging.WARNING, logger="Tenet.Sync.Controller"):
        for _ in range(5):
            NullScheduler().schedule(lambda: None, 40)

    assert caplog.text.count("nothing will run it") == 1


def test_a_reader_step_reaches_the_scheduler():
    """
    End to end through the reader, not by calling flush() by hand: the
    index-change callback must actually queue work on the scheduler. This is
    the link whose absence produced the defect above.
    """
    controller, hexrays, reader = make_controller()

    reader.seek(1)

    assert controller.scheduler.scheduled >= 1
    assert controller.scheduler._pending is not None


def test_controller_navigates_to_the_expression_for_an_offset():
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[0x100, 0x200], ips=[0x7000000100, 0x7000000200]),
    )

    reader.seek(0)
    event = controller.flush()

    assert event.applied is True
    assert event.ea == 0x401000 + 0x100
    assert event.precision == PRECISION_EXPR
    # the jump went to the item's own line and column
    assert hexrays.jump_calls[0][1] == 4
    assert hexrays.jump_calls[0][2] == 6


def test_controller_never_decompiles_the_same_function_twice():
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[0x100, 0x200]),
    )

    reader.seek(0)
    controller.flush()
    reader.seek(1)
    controller.flush()

    assert len(hexrays.jump_calls) == 2
    # both events resolve to the same entry, so only one decompile
    assert len(hexrays.decompile_calls) <= 1


def test_controller_opens_a_view_when_none_is_open():
    """
    The behaviour this feature is actually judged on: stepping a fresh
    session has to produce the C code. Declining because nothing was open
    yet made the entire feature look switched off while address resolution
    was working perfectly underneath it.
    """
    fake = FakeHexRays(pmap=make_pmap(), widget=None)
    controller, _, reader = make_controller(hexrays=fake)

    reader.seek(0)
    event = controller.flush()

    assert event.applied is True
    assert fake.open_calls == [event.ea]
    assert fake.jump_calls != []


def test_controller_respects_auto_open_being_disabled():
    fake = FakeHexRays(pmap=make_pmap(), widget=None)
    controller, _, reader = make_controller(hexrays=fake, auto_open=False)

    reader.seek(0)
    event = controller.flush()

    assert event.applied is False
    assert event.reason == "no-pseudocode-widget"
    assert fake.open_calls == []
    assert fake.decompile_calls == []       # no decompilation was forced
    assert fake.jump_calls == []


def test_controller_retargets_a_view_showing_another_function():
    """
    A pseudocode window is open, but on a different function than the one
    the trace is currently in. OPF_REUSE reloads that window instead of
    spawning a second one, so exactly one view follows the trace.
    """
    fake = FakeHexRays(pmap=make_pmap(), widget_entry=0x500000)
    controller, _, reader = make_controller(hexrays=fake)

    reader.seek(0)
    event = controller.flush()

    assert fake.open_calls == [event.ea]
    assert fake.widget_entry == fake.entry_ea     # switched to the trace
    assert event.applied is True


def test_controller_reopens_a_view_once_after_the_user_closes_it():
    """
    A step is an explicit request to see the C, so a single accidental close
    must not switch the feature off. It used to: closing the window meant it
    could never come back, even for an address that had just worked.
    """
    fake = FakeHexRays(pmap=make_pmap(), widget=None)
    controller, _, reader = make_controller(hexrays=fake)

    reader.seek(0)
    assert controller.flush().applied is True     # we opened it
    assert len(fake.open_calls) == 1

    fake.widget = None                            # ...and the user closes it
    reader.seek(1)
    event = controller.flush()

    assert event.applied is True
    assert len(fake.open_calls) == 2


def test_controller_stops_reopening_after_a_second_close():
    """
    The other half: a window that keeps reappearing is worse than no
    synchronisation at all, so the second closure is taken as a decision.
    """
    fake = FakeHexRays(pmap=make_pmap(), widget=None)
    controller, _, reader = make_controller(hexrays=fake)

    reader.seek(0)
    controller.flush()                            # opened
    fake.widget = None
    reader.seek(1)
    controller.flush()                            # reopened once

    fake.widget = None
    reader.seek(2)
    event = controller.flush()

    assert event.applied is False
    assert event.reason == "pseudocode-closed-by-user"
    assert len(fake.open_calls) == 2              # no third attempt


def test_controller_reports_a_function_that_cannot_be_opened():
    fake = FakeHexRays(pmap=make_pmap(), widget=None, openable=False)
    controller, _, reader = make_controller(hexrays=fake)

    reader.seek(0)
    event = controller.flush()

    assert event.reason == "pseudocode-open-failed"
    assert fake.open_calls == [event.ea]


def test_controller_retries_a_broken_function_before_giving_up():
    """
    Bounded, not permanent. One bad attempt -- and a first attempt can fail
    for reasons that have nothing to do with the function, with the
    decompiler still initialising or analysis mid-run -- must not disable
    the feature for the whole trace; but a function that genuinely will not
    decompile is not re-attempted on every step either.
    """
    fake = FakeHexRays(pmap=make_pmap(), widget=None, openable=False)
    controller, _, reader = make_controller(
        hexrays=fake,
        reader=make_reader(offs=[0x100, 0x200, 0x300, 0x400],
                           ips=[0x7000000100, 0x7000000200,
                                0x7000000300, 0x7000000400],
                           trace_length=4),
    )

    for idx in range(controller.MAX_OPEN_ATTEMPTS):
        reader.seek(idx)
        assert controller.flush().reason == "pseudocode-open-failed"

    assert len(fake.open_calls) == controller.MAX_OPEN_ATTEMPTS

    # ...and now it stops, without having taken anything else down with it
    reader.seek(0)
    controller.flush()
    assert len(fake.open_calls) == controller.MAX_OPEN_ATTEMPTS


def test_a_different_function_is_tried_fresh():
    """
    A function that will not decompile is remembered, so the failure is not
    put on screen once per event in the trace -- but stepping into a
    different function must still be attempted, since that one may be fine.
    """
    fake = FakeHexRays(pmap=make_pmap(), widget=None, openable=False)
    controller, _, reader = make_controller(hexrays=fake)

    for _ in range(controller.MAX_OPEN_ATTEMPTS):
        reader.seek(0)
        controller.flush()

    assert len(fake.open_calls) == controller.MAX_OPEN_ATTEMPTS

    fake.entry_ea = 0x600000                      # now a different function
    reader.seek(2)
    controller.flush()

    assert len(fake.open_calls) == controller.MAX_OPEN_ATTEMPTS + 1


def test_addresses_outside_any_function_are_retried_bounded_too():
    """
    The same bounded rule when there is no function entry to key on: the
    failure is remembered under a ``None`` key rather than forgotten (which
    would re-run it on every event) and rather than latching forever.
    """
    fake = FakeHexRays(pmap=make_pmap(), entry_ea=None, widget=None,
                       openable=False)
    controller, _, reader = make_controller(
        hexrays=fake,
        reader=make_reader(offs=[0x100, 0x200, 0x300, 0x400],
                           ips=[0x7000000100, 0x7000000200,
                                0x7000000300, 0x7000000400],
                           trace_length=4),
    )

    for idx in range(controller.MAX_OPEN_ATTEMPTS):
        reader.seek(idx)
        assert controller.flush().reason == "pseudocode-open-failed"

    assert len(fake.open_calls) == controller.MAX_OPEN_ATTEMPTS

    reader.seek(0)
    controller.flush()
    assert len(fake.open_calls) == controller.MAX_OPEN_ATTEMPTS


def test_attach_starts_pseudocode_view_tracking():
    """
    The hooks can only see windows opened after they are installed, so
    tracking starts when the trace is attached rather than the first time a
    view happens to be wanted -- by which point one the user already had
    open is invisible to every sync that follows.
    """
    fake = FakeHexRays(pmap=make_pmap())
    make_controller(hexrays=fake)

    assert fake.track_calls != []


def test_controller_rejects_unmapped_events():
    # no origin resolved and the legacy rebase is a no-op -> no mapping
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[None], ips=[0x778ED5F010], origin=None),
    )

    reader.seek(0)
    event = controller.flush()

    assert event.applied is False
    assert event.reason == "unmapped"
    assert hexrays.jump_calls == []


def test_controller_leaves_the_view_alone_when_nothing_maps():
    # the address resolves, but the decompiler produced no usable map
    fake = FakeHexRays(pmap=None)
    controller, _, reader = make_controller(
        hexrays=fake,
        reader=make_reader(offs=[0x100], ips=[0x7000000100]),
    )

    reader.seek(0)
    event = controller.flush()

    assert event.applied is False
    assert event.reason == "no-ctree-item"
    assert fake.jump_calls == []


def test_controller_leaves_the_view_alone_when_lookup_finds_nothing():
    empty = PseudoMap(entry_ea=0x401000)      # a map with no items
    fake = FakeHexRays(pmap=empty)
    controller, _, reader = make_controller(
        hexrays=fake,
        reader=make_reader(offs=[0x100], ips=[0x7000000100]),
    )

    reader.seek(0)
    event = controller.flush()

    assert event.precision == PRECISION_NONE
    assert event.applied is False
    assert event.reason == "no-ctree-item"


def test_controller_coalesces_a_burst_of_index_changes():
    scheduler = NullScheduler()
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[0x10, 0x20, 0x30]),
        scheduler=scheduler,
    )

    # scrub through three positions without letting the scheduler run
    reader.seek(0)
    reader.seek(1)
    reader.seek(2)
    assert scheduler._pending is not None

    assert scheduler.run_pending() is True
    event = controller.events[-1]

    # only the last position was ever synchronised
    assert event.idx == 2
    assert len(hexrays.jump_calls) == 1
    assert scheduler.run_pending() is False      # nothing left queued


def test_controller_generation_bumps_on_every_index_change():
    controller, _, reader = make_controller()
    before = controller.generation.value

    reader.seek(0)
    after = controller.generation.value
    assert after > before


def test_controller_drops_results_computed_for_an_older_index():
    #
    # Simulate the user seeking again while a decompilation is in flight:
    # the pending update is superseded, and the older one must not apply.
    #
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[0x10, 0x20]),
    )

    reader.seek(0)
    # the flush is now pending; a newer seek supersedes it
    reader.seek(1)

    event = controller.flush()
    assert event.idx == 1
    assert event.ea == 0x401000 + 0x20
    assert len(hexrays.jump_calls) == 1


def test_controller_aborts_prefetch_when_stale():
    #
    # A decompile that takes so long the user has moved on must not have its
    # map published, nor its navigation applied.
    #
    class SlowHexRays(FakeHexRays):
        def __init__(self, *args, **kwargs):
            FakeHexRays.__init__(self, *args, **kwargs)
            self.controller = None

        def decompile(self, ea):
            # the user seeks while we are decompiling
            self.controller.reader.seek(1)
            return FakeHexRays.decompile(self, ea)

    fake = SlowHexRays(pmap=make_pmap())
    controller, _, reader = make_controller(
        hexrays=fake,
        reader=make_reader(offs=[0x10, 0x20]),
    )
    fake.controller = controller

    reader.seek(0)
    event = controller.flush()

    assert event.applied is False
    assert event.stale is True or event.reason.startswith("stale")
    # the superseded navigation never happened
    assert fake.jump_calls == []


def test_controller_rejects_a_map_built_for_an_older_generation():
    class StaleMapHexRays(FakeHexRays):
        def build_pseudo_map(self, cfunc):
            # the user moves while the map is being built
            self.controller.reader.seek(1)
            return FakeHexRays.build_pseudo_map(self, cfunc)

    fake = StaleMapHexRays(pmap=make_pmap())
    controller, _, reader = make_controller(
        hexrays=fake,
        reader=make_reader(offs=[0x10, 0x20]),
    )
    fake.controller = controller

    reader.seek(0)
    event = controller.flush()

    assert event.applied is False
    assert event.reason == "stale-map"


def test_controller_survives_a_decompiler_exception():
    class ExplodingHexRays(FakeHexRays):
        def decompile(self, ea):
            raise RuntimeError("the decompiler had a bad day")

    fake = ExplodingHexRays(pmap=make_pmap())
    controller, _, reader = make_controller(hexrays=fake)

    reader.seek(0)
    event = controller.flush()

    assert event.applied is False
    assert event.reason.startswith("error")
    assert fake.jump_calls == []


def test_controller_detach_clears_caches_and_stops_tracking():
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[0x10, 0x20]),
    )

    reader.seek(0)
    controller.flush()
    assert len(controller.cache.cfuncs) > 0

    controller.detach_reader()

    assert len(controller.cache.cfuncs) == 0
    assert controller.reader is None
    # the old reader no longer drives us
    before = controller.generation.value
    reader.seek(1)
    assert controller.generation.value == before
    assert controller.flush().reason == "no-reader"


def test_controller_attach_replaces_the_previous_reader():
    controller, _, first = make_controller(reader=make_reader(offs=[0x10]))
    second = make_reader(offs=[0x30])

    controller.attach_reader(second)
    assert controller.reader is second

    second.seek(0)
    event = controller.flush()
    assert event.ea == 0x401000 + 0x30


def test_controller_prefetch_warms_maps_without_new_decompilations():
    controller, hexrays, reader = make_controller(
        reader=make_reader(offs=[0x10, 0x20, 0x30, 0x40]),
    )

    # seed the cfunc cache the way a first navigation would
    controller.cache.put_cfunc(hexrays.entry_ea, hexrays.decompile_result)

    decompiles_before = len(hexrays.decompile_calls)
    maps_before = len(hexrays.map_calls)

    reader.seek(0)
    controller.flush()

    # prefetch may build maps, but must never trigger a fresh decompilation
    assert len(hexrays.decompile_calls) == decompiles_before
    assert len(hexrays.map_calls) >= maps_before


def test_controller_events_are_bounded():
    controller, _, reader = make_controller(
        reader=make_reader(offs=list(range(200))),
    )

    for idx in range(200):
        reader.seek(idx)
        controller.flush()

    assert len(controller.events) <= controller._max_events


def test_null_scheduler_runs_only_what_is_queued():
    scheduler = NullScheduler()
    ran = []

    assert scheduler.run_pending() is False
    scheduler.schedule(lambda: ran.append(1), 0)
    scheduler.schedule(lambda: ran.append(2), 0)   # replaces the first
    assert scheduler.run_pending() is True
    assert ran == [2]
    assert scheduler.run_pending() is False

    scheduler.schedule(lambda: ran.append(3), 0)
    scheduler.cancel()
    assert scheduler.run_pending() is False
    assert ran == [2]


def test_sync_event_repr_is_informative():
    event = SyncEvent(12, 0x401000, PRECISION_EXPR, applied=True)
    text = repr(event)
    assert "12" in text
    assert "0x401000" in text
    assert PRECISION_EXPR in text


#-------------------------------------------------------------------------
# describe_target (what the event info panel shows)
#-------------------------------------------------------------------------
#
#    describe_target() must answer from the cache *only*. It is called on
#    every index change to fill in the event info panel, so if it ever
#    triggered a decompilation, scrubbing the timeline would drag the
#    decompiler along with it.
#

def test_describe_target_reports_precision_line_and_function():
    controller, hexrays, _ = make_controller()

    # warm the cache the way a real navigation would
    reader = controller.reader
    reader.seek(0)
    controller.flush()

    verdict = controller.describe_target(0x401100)

    assert verdict is not None
    precision, line, name = verdict
    assert precision == PRECISION_EXPR
    assert line == 4
    assert name == "sub_401000"


def test_describe_target_never_forces_a_decompilation():
    """
    A cold cache must yield None -- not a fresh decompile.

    This is the property that keeps the timeline responsive: the panel
    reports 'not mapped' rather than dragging Hex-Rays into a scrub.
    """
    controller, hexrays, _ = make_controller()

    assert controller.cache.get_map(0x401000) is None
    calls_before = len(hexrays.decompile_calls)

    assert controller.describe_target(0x401100) is None

    assert len(hexrays.decompile_calls) == calls_before
    assert hexrays.map_calls == []


def test_describe_target_is_none_without_a_reader():
    controller, _, _ = make_controller()
    controller.detach_reader()

    assert controller.describe_target(0x401100) is None


def test_describe_target_is_none_for_none_ea():
    controller, _, _ = make_controller()
    assert controller.describe_target(None) is None


def test_describe_target_reports_nearest_when_the_address_is_absent():
    """
    A mapped function with no item at this address falls back to the nearest
    one -- *reported as approximate* rather than passed off as exact.
    """
    controller, hexrays, reader = make_controller()

    reader.seek(0)
    controller.flush()

    # inside the function, but not an address anything maps to exactly
    verdict = controller.describe_target(0x401900)

    assert verdict is not None
    precision, line, name = verdict
    assert precision == PRECISION_NEAREST
    assert name == "sub_401000"


def test_describe_target_reports_none_when_nothing_is_close_enough():
    """
    Far outside the harvested range the answer is PRECISION_NONE, and the
    panel shows 'not mapped' rather than a stale/incorrect expression.
    """
    controller, hexrays, reader = make_controller()

    reader.seek(0)
    controller.flush()

    # well beyond NEAREST_MAX_DISTANCE of any harvested item
    verdict = controller.describe_target(0x411100)

    assert verdict is not None
    precision, line, name = verdict
    assert precision == PRECISION_NONE
    assert line is None


def test_describe_target_survives_a_broken_hexrays():
    class BrokenHexRays(FakeHexRays):
        def function_entry_ea(self, ea):
            raise RuntimeError("hex-rays exploded")

    controller, _, _ = make_controller(hexrays=BrokenHexRays(pmap=make_pmap()))

    assert controller.describe_target(0x401100) is None


#-------------------------------------------------------------------------
# Navigation: the jump is the part that has to be believed
#-------------------------------------------------------------------------

def test_sync_reports_applied_false_when_the_widget_refuses_the_jump():
    #
    # The exact shape of the failure that reached the user as "pseudocode
    # sync does nothing": every stage resolves -- reason is empty, precision
    # is 'expr' -- and only the jump returns False. Before 'applied' surfaced
    # that, a refused jump was indistinguishable from a working one in the
    # log, and the one place that said why was a debug line nobody enables.
    #
    hexrays = FakeHexRays(pmap=make_pmap())
    hexrays.jump_refused = True
    controller, _, reader = make_controller(hexrays=hexrays)

    reader.seek(0)
    controller.flush()

    assert len(hexrays.jump_calls) == 1
    event = controller.events[-1]
    assert event.applied is False
    assert event.reason == ""
    assert event.precision == PRECISION_EXPR


def test_a_raising_jump_is_contained_and_reported():
    # a build whose navigation API differs raises rather than returning
    # False; that must not escape into the trace reader
    hexrays = FakeHexRays(pmap=make_pmap())
    hexrays.jump_raises = RuntimeError("no such overload")
    controller, _, reader = make_controller(hexrays=hexrays)

    reader.seek(0)
    controller.flush()

    assert controller.events[-1].applied is False


def test_navigation_passes_the_address_along_for_the_coarse_fallback():
    #
    # The address lets IDA work the line out itself when the line number is
    # refused -- coarser than the expression, but the view being at the
    # right statement beats it not moving at all.
    #
    hexrays = FakeHexRays(pmap=make_pmap())
    controller, _, reader = make_controller(hexrays=hexrays)

    reader.seek(0)
    controller.flush()

    vdui, line, x, length, ea = hexrays.jump_calls[0]
    assert line == 4
    assert x == 6
    assert ea == 0x401100


def test_a_successful_jump_is_reported_as_applied():
    hexrays = FakeHexRays(pmap=make_pmap())
    controller, _, reader = make_controller(hexrays=hexrays)

    reader.seek(0)
    controller.flush()

    assert controller.events[-1].applied is True


#-------------------------------------------------------------------------
# View registry: one window must not be recorded once per retarget
#-------------------------------------------------------------------------

@pytest.fixture
def registry():
    """tenet.sync.hexrays_api with a clean, and then empty, view registry."""
    from tenet.sync import hexrays_api

    del hexrays_api._open_vduis[:]
    yield hexrays_api
    del hexrays_api._open_vduis[:]


class FakeWidget(object):
    """A stand-in for the TWidget of one pseudocode view."""


def make_vdui(widget=None, entry_ea=0x401000, valid=True):
    """
    A vdui-like object.

    Crucially, two of these built from the same ``widget`` are *distinct
    objects* -- which is what IDA does, handing a fresh wrapper back for the
    same underlying view every time ``open_pseudocode()`` is called.
    """
    widget = widget if widget is not None else FakeWidget()

    class Cfunc(object):
        pass

    class Vdui(object):
        pass

    vdui = Vdui()
    vdui.ct = widget
    vdui.cfunc = Cfunc()
    vdui.cfunc.entry_ea = entry_ea
    vdui.valid = lambda: valid
    return vdui


def test_same_view_sees_through_distinct_wrappers_of_one_window(registry):
    window = FakeWidget()
    first = make_vdui(widget=window)
    second = make_vdui(widget=window)

    assert first is not second
    assert registry._same_view(first, second) is True


def test_same_view_does_not_merge_two_windows_showing_one_function(registry):
    first = make_vdui(widget=FakeWidget())
    second = make_vdui(widget=FakeWidget())

    assert registry._same_view(first, second) is False


def test_one_window_is_not_recorded_once_per_retarget(registry):
    #
    # The log listed a single window eleven times over, one entry per
    # retarget: open_pseudocode() returns a fresh wrapper each call, so
    # comparing with `is` never recognised it as already known.
    #
    window = FakeWidget()

    for _ in range(9):
        registry._remember_vdui(make_vdui(widget=window))

    assert len(registry._open_vduis) == 1


def test_forget_clears_every_duplicate_entry(registry):
    window = FakeWidget()
    for _ in range(4):
        registry._remember_vdui(make_vdui(widget=window))

    registry._forget_vdui(make_vdui(widget=window))

    assert registry._open_vduis == []


def test_forget_leaves_other_windows_alone(registry):
    window = FakeWidget()
    other = FakeWidget()
    registry._remember_vdui(make_vdui(widget=window))
    registry._remember_vdui(make_vdui(widget=other))

    registry._forget_vdui(make_vdui(widget=window))

    assert len(registry._open_vduis) == 1
    assert registry._same_view(registry._open_vduis[0], make_vdui(widget=other))


def test_tracked_views_never_grow_without_bound(registry):
    # even on a build whose wrappers cannot be compared at all, a long
    # session must not accumulate views forever
    for _ in range(registry.MAX_TRACKED_VIEWS + 25):
        registry._remember_vdui(make_vdui(widget=FakeWidget()))

    assert len(registry._open_vduis) == registry.MAX_TRACKED_VIEWS


def test_an_invalid_vdui_is_never_tracked(registry):
    registry._remember_vdui(make_vdui(valid=False))

    assert registry._open_vduis == []


#-------------------------------------------------------------------------
# Place discovery: the concrete class differs per IDA build
#-------------------------------------------------------------------------

def _place_class(name):
    """A constructible place_t subclass, named for assertions."""
    class _Place(object):
        def __init__(self, line=0):
            self.line = line

    _Place.__name__ = name
    return _Place


#: stands in for simpleline_place_t on IDA 9.4: the name exists, the class
#: is abstract, and it cannot be constructed at all
class AbstractPlace(object):
    def __init__(self, *args):
        raise AttributeError("No constructor defined - class is abstract")


def make_kernwin(accepted=(), exploding=(),
                 abstract=("simpleline_place_t",)):
    """
    A stand-in for ``ida_kernwin``.

    ``accepted`` names the place classes the viewer will take, ``exploding``
    the ones whose ``jumpto`` raises the way a differing API does, and
    ``abstract`` the ones that exist but cannot be constructed.
    """

    class Kernwin(object):
        pass

    kernwin = Kernwin()

    def make(name):
        return AbstractPlace if name in abstract else _place_class(name)

    kernwin.simpleline_place_t = make("simpleline_place_t")
    kernwin.good_line_place_t = make("good_line_place_t")
    kernwin.other_line_place_t = make("other_line_place_t")
    kernwin.boom_place_t = make("boom_place_t")

    # must never be scanned: neither is a place class, whatever they end with
    kernwin.replace_place = lambda *args: None
    kernwin.not_a_place_t = "an int that merely ends with place_t"

    def jumpto(handle, place, x=0, y=0):
        name = type(place).__name__
        if name in exploding:
            raise TypeError("Wrong number or type of arguments")
        return name in accepted

    kernwin.jumpto = jumpto
    kernwin.activate_widget = lambda handle, make_current: True
    return kernwin


@pytest.fixture
def hexrays_mod():
    """tenet.sync.hexrays_api with clean one-shot navigation state."""
    from tenet.sync import hexrays_api

    hexrays_api._accepted_place_class[0] = None
    hexrays_api._surface_reported[0] = False
    hexrays_api._place_name_modules.clear()
    hexrays_api._constructible[0] = None
    yield hexrays_api
    hexrays_api._accepted_place_class[0] = None
    hexrays_api._surface_reported[0] = False
    hexrays_api._place_name_modules.clear()
    hexrays_api._constructible[0] = None


def test_the_abstract_place_class_is_skipped(hexrays_mod):
    #
    # IDA 9.4 reports "No constructor defined - class is abstract" for
    # simpleline_place_t, the one class that looks obviously right. Offering
    # every constructible class instead of naming that one is the whole
    # point of the discovery.
    #
    kernwin = make_kernwin()

    places = dict(hexrays_mod._line_places(7, kernwin, []))

    assert "simpleline_place_t" not in places
    assert places["good_line_place_t"].line == 7
    assert places["other_line_place_t"].line == 7


def test_only_place_named_classes_are_considered(hexrays_mod):
    kernwin = make_kernwin()

    names = [name for name, _ in hexrays_mod._line_places(7, kernwin, [])]

    # ends with 'place' but not 'place_t', and is callable
    assert "replace_place" not in names
    # ends with 'place_t' but is not a class at all
    assert "not_a_place_t" not in names
    assert set(names) == {"good_line_place_t", "other_line_place_t",
                          "boom_place_t"}


def test_the_accepted_place_class_is_discovered_once(hexrays_mod, monkeypatch):
    #
    # Discovery means offering every class to the viewer, which is fine once
    # per session; doing it again for every trace event would not be.
    #
    import sys

    kernwin = make_kernwin(accepted=("good_line_place_t",))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 7, x=3) is True
    assert hexrays_mod._accepted_place_class[0] == "good_line_place_t"

    names = [n for n, _ in hexrays_mod._line_places(9, kernwin, [])]
    assert names == ["good_line_place_t"]


def test_a_build_with_no_constructible_place_still_reports(hexrays_mod,
                                                            monkeypatch):
    import sys

    kernwin = make_kernwin(abstract=("simpleline_place_t",
                                     "good_line_place_t",
                                     "other_line_place_t",
                                     "boom_place_t"))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 7) is False


def test_a_refusal_is_recorded_differently_from_an_exception(hexrays_mod):
    #
    # They are different diagnoses: a refusal means this place class is not
    # the one the view takes, an exception means the API itself differs.
    #
    kernwin = make_kernwin()
    handle = object()

    refused = []
    result = hexrays_mod._try_jump(
        kernwin, [("good_line_place_t", _place_class("good_line_place_t")(),
                   "ct", handle)], 0, refused)
    assert result is None
    assert any("refused" in message for message in refused)

    exploding = make_kernwin(exploding=("boom_place_t",))
    raised = []
    result = hexrays_mod._try_jump(
        exploding, [("boom_place_t", _place_class("boom_place_t")(),
                     "ct", handle)], 0, raised)
    assert result is None
    assert any("TypeError" in message for message in raised)
    assert not any("refused" in message for message in raised)


def test_repeated_identical_attempts_are_recorded_once(hexrays_mod):
    attempts = []
    for _ in range(5):
        hexrays_mod._note(attempts, "jumpto(ct, good_line_place_t) refused")

    assert attempts == ["jumpto(ct, good_line_place_t) refused"]


def test_a_failed_place_reports_why(hexrays_mod):
    #
    # "nothing could be constructed" is useless on its own -- the entire
    # point of the last three rounds of IDA output was that the reason is
    # different on every build, and the reason is the answer.
    #
    kernwin = make_kernwin(abstract=("simpleline_place_t",))
    attempts = []

    places = hexrays_mod._line_places(7, kernwin, attempts)

    assert sorted(name for name, _ in places) == ["boom_place_t",
                                                  "good_line_place_t",
                                                  "other_line_place_t"]
    assert any("simpleline_place_t" in message and "abstract" in message
               for message in attempts)


def test_a_module_without_place_names_says_so(hexrays_mod, monkeypatch):
    import sys

    # keep the scan honest: only the module under test is consulted
    monkeypatch.setitem(sys.modules, "ida_hexrays", None)

    class Empty(object):
        pass

    attempts = []

    assert hexrays_mod._line_places(7, Empty(), attempts) == []
    assert attempts == ["no *place_t names found in ida_kernwin or "
                        "ida_hexrays"]


def test_a_non_callable_place_name_is_reported(hexrays_mod):
    kernwin = make_kernwin()
    kernwin.augmented_place_t = 42

    attempts = []
    hexrays_mod._line_places(7, kernwin, attempts)

    assert "augmented_place_t is not callable" in attempts


def test_the_navigation_surface_is_dumped_once(hexrays_mod, monkeypatch):
    #
    # Guessing IDA's navigation API has been wrong three times, so the
    # plugin now prints what the build actually exposes -- once per trace,
    # not once per event, or the log drowns the signal it exists to carry.
    #
    import sys

    reported = []
    monkeypatch.setattr(hexrays_mod, "pdbg",
                        lambda fmt, *args: reported.append(fmt % args))

    kernwin = make_kernwin(abstract=("simpleline_place_t",
                                     "good_line_place_t",
                                     "other_line_place_t",
                                     "boom_place_t"))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 7) is False

    surface = [line for line in reported if "nav surface" in line]
    assert surface, "the failing jump must dump the navigation surface"
    assert any("simpleline_place_t" in line for line in surface)

    hexrays_mod.jump_to_item(make_vdui(), 8)
    assert len([l for l in reported if "nav surface" in l]) == len(surface)


def test_a_successful_navigation_never_dumps_the_surface(hexrays_mod,
                                                          monkeypatch):
    import sys

    reported = []
    monkeypatch.setattr(hexrays_mod, "pdbg",
                        lambda fmt, *args: reported.append(fmt % args))
    monkeypatch.setitem(sys.modules, "ida_kernwin",
                        make_kernwin(accepted=("good_line_place_t",)))

    assert hexrays_mod.jump_to_item(make_vdui(), 7) is True
    assert not any("nav surface" in line for line in reported)


def test_the_decompiler_module_is_scanned_too(hexrays_mod, monkeypatch):
    #
    # The generic place classes are the decompiler's to accept or refuse; a
    # place Hex-Rays defines for its own viewer is the only kind it is
    # certain to take, so it is worth scanning for.
    #
    import sys
    import types

    fake = types.ModuleType("ida_hexrays")
    fake.cfunc_line_place_t = _place_class("cfunc_line_place_t")
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake)

    kernwin = make_kernwin(abstract=("simpleline_place_t",))
    places = dict(hexrays_mod._line_places(7, kernwin, []))

    assert "cfunc_line_place_t" in places
    assert "good_line_place_t" in places


def test_a_cached_class_is_resolved_back_to_its_own_module(hexrays_mod,
                                                            monkeypatch):
    #
    # The cache remembers the class *name*, but a name the decompiler owns
    # does not resolve on ida_kernwin. Looked up in the wrong module, the
    # second trace event would report "not callable" for a class that had
    # just worked -- invisible to any test that only jumps once.
    #
    import sys
    import types

    fake = types.ModuleType("ida_hexrays")
    fake.cfunc_line_place_t = _place_class("cfunc_line_place_t")
    monkeypatch.setitem(sys.modules, "ida_hexrays", fake)

    kernwin = make_kernwin(abstract=("simpleline_place_t",))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    hexrays_mod._accepted_place_class[0] = "cfunc_line_place_t"
    hexrays_mod._place_name_modules["cfunc_line_place_t"] = fake

    places = dict(hexrays_mod._line_places(4, kernwin, []))

    assert "cfunc_line_place_t" in places
    assert "simpleline_place_t" not in places


def test_an_unresolvable_cache_falls_back_to_discovery(hexrays_mod,
                                                        monkeypatch):
    #
    # A stale cache must degrade to offering everything, not to "nothing to
    # try" -- that message means "this build has no place class at all",
    # which is an entirely different bug and would send the diagnosis the
    # wrong way.
    #
    import sys

    monkeypatch.setitem(sys.modules, "ida_kernwin", make_kernwin())
    hexrays_mod._accepted_place_class[0] = "vanished_line_place_t"
    hexrays_mod._place_name_modules.clear()

    attempts = []
    places = dict(hexrays_mod._line_places(3, make_kernwin(), attempts))

    assert "good_line_place_t" in places
    assert not any("no *place_t names" in m for m in attempts)


def test_the_surface_dump_never_raises(hexrays_mod, monkeypatch):
    # it runs inside a UI callback: breaking the navigation it exists to
    # explain would be worse than printing nothing
    reported = []
    monkeypatch.setattr(hexrays_mod, "pdbg",
                        lambda fmt, *args: reported.append(fmt % args))

    class BadVdui(object):
        def __dir__(self):
            raise RuntimeError("no introspection on this build")

    hexrays_mod._surface_reported[0] = False
    hexrays_mod._report_navigation_surface(BadVdui(), object(), [])

    assert any("could not be collected" in line for line in reported)
    # and it is still consumed, so a healthy build after it would not repeat
    assert hexrays_mod._surface_reported[0] is True


#--------------------------------------------------------------------------
# the clone route -- IDA 9.4's real shape
#--------------------------------------------------------------------------

def make_clone_kernwin(refuse=False, getter=None, downcast=None):
    """
    An ``ida_kernwin`` matching what IDA 9.4 actually exposes.

    Every ``*place_t`` class is abstract, the place is reachable only from
    the view itself, and the downcast is a module-level function rather than
    a constructor. ``getter``/``downcast`` replace the two entry points so a
    missing or failing one can be simulated.
    """

    class LinePlace(object):
        """simpleline_place_t: abstract to construct, mutable once cloned."""

        def __init__(self, n=0):
            self.n = n

        def clone(self):
            return LinePlace(self.n)

    class Kernwin(object):
        pass

    kernwin = Kernwin()

    # the four classes IDA 9.4 exposes -- none of them constructible
    for name in ("idaplace_t", "place_t", "simpleline_place_t", "tiplace_t"):
        setattr(kernwin, name, AbstractPlace)

    viewer_place = LinePlace(3)   # the view is showing line 3

    def default_getter(handle, mouse):
        return (viewer_place, 0, 0)

    def default_downcast(place):
        return place if isinstance(place, LinePlace) else None

    kernwin.get_custom_viewer_place = (getter if getter is not None
                                       else default_getter)
    kernwin.place_t_as_simpleline_place_t = (downcast if downcast is not None
                                             else default_downcast)

    jumps = []

    def jumpto(handle, place, x=0, y=0):
        jumps.append((handle, getattr(place, "n", None), x, y))
        return not refuse

    kernwin.jumpto = jumpto
    kernwin.jumps = jumps
    kernwin.viewer_place = viewer_place
    kernwin.activate_widget = lambda handle, make_current: True
    return kernwin


def test_the_cursor_moves_by_cloning_the_views_own_place(hexrays_mod,
                                                          monkeypatch):
    #
    # The whole point. Nothing on this build can be constructed, so the only
    # way to name a line is to take the place the view is already showing,
    # clone it, and retarget the clone.
    #
    import sys

    kernwin = make_clone_kernwin()
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 15, x=57) is True

    handle, line, x, y = kernwin.jumps[0]
    assert line == 15
    # the clone route must not poison the construction cache: its label is
    # not a place class this build could ever construct again
    assert hexrays_mod._accepted_place_class[0] is None


def test_the_clone_is_never_the_viewers_own_place(hexrays_mod, monkeypatch):
    #
    # Mutating the view's place in place would corrupt every later jump -- it
    # is shared state, and that is exactly why the route clones first.
    #
    import sys

    kernwin = make_clone_kernwin()
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 22) is True
    assert kernwin.viewer_place.n == 3, "the view's place was mutated"
    assert kernwin.jumps[0][1] == 22


def test_a_pure_clone_success_still_reports_itself(hexrays_mod, monkeypatch):
    #
    # With no refusals the attempt list is empty, and an empty list used to
    # mean "say nothing" -- a sync that silently stops logging looks exactly
    # like one that silently stopped working.
    #
    import sys

    reported = []
    monkeypatch.setattr(hexrays_mod, "pdbg",
                        lambda fmt, *args: reported.append(fmt % args))
    kernwin = make_clone_kernwin()
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 11) is True
    assert any("via jumpto" in line for line in reported)


def test_a_missing_clone_api_falls_through_to_construction(hexrays_mod,
                                                            monkeypatch):
    #
    # Cloning needs the view to already have a place. A cold view has none,
    # and on a build that does allow construction the fallback must still
    # run rather than give up.
    #
    import sys

    kernwin = make_clone_kernwin(getter=lambda handle, mouse: None)
    kernwin.good_line_place_t = _place_class("good_line_place_t")
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 9) is True
    assert kernwin.jumps, "the construction fallback never ran"


def test_a_place_that_is_not_a_line_place_is_reported(hexrays_mod,
                                                        monkeypatch):
    import sys

    kernwin = make_clone_kernwin(downcast=lambda place: None)
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 9) is False
    # and the reason is recorded, not swallowed
    attempts = []
    hexrays_mod._clone_targets(9, kernwin, [("ct", object())], attempts)
    assert any("not a simpleline_place_t" in m for m in attempts)


def test_construction_refusals_are_not_repeated_forever(hexrays_mod,
                                                         monkeypatch):
    #
    # The sync loop runs on every trace event. Where every class is abstract
    # discovery produces the identical seven refusals every time -- answer it
    # once instead of printing it until the trace ends.
    #
    import sys

    kernwin = make_kernwin(abstract=("simpleline_place_t",
                                     "good_line_place_t",
                                     "other_line_place_t",
                                     "boom_place_t"))
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    assert hexrays_mod.jump_to_item(make_vdui(), 7) is False
    assert hexrays_mod._constructible[0] is False

    attempts = []
    hexrays_mod._jump_with_place(kernwin, 8, [("ct", object())], 0, attempts)

    assert attempts == ["ida_kernwin.get_custom_viewer_place is absent",
                        "no *place_t class can be constructed on this build"]


def test_downcast_helpers_are_never_offered_as_places(hexrays_mod,
                                                        monkeypatch):
    #
    # IDA 9.4 exposes place_t_as_simpleline_place_t. It ends with place_t and
    # is callable, so it scans exactly like a place class -- but it builds
    # nothing, and returns None rather than raising when it cannot convert.
    # Offering that None to jumpto would report success while moving nothing.
    #
    import sys

    kernwin = make_kernwin(abstract=("simpleline_place_t",))
    kernwin.place_t_as_simpleline_place_t = lambda place: None
    monkeypatch.setitem(sys.modules, "ida_kernwin", kernwin)

    attempts = []
    places = dict(hexrays_mod._line_places(5, kernwin, attempts))

    assert "place_t_as_simpleline_place_t" not in places
    assert any("downcast helper" in message for message in attempts)
    assert all(place is not None for place in places.values())
