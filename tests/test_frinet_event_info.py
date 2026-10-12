"""
Tests for the FRINET event info model and the Qt binding shim.

Neither requires IDA, Qt, or PySide6:

* ``EventInfoModel`` is deliberately pure (it renders strings from a trace
  reader + a fake disassembler context), so the *interesting* behaviour --
  what is shown for an in-module event, an external event, a legacy trace,
  a missing register -- is tested here rather than in the GUI.
* the Qt shim's binding resolution is pure logic over ``sys.modules``, so
  it can be tested by planting fake modules (there is no PySide6 in this
  environment, and IDA is not available at all).
"""

import contextlib
import importlib
import os
import re
import sys
import types as pytypes

import pytest

from tenet.event_info import EventInfoModel
from tenet.util.qt import shim

_HERE = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.join(os.path.dirname(_HERE), "tenet", "plugins", "tenet")

#: the view that used to hardcode PyQt5 star imports, and is the reason the
#: Qt classes are resolved through the shim
TREE_VIEW_SOURCE = os.path.join(_PLUGIN_ROOT, "ui", "tree_view.py")


#--------------------------------------------------------------------------
# fakes
#--------------------------------------------------------------------------

class FakeArch(object):
    POINTER_SIZE = 8
    IP = "pc"


class FakeAnalysis(object):
    """Resolves offsets through a fixed origin, like the real one."""

    def __init__(self, origin=0x400000):
        self.origin = origin

    def translate_offset(self, off):
        if off is None:
            return None
        return self.origin + off

    def rebase_pointer(self, address):
        return address


class FakeDctx(object):
    """is_mapped() over an explicit set of known addresses."""

    def __init__(self, mapped=()):
        self._mapped = set(mapped)

    def is_mapped(self, address):
        return address in self._mapped


class FakeDisassembler(object):
    """Stands in for the disassembler[] selector."""

    def __init__(self, dctx):
        self._dctx = dctx

    def __getitem__(self, key):
        return self._dctx


class FakeReader(object):
    """The minimum surface EventInfoModel.update() touches."""

    def __init__(self, ips, offs, reg_deltas=None, read_deltas=None,
                 write_deltas=None, segment_id=0, has_offsets=True,
                 analysis=None):
        self._ips = ips
        self._offs = offs
        self._reg_deltas = reg_deltas or {}
        self._read_deltas = read_deltas or {}
        self._write_deltas = write_deltas or {}
        self._segment_id = segment_id
        self.has_offsets = has_offsets
        self.analysis = analysis or FakeAnalysis()

        self.idx = 0
        self.trace = self

    # --- trace surface -------------------------------------------------

    @property
    def length(self):
        return len(self._ips)

    def get_ip(self, idx):
        return self._ips[idx]

    def get_offset(self, idx):
        if idx >= len(self._offs):
            return None
        return self._offs[idx]

    def get_segment(self, idx):
        return pytypes.SimpleNamespace(id=self._segment_id)

    def get_reg_delta(self, idx):
        return self._reg_deltas.get(idx, {})

    def get_read_delta(self, idx):
        return self._read_deltas.get(idx, {})

    def get_write_delta(self, idx):
        return self._write_deltas.get(idx, {})

    # --- reader surface ------------------------------------------------

    def idx_changed(self, callback):
        pass


class FakePctx(object):
    def __init__(self, arch=None):
        self.arch = arch or FakeArch()


#--------------------------------------------------------------------------
# helpers
#--------------------------------------------------------------------------

def make_model(reader, idx=0, dctx=None, sync=None):
    """Build an EventInfoModel around a fake reader and update it."""
    pctx = FakePctx()

    # the model reaches the disassembler through the module global
    import tenet.event_info as event_info_module
    previous = event_info_module.disassembler
    event_info_module.disassembler = FakeDisassembler(dctx or FakeDctx())

    try:
        model = EventInfoModel(pctx)
        model.update(reader, idx, sync=sync)
        return model
    finally:
        event_info_module.disassembler = previous


#--------------------------------------------------------------------------
# addressing
#--------------------------------------------------------------------------

class TestEventAddressing(object):

    def test_in_module_event_shows_all_three_stages(self):
        """pc / off / static_ea are all distinct and all rendered."""
        reader = FakeReader(
            ips=[0x77968b2290],
            offs=[0x59290],
            analysis=FakeAnalysis(origin=0x400000),
        )
        dctx = FakeDctx(mapped={0x459290})
        model = make_model(reader, dctx=dctx)

        assert model.pc == 0x77968b2290
        assert model.off == 0x59290
        assert model.static_ea == 0x459290

        # the three stages must never be conflated in the rendered output
        assert model.rendered["pc"] == "0x00000077968B2290"
        assert model.rendered["off"] == "0x59290"
        assert model.rendered["static_ea"] == "0x0000000000459290"
        assert model.rendered["mapped"] == "yes"
        assert model.offset_source == "frinet"

    def test_external_event_has_no_offset_and_is_not_translated(self):
        """An event outside the module gets no static address at all."""
        reader = FakeReader(
            ips=[0x778ED5F010],
            offs=[None],
            has_offsets=True,   # .frinet trace, but this event is external
        )
        model = make_model(reader, dctx=FakeDctx(mapped=set()))

        assert model.off is None
        assert model.static_ea is None
        assert model.mapped is None
        assert model.offset_source == "external"

        # say so explicitly rather than printing a translated guess
        assert model.rendered["off"] == "external (outside module)"
        assert model.rendered["static_ea"] == "n/a"
        assert model.rendered["mapped"] == "unknown"

    def test_legacy_trace_reports_missing_offsets_as_legacy(self):
        """A .tenet trace has no offsets anywhere: that is a different story."""
        reader = FakeReader(
            ips=[0x401000],
            offs=[None],
            has_offsets=False,  # legacy .tenet
        )
        model = make_model(reader, dctx=FakeDctx(mapped=set()))

        assert model.offset_source == "legacy"
        assert model.rendered["off"] == "no offsets (legacy trace)"
        assert model.static_ea is None

    def test_static_ea_uses_module_origin_not_imagebase(self):
        """
        The static address is idb_module_start + off, and idb_module_start
        is whatever the analysis resolved -- not an assumed imagebase.
        """
        reader = FakeReader(
            ips=[0x7FF0000010],
            offs=[0x10],
            analysis=FakeAnalysis(origin=0x100000),  # deliberately not 0x400000
        )
        model = make_model(reader, dctx=FakeDctx(mapped={0x100010}))

        assert model.static_ea == 0x100010
        assert model.rendered["static_ea"] == "0x0000000000100010"

    def test_offset_zero_is_a_real_offset_not_absence(self):
        """off=0 is the module origin; it must not be treated as 'no offset'."""
        reader = FakeReader(ips=[0x400000], offs=[0])
        model = make_model(reader, dctx=FakeDctx(mapped={0x400000}))

        assert model.off == 0
        assert model.static_ea == 0x400000
        assert model.offset_source == "frinet"
        assert model.rendered["off"] == "0x0"

    def test_unmapped_static_address_is_reported_as_unmapped(self):
        """A translated address that the IDB does not contain says 'no'."""
        reader = FakeReader(ips=[0x400010], offs=[0x10])
        model = make_model(reader, dctx=FakeDctx(mapped=set()))

        assert model.static_ea == 0x400010
        assert model.mapped is False
        assert model.rendered["mapped"] == "no"


#--------------------------------------------------------------------------
# deltas
#--------------------------------------------------------------------------

class TestEventDeltas(object):

    def test_changed_registers_are_listed(self):
        reader = FakeReader(
            ips=[0x401000],
            offs=[0x10],
            reg_deltas={0: {"x0": 1, "x1": 2}},
        )
        model = make_model(reader)

        assert model.registers_changed == {"x0": 1, "x1": 2}
        assert model.rendered["registers_changed"] == "x0, x1"

    def test_no_changed_registers_renders_none(self):
        reader = FakeReader(ips=[0x401000], offs=[0x10])
        model = make_model(reader)

        assert model.rendered["registers_changed"] == "none"

    def test_missing_reg_delta_does_not_crash(self):
        """A trace segment with no register data must not raise."""
        reader = FakeReader(ips=[0x401000], offs=[0x10])

        def boom(idx):
            raise ValueError("no register data")

        reader.get_reg_delta = boom
        model = make_model(reader)

        assert model.registers_changed == {}
        assert model.rendered["registers_changed"] == "none"

    def test_memory_deltas_are_rendered_as_addresses(self):
        reader = FakeReader(
            ips=[0x401000],
            offs=[0x10],
            read_deltas={0: {0x7000: b"\x01" * 8}},
            write_deltas={0: {0x7100: b"\x02" * 8}},
        )
        model = make_model(reader)

        assert model.rendered["memory_reads"] == "0x0000000000007000"
        assert model.rendered["memory_writes"] == "0x0000000000007100"

    def test_memory_delta_is_truncated_for_huge_events(self):
        """A memcpy touching thousands of bytes must not flood the panel."""
        many = {0x1000 + i: b"\x00" for i in range(64)}
        reader = FakeReader(
            ips=[0x401000], offs=[0x10], read_deltas={0: many},
        )
        model = make_model(reader)

        listed = model.rendered["memory_reads"].split(", ")
        assert len(listed) == 16

    def test_no_memory_accesses_renders_none(self):
        reader = FakeReader(ips=[0x401000], offs=[0x10])
        model = make_model(reader)

        assert model.rendered["memory_reads"] == "none"
        assert model.rendered["memory_writes"] == "none"


#--------------------------------------------------------------------------
# sync verdict + lifecycle
#--------------------------------------------------------------------------

class TestEventSyncAndLifecycle(object):

    def test_sync_verdict_is_rendered_when_available(self):
        reader = FakeReader(ips=[0x401000], offs=[0x10])

        class FakeSync(object):
            def describe_target(self, ea):
                return ("expr", 4, "sub_401000")

        model = make_model(reader, sync=FakeSync())

        assert model.sync_precision == "expr"
        assert model.sync_line == 4
        assert model.sync_function == "sub_401000"
        # lines are 0-based internally, 1-based for humans
        assert model.rendered["sync"] == "expr (line 5) in sub_401000"

    def test_sync_not_consulted_without_a_static_address(self):
        """An external event has nothing to look up in the pseudocode."""
        reader = FakeReader(ips=[0x778ED5F010], offs=[None])

        class FakeSync(object):
            def describe_target(self, ea):
                raise AssertionError("must not be called without an address")

        model = make_model(reader, sync=FakeSync())

        assert model.sync_precision is None
        assert model.rendered["sync"] == "not mapped"

    def test_sync_failure_is_swallowed(self):
        """A decompiler surprise must not take the panel down."""
        reader = FakeReader(ips=[0x401000], offs=[0x10])

        class FakeSync(object):
            def describe_target(self, ea):
                raise RuntimeError("hex-rays exploded")

        model = make_model(reader, sync=FakeSync())

        assert model.sync_precision is None
        assert model.rendered["sync"] == "not mapped"

    def test_reset_clears_everything(self):
        reader = FakeReader(ips=[0x401000], offs=[0x10])
        model = make_model(reader)
        assert model.rendered

        model.reset()

        assert model.idx == -1
        assert model.pc is None
        assert model.off is None
        assert model.static_ea is None
        assert model.registers_changed == {}
        assert model.rendered == {}

    def test_update_with_no_reader_resets(self):
        model = EventInfoModel(FakePctx())
        model.update(None, 0)
        assert model.idx == -1

    def test_thread_id_is_reported(self):
        reader = FakeReader(ips=[0x401000], offs=[0x10], segment_id=7)
        model = make_model(reader)
        assert model.tid == 7
        assert model.rendered["tid"] == "7"

    def test_length_is_reported(self):
        reader = FakeReader(ips=[0x401000, 0x401004], offs=[0x10, 0x14])
        model = make_model(reader)
        assert model.length == 2
        assert "2" in model.rendered["idx"]


#--------------------------------------------------------------------------
# Qt binding resolution
#--------------------------------------------------------------------------

class TestRunExec(object):
    """
    ``exec_()`` was renamed ``exec()`` in Qt6.

    PySide6 still carries the old spelling as a deprecated alias, but PyQt6
    dropped it, so the modal-dialog and popup-menu calls in the pre-existing
    views go through one helper rather than betting on IDA's binding.
    """

    class OnlyExec(object):
        def __init__(self):
            self.called = 0
            self.args = None

        def exec(self, *args):
            self.called += 1
            self.args = args
            return "result"

    class OnlyExecUnderscore(object):
        def __init__(self):
            self.called = 0

        def exec_(self, *args):
            self.called += 1
            return "legacy"

    class Both(object):
        def __init__(self):
            self.exec_called = 0
            self.legacy_called = 0

        def exec(self):
            self.exec_called += 1
            return "modern"

        def exec_(self):
            self.legacy_called += 1
            return "legacy"

    class Neither(object):
        pass

    def test_prefers_the_qt6_spelling(self):
        dialog = self.Both()
        assert shim.run_exec(dialog) == "modern"
        assert (dialog.exec_called, dialog.legacy_called) == (1, 0)

    def test_falls_back_to_the_legacy_spelling(self):
        dialog = self.OnlyExecUnderscore()
        assert shim.run_exec(dialog) == "legacy"
        assert dialog.called == 1

    def test_forwards_position_arguments(self):
        """Popup menus need their global position."""
        dialog = self.OnlyExec()
        shim.run_exec(dialog, 10, 20)
        assert (dialog.called, dialog.args) == (1, (10, 20))

    def test_raises_on_an_object_that_cannot_run(self):
        with pytest.raises(AttributeError):
            shim.run_exec(self.Neither())


@contextlib.contextmanager
def _without_bindings(bindings):
    """
    Forget every binding *and* refuse to import it again.

    Popping ``sys.modules`` on its own does not simulate "no Qt installed":
    the shim does a real ``import PySide6`` while reloading, so with PySide6
    present the module simply comes back and the test asserts on a state it
    never created. That passes with no binding installed and fails with one,
    which is the worst shape a test can have -- it looks green and has never
    exercised its own subject.
    """

    class _Blocked(object):
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in bindings:
                # ImportError is exactly what the shim treats as "not
                # installed", so the block is indistinguishable from absence
                raise ImportError("blocked for this test: %s" % fullname)
            return None

    for name in bindings:
        sys.modules.pop(name, None)

    finder = _Blocked()
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)


class TestQtBindingResolution(object):
    """
    The shim must never pick a binding different from the host's.

    Two Qt bindings cannot be mixed in one process, so if the host (IDA)
    already imported one, that one wins -- even when a 'preferred' binding
    is also installed.
    """

    # the bindings the shim knows about
    BINDINGS = ("PySide6", "PyQt5", "PySide2")

    @pytest.fixture(autouse=True)
    def clean_modules(self):
        """
        Save / restore sys.modules and shim globals around each test.

        The shim reads sys.modules at import time, so each scenario is
        exercised by re-importing it with a planted set of fake modules.
        ``importlib.reload`` mutates the *same* module object, so restoring
        sys.modules alone is not enough -- the shim's own globals are
        snapshotted too, otherwise a fake binding would leak into every
        test that runs afterwards.
        """
        saved = {name: sys.modules.get(name) for name in self.BINDINGS}
        saved_sub = {name: sys.modules.get(name)
                     for name in sys.modules
                     if any(name.startswith(b + ".") for b in self.BINDINGS)}
        saved_shim = sys.modules.get(shim.__name__)
        _GLOBAL_ATTRS = ("QT_AVAILABLE", "QT_BINDING", "USING_PYQT5",
                         "USING_PYSIDE2", "USING_PYSIDE6", "QtCore",
                         "QtGui", "QtWidgets")
        saved_globals = {attr: (hasattr(shim, attr), getattr(shim, attr, None))
                         for attr in _GLOBAL_ATTRS}

        yield

        for name in list(saved) + list(saved_sub):
            module = saved.get(name, saved_sub.get(name))
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

        for attr, (present, value) in saved_globals.items():
            if present:
                setattr(shim, attr, value)
            else:
                shim.__dict__.pop(attr, None)

        if saved_shim is not None:
            sys.modules[shim.__name__] = saved_shim

    @staticmethod
    def _fake_binding(name):
        """Build a minimal fake Qt binding package."""
        package = pytypes.ModuleType(name)
        for sub in ("QtCore", "QtGui", "QtWidgets"):
            module = pytypes.ModuleType("%s.%s" % (name, sub))
            if sub == "QtCore":
                # PySide bindings are aliased onto the PyQt names by the shim
                module.Signal = object
                module.Slot = object
            setattr(package, sub, module)
            sys.modules["%s.%s" % (name, sub)] = module
        sys.modules[name] = package
        return package

    def _reimport_shim(self):
        """Re-import the shim so it re-runs its binding resolution."""
        return importlib.reload(shim)

    def test_no_bindings_means_unavailable(self):
        with _without_bindings(self.BINDINGS):
            module = self._reimport_shim()

        assert module.QT_AVAILABLE is False
        assert module.QT_BINDING is None
        assert module.USING_PYQT5 is False
        assert module.USING_PYSIDE6 is False

    def test_single_binding_is_selected(self):
        for name in self.BINDINGS:
            sys.modules.pop(name, None)
        self._fake_binding("PySide6")

        module = self._reimport_shim()

        assert module.QT_AVAILABLE is True
        assert module.QT_BINDING == "PySide6"
        assert module.USING_PYSIDE6 is True
        assert module.USING_PYQT5 is False

    def test_host_binding_wins_over_preferred(self):
        """
        IDA imports PyQt5; a stray PySide6 must not be chosen instead.

        Mixing the two would crash the moment a panel was docked into IDA's
        main window, so the already-loaded binding always wins.
        """
        self._fake_binding("PyQt5")
        self._fake_binding("PySide6")

        module = self._reimport_shim()

        assert module.QT_BINDING == "PyQt5"
        assert module.USING_PYQT5 is True

    def test_pyside_binding_is_aliased_onto_pyqt_names(self):
        """The rest of the plugin only ever uses the PyQt spellings."""
        for name in self.BINDINGS:
            sys.modules.pop(name, None)
        self._fake_binding("PySide2")

        module = self._reimport_shim()

        # pyqtSignal / pyqtSlot must exist on the aliased QtCore
        assert hasattr(module.QtCore, "pyqtSignal")
        assert hasattr(module.QtCore, "pyqtSlot")

    def test_pyside6_restores_the_widgets_qt6_moved(self):
        """
        ``QtWidgets.QAction`` does not exist in Qt6 -- it moved to QtGui.

        Every context menu in this plugin (including code that predates
        FRINET) spells it ``QtWidgets.QAction``, so under IDA's PySide6 the
        register panel used to die with an AttributeError before a single
        widget was shown. The shim puts the name back so one call site
        works under every binding.
        """
        for name in self.BINDINGS:
            sys.modules.pop(name, None)

        package = self._fake_binding("PySide6")
        # Qt6 layout: the classes live in QtGui only
        package.QtGui.QAction = type("QAction", (), {})
        package.QtGui.QActionGroup = type("QActionGroup", (), {})
        package.QtGui.QShortcut = type("QShortcut", (), {})
        assert not hasattr(package.QtWidgets, "QAction")

        module = self._reimport_shim()

        assert module.QT_BINDING == "PySide6"
        assert module.QtWidgets.QAction is package.QtGui.QAction
        assert module.QtWidgets.QActionGroup is package.QtGui.QActionGroup
        assert module.QtWidgets.QShortcut is package.QtGui.QShortcut

    def test_pyside6_does_not_clobber_an_existing_qaction(self):
        """If QtWidgets really has QAction, it must be left alone."""
        for name in self.BINDINGS:
            sys.modules.pop(name, None)

        package = self._fake_binding("PySide6")
        package.QtGui.QAction = type("GuiAction", (), {})
        own = type("WidgetsAction", (), {})
        package.QtWidgets.QAction = own

        module = self._reimport_shim()

        assert module.QtWidgets.QAction is own

    #
    # where a real Qt6 build puts the classes this plugin asks for. Getting
    # this wrong is not a loud failure at import -- it is an AttributeError
    # deep inside a view's __init__ -- so the layout is spelled out here and
    # checked against the shim's lookup.
    #
    QT6_LAYOUT = {
        "QtGui": ("QAction", "QActionGroup", "QShortcut", "QBrush", "QColor",
                  "QStandardItem", "QStandardItemModel"),
        "QtWidgets": ("QHeaderView", "QMenu", "QTreeView", "QVBoxLayout",
                      "QWidget"),
        "QtCore": ("QObject", "Qt"),
    }

    def _fake_qt6(self):
        """Plant a fake PySide6 whose classes sit in their real Qt6 homes."""
        for name in self.BINDINGS:
            sys.modules.pop(name, None)

        package = self._fake_binding("PySide6")
        for module_name, classes in self.QT6_LAYOUT.items():
            module = getattr(package, module_name)
            for class_name in classes:
                setattr(module, class_name, type(class_name, (), {}))
        return package

    def test_qt_class_finds_qtgui_only_classes(self):
        """
        ``QStandardItem`` / ``QStandardItemModel`` are QtGui classes.

        They are not in QtWidgets on any Qt version, so a lookup that only
        knows about QtWidgets fails -- which is exactly what happened when
        ``tree_view`` was ported off its PyQt5 star imports.
        """
        package = self._fake_qt6()
        module = self._reimport_shim()

        assert module.qt_class("QStandardItem") is package.QtGui.QStandardItem
        assert (module.qt_class("QStandardItemModel")
                is package.QtGui.QStandardItemModel)
        assert module.qt_class("QTreeView") is package.QtWidgets.QTreeView
        assert module.qt_class("Qt") is package.QtCore.Qt

    def test_qt_class_reports_where_it_looked(self):
        self._fake_qt6()
        module = self._reimport_shim()

        with pytest.raises(AttributeError) as excinfo:
            module.qt_class("QDoesNotExist")

        message = str(excinfo.value)
        for module_name in self.QT6_LAYOUT:
            assert module_name in message
        assert "QDoesNotExist" in message

    def test_every_class_tree_view_asks_for_exists_under_qt6(self):
        """
        Regression guard for the Qt6 class lookup.

        ``tree_view`` resolves each Qt class by name; every name it asks
        for must actually exist somewhere in a Qt6 binding, or the plugin
        stops loading entirely (``context`` imports this view at module
        scope, so an AttributeError here takes the whole plugin down).
        """
        package = self._fake_qt6()
        module = self._reimport_shim()

        with open(TREE_VIEW_SOURCE) as handle:
            source = handle.read()

        requested = re.findall(r'qt_class\("(\w+)"\)', source)
        assert requested, "tree_view.py no longer uses qt_class(); update this test"

        for class_name in requested:
            resolved = module.qt_class(class_name)
            assert resolved.__name__ == class_name

    def test_pyqt5_is_not_touched_by_the_qt6_restoration(self):
        """Qt5 keeps QAction in QtWidgets; nothing to restore there."""
        for name in self.BINDINGS:
            sys.modules.pop(name, None)

        package = self._fake_binding("PyQt5")
        package.QtGui.QAction = type("GuiAction", (), {})
        own = type("WidgetsAction", (), {})
        package.QtWidgets.QAction = own

        module = self._reimport_shim()

        assert module.QT_BINDING == "PyQt5"
        assert module.QtWidgets.QAction is own

    def test_wrapinstance_raises_without_a_binding(self):
        with _without_bindings(self.BINDINGS):
            module = self._reimport_shim()

        assert module.QT_AVAILABLE is False
        with pytest.raises(RuntimeError):
            module.wrapinstance(0, object)


def test_the_binding_blocker_blocks_and_then_gets_out_of_the_way():
    # Popping sys.modules alone does not simulate an absent Qt: the shim
    # does a real ``import PySide6`` while reloading, so the module comes
    # straight back. That is what made the "no bindings" tests green in every
    # environment without PySide6 and red in every environment with it.
    before = list(sys.meta_path)

    with _without_bindings(("PySide6",)):
        assert len(sys.meta_path) == len(before) + 1
        with pytest.raises(ImportError):
            __import__("PySide6")
        # unrelated imports are untouched
        __import__("json")

    assert sys.meta_path == before
