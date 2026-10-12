"""
Tests for the IDA Qt bridge helpers in ``integration/api/ida_api.py``.

IDA ships more than one way to turn a ``TWidget*`` into a Qt widget, and
they are not interchangeable -- which is a *runtime* difference, not
something a name check can settle:

* ``TWidgetToQtPythonWidget`` (9.2+) is binding-agnostic: it tries
  shiboken6 + PySide6 and falls back to PyQt5's ``sip``.
* ``TWidgetToPyQtWidget`` / ``FormToPyQtWidget`` are aliases of that on
  9.2+, and the original implementation on <= 9.1.
* ``TWidgetToPySideWidget`` / ``FormToPySideWidget`` (9.2+) are **broken
  when called from a plugin**: they end in
  ``ctx.QtGui.QWidget.FromCapsule(tw)`` where ``ctx`` defaults to
  ``sys.modules['__main__']``. From IDA's console that works; from a plugin
  ``__main__`` is the plugin module, which has no ``QtGui``. Confirmed still
  broken in IDA 9.4 -- see Hex-Rays community thread 560, whose last reply
  (July 2026) recommends ``TWidgetToQtPythonWidget`` as the workaround.

Importing the module normally needs a real IDA, so the ``ida_*`` modules are
planted as stubs here. That exercises the import itself (catching a stray
module-level IDA dependency) as well as the converter selection.
"""

import importlib
import sys
import types

import pytest

from tenet.util.qt import shim as shim_module

#: every module ida_api.py imports from IDA
IDA_MODULES = (
    "ida_ua", "ida_dbg", "ida_idp", "ida_pro", "ida_auto", "ida_nalt",
    "ida_name", "ida_xref", "idautils", "ida_bytes", "ida_idaapi", "ida_ida",
    "ida_diskio", "ida_kernwin", "ida_segment", "idaapi",
)


@pytest.fixture
def ida_api():
    """
    Import ``tenet.integration.api.ida_api`` against stubbed IDA modules.

    A fake PySide6 is planted as well: ``ida_api`` class bodies reference
    ``QtCore``, which only exists once the Qt shim has resolved a binding.
    """
    prefixes = ("tenet.util.qt", "tenet.integration",
                "PySide6", "PyQt5", "PySide2")
    saved = {name: module for name, module in list(sys.modules.items())
             if name in IDA_MODULES or name.startswith(prefixes)}
    saved_shim = dict(getattr(shim_module, "__dict__", {}))

    def _reset():
        for name in list(sys.modules):
            if name in IDA_MODULES or name.startswith(prefixes):
                sys.modules.pop(name, None)
        sys.modules.update(saved)
        shim_module.__dict__.clear()
        shim_module.__dict__.update(saved_shim)

    _reset()

    stubs = {}
    for name in IDA_MODULES:
        #
        # PEP 562 module __getattr__: any constant or helper ida_api touches
        # at import time (ida_kernwin.MFF_FAST, ...) resolves to 0 instead of
        # forcing an exhaustive hand-written stub.
        #
        stub = types.ModuleType(name)
        stub.__getattr__ = lambda attribute: 0
        stubs[name] = stub
        sys.modules[name] = stub

    kernwin = sys.modules["ida_kernwin"]
    kernwin.get_kernel_version = lambda: "9.4"
    # headless, so IDACoreAPI does not try to build a real Qt widget here
    kernwin.cvar = types.SimpleNamespace(batch=True)

    class _PluginForm(object):
        """
        The shape of ``ida_kernwin.PluginForm`` on IDA 9.4.

        Mirrors IDA's own ``pywraps/py_kernwin_plgform.py``: the
        binding-agnostic bridge works, while the PySide-specific one raises
        exactly what it raises in IDA because it reaches for ``__main__``'s
        ``QtGui``, which a plugin never has.
        """

        #: every converter that got called, in order
        calls = []

        @staticmethod
        def TWidgetToQtPythonWidget(widget, ctx=None):
            _PluginForm.calls.append("TWidgetToQtPythonWidget")
            return ("qt-python-twidget", widget)

        @staticmethod
        def TWidgetToPyQtWidget(widget, ctx=None):
            _PluginForm.calls.append("TWidgetToPyQtWidget")
            return ("pyqt-twidget", widget)

        @staticmethod
        def FormToPyQtWidget(form, ctx=None):
            _PluginForm.calls.append("FormToPyQtWidget")
            return ("pyqt-form", form)

        @staticmethod
        def TWidgetToPySideWidget(widget, ctx=None):
            _PluginForm.calls.append("TWidgetToPySideWidget")
            raise AttributeError("module '__main__' has no attribute 'QtGui'")

        @staticmethod
        def FormToPySideWidget(form, ctx=None):
            _PluginForm.calls.append("FormToPySideWidget")
            raise AttributeError("module '__main__' has no attribute 'QtGui'")

    kernwin.PluginForm = _PluginForm

    # a permissive fake Qt binding, so the shim resolves and QtCore exists
    for sub in ("QtCore", "QtGui", "QtWidgets"):
        qualified = "PySide6." + sub
        module = types.ModuleType(qualified)

        def _attribute(attribute, _module=module):
            value = type(attribute, (), {"__init__": lambda self, *a, **k: None})
            setattr(_module, attribute, value)
            return value

        module.__getattr__ = _attribute
        sys.modules[qualified] = module

    package = types.ModuleType("PySide6")
    for sub in ("QtCore", "QtGui", "QtWidgets"):
        setattr(package, sub, sys.modules["PySide6." + sub])
    sys.modules["PySide6"] = package

    # force tenet.util.qt to re-resolve against the planted binding
    for name in list(sys.modules):
        if name.startswith("tenet.util.qt"):
            sys.modules.pop(name, None)

    #
    # ...and force ida_api to be rebuilt against *these* stubs. ``_reset``
    # restores whatever was already imported, so a copy pulled in earlier by
    # another test would be handed straight back by import_module -- still
    # bound to the ida_kernwin it imported against, and the converters
    # planted above would be invisible to it. Nothing about that is visible
    # until some other test file reaches the disassembler API first.
    #
    for name in list(sys.modules):
        if name.startswith("tenet.integration"):
            sys.modules.pop(name, None)

    try:
        yield importlib.import_module("tenet.integration.api.ida_api")
    finally:
        del stubs
        _reset()


class TestThemeHintsAreNeverFatal(object):
    """
    A palette *hint* must never be able to abort a trace load.

    That is what actually stopped the trace dialog: reading the
    disassembly background colour goes through IDA's Qt bridge, and the
    bridge raised. Both hints document themselves as best-effort, so both
    have to degrade instead of propagating.
    """

    @staticmethod
    def _palette():
        from tenet.ui.palette import PluginPalette
        return PluginPalette

    def test_a_failing_hint_degrades_to_the_default(self, ida_api):
        palette = self._palette()

        class StandIn(object):
            _hint_or_none = palette._hint_or_none
            _user_qt_hint = "untouched"
            _user_disassembly_hint = "untouched"

            @staticmethod
            def _qt_theme_hint():
                raise RuntimeError("no Qt bridge in this session")

            @staticmethod
            def _disassembly_theme_hint():
                # the exact failure seen on IDA 9.4
                raise AttributeError("module '__main__' has no attribute 'QtGui'")

            def refresh(self):
                palette._refresh_theme_hints(self)

        stand_in = StandIn()
        stand_in.refresh()

        assert stand_in._user_qt_hint is None
        # the documented fallback, not None and not a crash
        assert stand_in._user_disassembly_hint == "dark"

    def test_a_working_hint_is_kept(self, ida_api):
        palette = self._palette()

        class StandIn(object):
            _hint_or_none = palette._hint_or_none
            _user_qt_hint = None
            _user_disassembly_hint = None

            @staticmethod
            def _qt_theme_hint():
                return "light"

            @staticmethod
            def _disassembly_theme_hint():
                return "dark"

            def refresh(self):
                palette._refresh_theme_hints(self)

        stand_in = StandIn()
        stand_in.refresh()

        assert stand_in._user_qt_hint == "light"
        assert stand_in._user_disassembly_hint == "dark"


class TestPythonWidgetBridge(object):
    """
    The bridge must reach a converter that actually works, in preference
    order, rather than trusting a name.
    """

    @staticmethod
    def _form(ida_api):
        return ida_api.ida_kernwin.PluginForm

    def test_module_imports_without_a_live_ida(self, ida_api):
        """The bridge helpers must not drag in extra IDA dependencies."""
        assert callable(ida_api.twidget_to_qt)
        assert callable(ida_api.form_to_qt)

    def test_prefers_the_binding_agnostic_bridge(self, ida_api):
        """``TWidgetToQtPythonWidget`` is IDA's own recommended spelling."""
        assert ida_api.twidget_to_qt("W") == ("qt-python-twidget", "W")
        assert self._form(ida_api).calls == ["TWidgetToQtPythonWidget"]

    def test_the_broken_pyside_bridge_is_never_reached(self, ida_api):
        """
        The regression this whole ordering exists for.

        On IDA 9.4 ``TWidgetToPySideWidget`` raises
        ``AttributeError: module '__main__' has no attribute 'QtGui'``
        whenever it is called from a plugin -- which is what stopped the
        trace dialog from working. A working converter comes first, so it
        must not be attempted at all.
        """
        assert ida_api.twidget_to_qt("W") == ("qt-python-twidget", "W")
        assert "TWidgetToPySideWidget" not in self._form(ida_api).calls

    def test_falls_through_when_a_converter_raises(self, ida_api):
        """
        Whether a converter works is a runtime fact, not a name check.

        An IDA build that broke the first spelling must not take the plugin
        down; the next candidate is tried instead.
        """
        form = self._form(ida_api)

        def _broken(widget, ctx=None):
            form.calls.append("TWidgetToQtPythonWidget")
            raise RuntimeError("bridge went away")

        setattr(form, "TWidgetToQtPythonWidget", staticmethod(_broken))

        assert ida_api.twidget_to_qt("W") == ("pyqt-twidget", "W")
        assert form.calls == ["TWidgetToQtPythonWidget", "TWidgetToPyQtWidget"]

    def test_pyside_spelling_is_used_when_it_is_the_only_working_one(self, ida_api):
        """
        A future IDA that fixes the PySide bridge, on a build without the
        others: it should still be usable.
        """
        class PySideOnly(object):
            @staticmethod
            def TWidgetToPySideWidget(widget, ctx=None):
                return ("pyside-twidget", widget)

        self._form(ida_api).calls = []
        ida_api.ida_kernwin.PluginForm = PySideOnly
        assert ida_api.twidget_to_qt("W") == ("pyside-twidget", "W")

    def test_legacy_ida_exposes_only_the_pyqt_spelling(self, ida_api):
        """IDA <= 9.1 has no PySide or binding-agnostic bridge at all."""
        class LegacyOnly(object):
            TWidgetToPyQtWidget = staticmethod(lambda widget: ("pyqt-twidget", widget))
            FormToPyQtWidget = staticmethod(lambda form: ("pyqt-form", form))

        ida_api.ida_kernwin.PluginForm = LegacyOnly
        assert ida_api.twidget_to_qt("W") == ("pyqt-twidget", "W")
        assert ida_api.form_to_qt("F") == ("pyqt-form", "F")

    def test_form_bridge_prefers_the_working_one(self, ida_api):
        assert ida_api.form_to_qt("F") == ("pyqt-form", "F")
        assert "FormToPySideWidget" not in self._form(ida_api).calls

    def test_none_is_passed_through_without_calling_any_converter(self, ida_api):
        """
        ``GetWidget()`` can legitimately return None; IDA's own PySide
        converter returns None there rather than raising, and the others
        would raise something unhelpful about a NULL capsule.
        """
        assert ida_api.twidget_to_qt(None) is None
        assert self._form(ida_api).calls == []

    def test_raises_listing_every_attempt(self, ida_api):
        """
        When nothing works, the error has to say what was tried and why --
        this is the only diagnosis available without a debugger.
        """
        error = AttributeError("module '__main__' has no attribute 'QtGui'")

        class AllBroken(object):
            @staticmethod
            def TWidgetToQtPythonWidget(widget, ctx=None):
                raise ImportError("no shiboken6, no sip")

            @staticmethod
            def TWidgetToPyQtWidget(widget, ctx=None):
                raise ImportError("no shiboken6, no sip")

            @staticmethod
            def TWidgetToPySideWidget(widget, ctx=None):
                raise error

        ida_api.ida_kernwin.PluginForm = AllBroken

        with pytest.raises(RuntimeError) as excinfo:
            ida_api.twidget_to_qt("W")

        message = str(excinfo.value)
        for name in ("TWidgetToQtPythonWidget", "TWidgetToPyQtWidget",
                     "TWidgetToPySideWidget"):
            assert name in message
        # and the real cause, not just the names
        assert "module '__main__' has no attribute 'QtGui'" in message
