"""
Qt smoke test: import every plugin view and construct the widgets, under a
**real** PySide6.

This exists because of a specific class of failure that no amount of fake
modules catches: Qt6 moved classes between modules (``QAction``,
``QActionGroup`` and ``QShortcut`` left ``QtWidgets`` for ``QtGui``; the
plugin also used to pick Qt names up through PyQt5 star imports). Those
failures are not import-time errors in a head-less test environment -- they
surface as an ``AttributeError`` deep inside a view's ``__init__``, which in
practice meant the plugin loaded a trace and then died with no UI at all.

The test is **skipped** when PySide6 is not installed, and is honest about
it. To run it:

    pip install PySide6
    python3 -m pytest tests/test_frinet_qt_smoke.py -q

or point it at an existing install without touching the environment:

    FRINET_PYSIDE_PATH=/path/to/pyside python3 -m pytest tests/ -q

Everything runs in a subprocess on Qt's ``offscreen`` platform, so it never
touches the display and never leaks a QApplication or a stubbed ``ida_*``
module into the rest of the suite.
"""

import os
import subprocess
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_PLUGIN_ROOT = os.path.join(_ROOT, "tenet", "plugins")

#: optional extra sys.path entry, for a PySide6 installed elsewhere
_PYSIDE_PATH = os.environ.get("FRINET_PYSIDE_PATH", "")

_SCRIPT = r'''
import os, sys, types, traceback

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, %(plugin_root)r)

#
# stub out IDA: the views reach the disassembler integration layer, which
# cannot import outside IDA. A module-level __getattr__ returning 0 answers
# the constants (ida_kernwin.MFF_FAST, ...) without an exhaustive stub.
#
IDA_MODULES = (
    "ida_ua", "ida_dbg", "ida_idp", "ida_pro", "ida_auto", "ida_nalt",
    "ida_name", "ida_xref", "idautils", "ida_bytes", "ida_idaapi", "ida_ida",
    "ida_diskio", "ida_kernwin", "ida_segment", "idaapi", "idc", "ida_funcs",
    "ida_hexrays", "ida_lines", "ida_loader",
)

class _PluginForm(object):
    @staticmethod
    def TWidgetToPySideWidget(widget): return widget
    @staticmethod
    def TWidgetToPyQtWidget(widget): return widget
    @staticmethod
    def FormToPySideWidget(form): return form
    @staticmethod
    def FormToPyQtWidget(form): return form

for _name in IDA_MODULES:
    _module = types.ModuleType(_name)
    _module.__getattr__ = lambda attribute: 0
    sys.modules[_name] = _module

_kernwin = sys.modules["ida_kernwin"]
_kernwin.get_kernel_version = lambda: "9.4"
_kernwin.cvar = types.SimpleNamespace(batch=True)
_kernwin.PluginForm = _PluginForm

from PySide6 import QtGui, QtWidgets
APP = QtWidgets.QApplication([])      # QWidget and font metrics both need one

#--------------------------------------------------------------------------
# import every view -- catches a module-level Qt mistake immediately
#--------------------------------------------------------------------------
VIEWS = ("palette", "breakpoint_view", "event_info_view", "hex_view",
         "reg_view", "trace_view", "tree_view")

for _view in VIEWS:
    __import__("tenet.ui." + _view)

from tenet.util.qt import shim
assert shim.QT_BINDING == "PySide6", shim.QT_BINDING
assert QtWidgets.QAction is QtGui.QAction, "Qt6 QAction move was not aliased"

#--------------------------------------------------------------------------
# fakes: just enough surface for the views to lay themselves out
#--------------------------------------------------------------------------
Q = QtGui.QColor

class Palette(object):
    def __getattr__(self, name):
        return Q(255, 255, 255)

class Arch(object):
    POINTER_SIZE = 8
    IP = "pc"
    REGISTERS = ["x%%d" %% i for i in range(31)] + ["fp", "sp", "lr"]

class _BreakpointModel(object):
    def __init__(self):
        self.breakpoints = {}
        self.bp_exec = {}
        self.bp_mem = {}
        self.bp_reg = {}
    def breakpoints_changed(self, callback): pass

class _Breakpoints(object):
    def __init__(self): self.model = _BreakpointModel()

class Pctx(object):
    palette = Palette()
    arch = Arch()
    def __init__(self): self.breakpoints = _Breakpoints()

class Model(object):
    def __init__(self):
        self.arch = Arch()
        self.idx = 0
        self.registers = {}
        self.display_decimal = False
        self.delta_trace = {}
        self.delta_navigation = {}
        self.execution_breakpoints = set()
        self.focused_reg_name = None
        self.focused_reg_value = None
        self.rendered = {}
        self.static_ea = None
        self._callbacks = {}
    def registers_changed(self, callback): self._callbacks.setdefault("reg", []).append(callback)
    def event_changed(self, callback):     self._callbacks.setdefault("evt", []).append(callback)
    def render_value(self, name, value):   return hex(value)

class Controller(object):
    def __init__(self): self.pctx = Pctx()
    def clear_register_focus(self): pass
    def copy_register_value(self, *args): pass
    def evaluate_expression(self, *args): pass
    def focus_register_name(self, *args): pass
    def focus_register_value(self, *args): pass
    def follow_in_dump(self, *args): pass
    def set_ip_breakpoint(self, *args): pass
    def toggle_display_format(self, *args): pass

import tenet.context  # reg_view reaches tenet.context.NMEM at runtime

from tenet.event_info import EventInfoModel
from tenet.ui.breakpoint_view import BreakpointView
from tenet.ui.event_info_view import EventInfoView
from tenet.ui.hex_view import HexView
from tenet.ui.reg_view import RegisterView
from tenet.ui.trace_view import TraceDock
from tenet.ui.tree_view import MyTreeView

controller, model = Controller(), Model()

#
# constructing these is the whole point: the original failure was an
# AttributeError inside RegisterArea._init_ctx_menu, i.e. it only appeared
# once a widget was actually built.
#
EventInfoView(controller, EventInfoModel(Pctx())).refresh()
register_view = RegisterView(controller, model)
MyTreeView()
HexView(controller, model)
TraceDock(Pctx())

# the context menus are assembled during construction; they used to be the
# first thing to die under PySide6
_AREA = register_view.reg_area
for _name in ("_action_copy_value", "_action_toggle_base",
              "_action_follow_in_disassembly", "_action_clear"):
    assert isinstance(getattr(_AREA, _name), QtGui.QAction), _name
assert len(_AREA._actions_follow_in_dump) >= 1

print("SMOKE OK")
'''

#: the views this test builds, named so a failure is actionable
CONSTRUCTED = ("EventInfoView", "RegisterView", "MyTreeView", "HexView",
               "TraceDock")


def _child_env():
    env = dict(os.environ)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    parts = [_PLUGIN_ROOT]
    if _PYSIDE_PATH:
        parts.append(_PYSIDE_PATH)
    if env.get("PYTHONPATH"):
        parts.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(parts)
    return env


def _pyside_available():
    result = subprocess.run(
        [sys.executable, "-c", "import PySide6.QtWidgets"],
        env=_child_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


@pytest.mark.skipif(
    not _pyside_available(),
    reason="PySide6 not installed (pip install PySide6, or set "
           "FRINET_PYSIDE_PATH) -- this test is deliberately optional",
)
def test_views_import_and_construct_under_real_pyside6():
    """
    Every plugin view imports, and the dockable views actually build a
    widget tree, under a real PySide6.
    """
    result = subprocess.run(
        [sys.executable, "-c", _SCRIPT % {"plugin_root": _PLUGIN_ROOT}],
        env=_child_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True,
    )

    if result.returncode != 0:
        pytest.fail(
            "a plugin view failed to import or construct under PySide6 "
            "(views built: %s)\n\n%s" % (", ".join(CONSTRUCTED), result.stdout)
        )

    assert "SMOKE OK" in result.stdout, result.stdout
