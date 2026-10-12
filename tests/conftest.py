"""
Shared test configuration.

Adds the two import roots to ``sys.path``:

* ``tracer/``      -> ``import frinet``      (pure FRINET conversion helpers)
* ``tenet/plugins`` -> ``import tenet....``   (the IDA plugin package)

IDA itself is *not* required (and not available) here: anything that needs
IDA is either a pure module under test or covered by the manual test plan in
``docs/manual-testing.md``.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _path in (
    os.path.join(ROOT, "tracer"),
    os.path.join(ROOT, "tenet", "plugins"),
):
    if _path not in sys.path:
        sys.path.insert(0, _path)

#: Path of a real example trace, used as an end-to-end fixture when present.
#: It is *not* checked in: the tests that need it skip when it is missing.
EXAMPLE_TENET = os.path.join(ROOT, "example.tenet")

#--------------------------------------------------------------------------
# IDA module stubs (planted before any test module is collected)
#--------------------------------------------------------------------------
#
# ``tenet.util.log`` imports the disassembler API unconditionally, and that
# API imports every ``ida_*`` module it uses. Nothing here needs IDA to
# *work* -- only to be *importable*.
#
# This has to happen at conftest import time, and the reason is a trap that
# was invisible until PySide6 was installed. ``tenet/ui/__init__.py`` only
# imports the Qt views when ``QT_AVAILABLE``, and only those views drag in
# the disassembler API. So with no Qt binding present the whole IDA chain is
# skipped, ``import tenet.event_info`` succeeds, and every test passes --
# install PySide6 (as the Qt smoke-test section below says to do) and
# ``pytest tests`` stops collecting with ``No module named 'ida_ua'``.
#
# A suite that only passes because its dependencies are absent is not
# passing; it is untested. Planting the stubs here makes the import path the
# tests actually exercise the same one IDA will take.
#

IDA_STUB_MODULES = (
    "ida_ua", "ida_dbg", "ida_idp", "ida_pro", "ida_auto", "ida_nalt",
    "ida_name", "ida_xref", "idautils", "ida_bytes", "ida_idaapi", "ida_ida",
    "ida_diskio", "ida_kernwin", "ida_segment", "idaapi",
)


def _plant_ida_stubs():
    import types

    for name in IDA_STUB_MODULES:
        if name in sys.modules:
            continue
        stub = types.ModuleType(name)
        # PEP 562: a module-level __getattr__ makes any attribute resolvable,
        # so a star import or an API probe can never raise inside IDA code
        stub.__getattr__ = lambda attribute: 0
        sys.modules[name] = stub

    kernwin = sys.modules["ida_kernwin"]

    #
    # PluginForm is subclassed at module scope in ida_api.py, so it has to be
    # a real type -- the permissive __getattr__ above would hand back 0, and
    # subclassing an int raises before anything can be tested.
    #
    kernwin.PluginForm = type("PluginForm", (object,), {})

    # what pmsg needs to reach the output window, plus what IDACoreAPI and
    # the Qt shim consult while the import chain resolves
    kernwin.is_msg_inited = lambda: True
    kernwin.get_kernel_version = lambda: "9.4"
    kernwin.cvar = types.SimpleNamespace(batch=True)


#: the bindings the shim will accept as "a Qt is available"
QT_BINDINGS = ("PySide6", "PyQt5", "PySide2")


def _binding_installed():
    for name in QT_BINDINGS:
        try:
            __import__(name)
        except Exception:
            continue
        return True
    return False


def _plant_placeholder_binding():
    """
    Give ``ida_api.py`` a Qt when no binding is installed.

    ``ida_api`` ends with ``class IDADockSizeHack(QtCore.QObject)``, and gets
    ``QtCore`` from a star import of ``tenet.util.qt`` that only supplies it
    once a binding resolves. So importing the disassembler API head-lessly
    needs a Qt, not just an IDA -- otherwise the ``ImportError`` that
    ``event_info.py`` deliberately catches is replaced by a ``NameError`` it
    cannot catch.

    This is the same permissive stand-in ``test_frinet_diagnostics`` uses.
    Registering it under the real binding name is deliberate: the point is
    for the import path the tests exercise to be the one IDA will take, and
    the alternative -- a private placeholder module -- would import fine and
    still leave ``QtCore`` undefined.
    """
    import types

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
    package.__path__ = []
    for sub in ("QtCore", "QtGui", "QtWidgets"):
        setattr(package, sub, sys.modules["PySide6." + sub])
    sys.modules["PySide6"] = package


_plant_ida_stubs()

if not _binding_installed():
    _plant_placeholder_binding()
