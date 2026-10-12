"""
Tests for the ``TENET_DEBUG`` diagnostics in ``util/log.py``.

These exist because ``pdbg`` runs on the hot paths (every timeline step, and
the disassembly repaint hook). Two properties therefore matter more than
usual and are worth pinning:

* it must cost nothing when disabled -- no formatting, no disassembler call
* it must never raise -- a diagnostic that throws inside a UI callback would
  break the exact thing it is meant to explain

Importing the module normally needs a real IDA, so the ``ida_*`` modules are
planted as stubs here (the same approach as ``test_frinet_ida_bridge.py``).
"""

import importlib
import sys
import types

import pytest

#: every module the log module's import chain touches
IDA_MODULES = (
    "ida_ua", "ida_dbg", "ida_idp", "ida_pro", "ida_auto", "ida_nalt",
    "ida_name", "ida_xref", "idautils", "ida_bytes", "ida_idaapi", "ida_ida",
    "ida_diskio", "ida_kernwin", "ida_segment", "idaapi",
)


@pytest.fixture
def log_module(monkeypatch):
    """Import ``tenet.util.log`` against stubbed IDA modules."""
    prefixes = ("tenet.util.log", "tenet.util.misc", "tenet.util.qt",
                "tenet.integration", "PySide6", "PyQt5", "PySide2")
    saved = {name: module for name, module in list(sys.modules.items())
             if name in IDA_MODULES or name.startswith(prefixes)}

    for name in list(sys.modules):
        if name in IDA_MODULES or name.startswith(prefixes):
            sys.modules.pop(name, None)

    for name in IDA_MODULES:
        stub = types.ModuleType(name)
        stub.__getattr__ = lambda attribute: 0
        sys.modules[name] = stub

    # what pmsg needs to reach the output window, plus the two attributes
    # IDACoreAPI touches while the import chain resolves
    kernwin = sys.modules["ida_kernwin"]
    kernwin.is_msg_inited = lambda: True
    kernwin.get_kernel_version = lambda: "9.4"
    kernwin.cvar = types.SimpleNamespace(batch=True)

    #
    # PluginForm is a *base class* in ida_api.py, so it has to be a real
    # type -- the PEP 562 stub above would hand back 0, and subclassing an
    # int raises before we ever get to test anything
    #
    kernwin.PluginForm = type("PluginForm", (object,), {})

    #
    # a permissive fake PySide6, so the shim resolves and ``QtCore`` exists.
    # ida_api.py subclasses ``QtCore.QObject`` at module scope, so without
    # this the import dies before the diagnostics can be exercised.
    #
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

    messages = []
    module = importlib.import_module("tenet.util.log")
    monkeypatch.setattr(module, "disassembler",
                        types.SimpleNamespace(is_msg_inited=lambda: True,
                                              message=messages.append))
    module._messages = messages

    yield module

    for name in list(sys.modules):
        if name in IDA_MODULES or name.startswith(prefixes):
            sys.modules.pop(name, None)
    sys.modules.update(saved)


def _enable(monkeypatch, module, value="1"):
    monkeypatch.setenv("TENET_DEBUG", value)
    module.DEBUG_ENABLED = True


def test_debug_is_silent_by_default(log_module, monkeypatch):
    """Without TENET_DEBUG the output window must stay clean."""
    monkeypatch.delenv("TENET_DEBUG", raising=False)
    log_module.DEBUG_ENABLED = False

    log_module.pdbg("this should not appear")
    log_module.pdbg("nor should %s", "this")

    assert log_module._messages == []


def test_debug_reaches_the_output_window_when_enabled(log_module, monkeypatch):
    _enable(monkeypatch, log_module)

    log_module.pdbg("step idx=%d off=%s", 7, "0x59290")

    assert len(log_module._messages) == 1
    assert "step idx=7 off=0x59290" in log_module._messages[0]
    # greppable out of a pasted log
    assert log_module._messages[0].startswith("[Tenet]")


def test_debug_with_no_arguments_passes_through(log_module, monkeypatch):
    _enable(monkeypatch, log_module)

    log_module.pdbg("a plain message")

    assert "a plain message" in log_module._messages[0]


def test_debug_never_raises_on_a_bad_format(log_module, monkeypatch):
    """
    A diagnostic must not be able to break the call site it is explaining.

    ``%d`` against a string is the classic one, and these calls sit inside
    IDA UI callbacks where an exception would take the timeline with it.
    """
    _enable(monkeypatch, log_module)

    log_module.pdbg("idx=%d", "not-an-int")
    log_module.pdbg("missing %s and %s", "one")

    # both survived, and say what they were given
    assert len(log_module._messages) == 2


def test_disabled_debug_does_not_format_its_arguments(log_module, monkeypatch):
    """
    The cost that matters: arguments are still evaluated at the call site,
    but ``pdbg`` must not build the message when nobody will read it.
    """
    monkeypatch.delenv("TENET_DEBUG", raising=False)
    log_module.DEBUG_ENABLED = False

    class Exploding(object):
        def __mod__(self, _other):
            raise AssertionError("formatted while disabled")

        def __repr__(self):
            raise AssertionError("repr'd while disabled")

    # a lazy argument would raise here if pdbg touched it
    log_module.pdbg("value=%s", Exploding())

    assert log_module._messages == []
