"""
Tests for ``QTimerScheduler`` -- the thing that actually runs pseudocode
updates.

It exists because the previous arrangement queued updates into a scheduler
that never ran them: the plugin passed nothing, the controller defaulted to a
:class:`NullScheduler`, and the pseudocode silently never followed the trace
while the timeline and disassembly both worked. So what is pinned here is the
behaviour the plugin depends on -- that a queued callback really does get
invoked, that a burst collapses into one run, and that cancelling drops the
work rather than half of it.

The timer is substituted with a controllable fake rather than a real Qt one:
these are decisions, not Qt's, and Qt's own timer behaviour is already
exercised by the optional smoke test.
"""

import importlib
import sys
import types

import pytest

#: every module the import chain touches
IDA_MODULES = (
    "ida_ua", "ida_dbg", "ida_idp", "ida_pro", "ida_auto", "ida_nalt",
    "ida_name", "ida_xref", "idautils", "ida_bytes", "ida_idaapi", "ida_ida",
    "ida_diskio", "ida_kernwin", "ida_segment", "idaapi",
)


class FakeTimer(object):
    """
    A ``QTimer`` that only records what it was asked to do.

    ``fire()`` stands in for the event loop elapsing, so a test decides when
    (and whether) the timeout happens instead of waiting on one.
    """

    def __init__(self):
        self.timeout = types.SimpleNamespace(connect=self._connect)
        self.single_shot = None
        self.interval = None
        self.started = 0
        self.stopped = 0
        self._timeout = None

    def setSingleShot(self, value):
        self.single_shot = value

    def setInterval(self, value):
        self.interval = value

    def start(self):
        self.started += 1

    def stop(self):
        self.stopped += 1

    def _connect(self, callback):
        self._timeout = callback

    def fire(self):
        """Elapse the timer, as the event loop eventually would."""
        if self._timeout is not None:
            self._timeout()


@pytest.fixture
def qt_util(monkeypatch):
    """Import ``tenet.util.qt.util`` against a planted fake PySide6."""
    prefixes = ("tenet.util.qt", "PySide6", "PyQt5", "PySide2")
    saved = {name: module for name, module in list(sys.modules.items())
             if name in IDA_MODULES or name.startswith(prefixes)}

    for name in list(sys.modules):
        if name in IDA_MODULES or name.startswith(prefixes):
            sys.modules.pop(name, None)

    for name in IDA_MODULES:
        stub = types.ModuleType(name)
        stub.__getattr__ = lambda attribute: 0
        sys.modules[name] = stub

    # a permissive binding, so the shim resolves and QtGui/QtCore exist
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

    module = importlib.import_module("tenet.util.qt.util")

    # substitute the timer: these tests are about scheduling, not about Qt
    fake = types.SimpleNamespace(QTimer=FakeTimer)
    monkeypatch.setattr(module, "QtCore", fake)

    yield module

    for name in list(sys.modules):
        if name in IDA_MODULES or name.startswith(prefixes):
            sys.modules.pop(name, None)
    sys.modules.update(saved)


def make_scheduler(qt_util):
    """A scheduler with a reachable handle on its (fake) timer."""
    scheduler = qt_util.QTimerScheduler()
    return scheduler, scheduler._timer


def test_the_timer_is_single_shot_and_wired_to_the_scheduler(qt_util):
    """Coalescing only works if the timer does not repeat on its own."""
    scheduler, timer = make_scheduler(qt_util)

    assert timer.single_shot is True
    assert timer._timeout == scheduler._fire


def test_schedule_starts_the_timer_with_the_requested_delay(qt_util):
    scheduler, timer = make_scheduler(qt_util)
    ran = []

    scheduler.schedule(lambda: ran.append("ran"), 40)

    assert timer.started == 1
    assert timer.interval == 40
    assert scheduler.active is True
    assert ran == []

    timer.fire()
    assert ran == ["ran"]
    assert scheduler.active is False


def test_a_burst_collapses_into_a_single_run(qt_util):
    """
    The whole reason for coalescing: a timeline scrub fires an index change
    per step, and each one would otherwise open the decompiler. Only the
    final position matters.
    """
    scheduler, timer = make_scheduler(qt_util)
    ran = []

    for step in range(50):
        scheduler.schedule(lambda step=step: ran.append(step), 40)

    timer.fire()

    assert ran == [49]
    assert timer.started == 50


def test_cancel_drops_the_work_without_running_it(qt_util):
    scheduler, timer = make_scheduler(qt_util)
    ran = []

    scheduler.schedule(ran.append, 40)
    scheduler.cancel()
    timer.fire()

    assert ran == []
    assert timer.stopped == 1
    assert scheduler.active is False


def test_scheduling_again_after_cancel_works(qt_util):
    """Cancel is not terminal: the next step must still be able to run."""
    scheduler, timer = make_scheduler(qt_util)
    ran = []

    scheduler.schedule(lambda: ran.append("cancelled"), 40)
    scheduler.cancel()
    scheduler.schedule(lambda: ran.append("after"), 40)
    timer.fire()

    assert ran == ["after"]


def test_an_exception_in_the_callback_does_not_escape(qt_util, caplog):
    """
    The callback runs inside a Qt slot. An exception there surfaces far from
    its cause and takes the timer with it, so it is caught and logged where
    it happened instead.
    """
    import logging

    scheduler, timer = make_scheduler(qt_util)

    def boom():
        raise RuntimeError("decompiler exploded")

    scheduler.schedule(boom, 40)

    with caplog.at_level(logging.ERROR, logger="Tenet.Util.Qt"):
        timer.fire()

    assert "decompiler exploded" in caplog.text
    # and the timer is not left holding a half-consumed callback
    assert scheduler.active is False


def test_a_timeout_with_nothing_queued_is_harmless(qt_util):
    """
    A timer can outlive its intent (a cancel racing the timeout). Firing with
    nothing queued must be a no-op rather than a crash.
    """
    scheduler, timer = make_scheduler(qt_util)

    timer.fire()

    assert scheduler.active is False
