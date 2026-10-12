"""
FRINET probe: what does *this* IDA build expose for pseudocode navigation?

Run it inside IDA, with a pseudocode window open and focused:

    1. open any function's pseudocode (double-click into it, so it is the
       current widget)
    2. File -> Script file...  ->  this file
    3. copy the whole Output window and send it back

It is read-only apart from section 6, which deliberately moves the
pseudocode cursor a few times -- that is the experiment. It never raises
into IDA: anything that fails is printed and the probe moves on.

Why this exists
---------------
FRINET places the pseudocode cursor with

    ida_kernwin.jumpto(vdui.ct, place, x, 0)

which needs a *concrete* ``place_t``. The class that obviously fits --
``simpleline_place_t`` -- is abstract on IDA 9.4, so it cannot be
constructed at all, and its concrete subclass differs between versions.
Guessing it has already cost two rounds. This probe finds out instead: it
constructs every ``*place_t`` the build exposes and asks the live
pseudocode view which of them it accepts.

If exactly one returns True, that is the answer and it is already what
FRINET's runtime discovery looks for. If none do, the dump of
``ida_hexrays.vdui_t`` in section 1 names the real cursor API, and that is
the answer too.
"""

import ida_hexrays
import ida_kernwin


def section(title):
    print("\n===== %s =====" % title)


def public(name):
    return not name.startswith("__")


def main():
    print("probe: ida version = %s" % getattr(
        ida_kernwin, "get_kernel_version", lambda: "?")())

    #------------------------------------------------------------------
    # 1. what vdui_t actually offers on this build
    #------------------------------------------------------------------
    section("1. ida_hexrays.vdui_t members")
    print(sorted(n for n in dir(ida_hexrays.vdui_t) if public(n)))

    section("1b. ida_hexrays names mentioning place / jump / nav / cursor")
    print(sorted(n for n in dir(ida_hexrays)
                 if any(k in n.lower()
                        for k in ("place", "jump", "nav", "cursor"))))

    #------------------------------------------------------------------
    # 2. the live view, if one is current
    #------------------------------------------------------------------
    section("2. live pseudocode view")
    vu = None
    try:
        widget = ida_kernwin.get_current_widget()
        kind = ida_kernwin.get_widget_type(widget) if widget else None
        print("current widget type = %r" % kind)
        vu = ida_hexrays.get_widget_vdui(widget) if widget else None
        print("vdui = %r" % vu)
        if vu is not None:
            print("vdui members = %s" % sorted(n for n in dir(vu)
                                               if public(n)))
            print("vdui.cfunc entry = %r" % (
                vu.cfunc.entry_ea if vu.cfunc else None))
            for attr in ("ct", "ctext", "mba", "widget", "get_widget"):
                print("  vdui.%-11s = %r" % (attr, getattr(vu, attr,
                                                           "<absent>")))
    except Exception as exc:
        print("live view unavailable: %s: %s" % (type(exc).__name__, exc))

    if vu is None:
        print("\nNo pseudocode view is current. Click into one and re-run.")

    #------------------------------------------------------------------
    # 3. which place classes can be constructed at all
    #------------------------------------------------------------------
    section("3. constructible ida_kernwin *place_t classes")
    constructible = []
    for name in sorted(n for n in dir(ida_kernwin) if n.endswith("place_t")):
        cls = getattr(ida_kernwin, name, None)
        if not callable(cls):
            continue
        last = None
        for args in ((3,), (0,), ()):
            try:
                instance = cls(*args)
            except Exception as exc:
                last = "%s: %s" % (type(exc).__name__, exc)
                continue
            print("OK   %-32s%s" % (name, args))
            constructible.append((name, instance))
            break
        else:
            print("FAIL %-32s %s" % (name, last))

    #------------------------------------------------------------------
    # 4. what jumpto says about the prototypes it accepts
    #------------------------------------------------------------------
    section("4. ida_kernwin.jumpto")
    print(repr(getattr(ida_kernwin, "jumpto", "<absent>")))
    print(repr(getattr(ida_kernwin, "activate_widget", "<absent>")))
    for name in ("get_custom_viewer_place", "set_custom_viewer_place",
                 "custom_viewer_place_t", "simpleline_place_t",
                 "input_line_place_t", "disasm_line_place_t"):
        print("%-28s %r" % (name, getattr(ida_kernwin, name, "<absent>")))

    #------------------------------------------------------------------
    # 5. can we clone the view's own current place?
    #------------------------------------------------------------------
    section("5. cloning the view's current place")
    if vu is not None:
        for args in ((vu.ct, False), (vu.ct, False, 0, 0), (vu.ct,)):
            try:
                got = ida_kernwin.get_custom_viewer_place(*args)
                print("get_custom_viewer_place%r -> %r" % (args, got))
                break
            except Exception as exc:
                print("get_custom_viewer_place%r -> %s: %s"
                      % (args, type(exc).__name__, exc))

    #------------------------------------------------------------------
    # 6. THE EXPERIMENT: which place does the pseudocode view accept?
    #------------------------------------------------------------------
    section("6. jumpto against the live pseudocode view")
    if vu is None:
        print("skipped: no pseudocode view is current")
        return

    for name, place in constructible:
        for handle_name in ("ct",):
            handle = getattr(vu, handle_name, None)
            if handle is None:
                print("skip  %s: vdui.%s is absent" % (name, handle_name))
                continue
            for args in ((place, 0, 0), (place, 3, 0), (place,)):
                try:
                    ok = ida_kernwin.jumpto(handle, *args)
                except Exception as exc:
                    print("jumpto(%s, %s%r) -> %s: %s"
                          % (handle_name, name, args[1:],
                             type(exc).__name__, exc))
                    break
                print("jumpto(%s, %s%r) -> %r"
                      % (handle_name, name, args[1:], ok))
                if ok:
                    break

    print("\nprobe done.")


try:
    main()
except Exception as exc:      # never take IDA down with us
    print("probe failed: %s: %s" % (type(exc).__name__, exc))
