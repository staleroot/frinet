"""
Static check that every name a plugin module references is actually bound.

Why this exists
---------------

Three separate IDA-side failures in this project were the same mistake, and
none can be caught by importing the module -- each one lives on a code path
that only runs once the panel is on screen:

* ``PySide6.QtWidgets has no attribute 'QAction'``        (wrong Qt module)
* ``PySide6.QtWidgets has no attribute 'QStandardItem'``  (wrong Qt module)
* ``NameError: name 'Qt' is not defined``                 (dropped star import)

``pyflakes`` cannot help: nearly every UI module here does
``from tenet.util.qt import *``, and it gives up on undefined names in any
file with a star import.

So this resolves the star imports itself -- purely statically, by reading the
source of the imported module -- and reports any name that resolves to
nothing. Scoping is delegated to the stdlib's :mod:`symtable`, which already
knows the difference between a function local and a module global; that
distinction is exactly what a hand-rolled AST walk gets wrong, and getting it
wrong makes an audit either useless (too lenient) or noise (too strict).

Being static is the point: it needs neither IDA nor a Qt binding, so it runs
on every test run and fails before the code ever reaches a user's IDA.
"""

import ast
import builtins
import os
import symtable

import tenet

#: the plugin package directory (walked for source files)
PACKAGE_DIR = os.path.dirname(os.path.abspath(tenet.__file__))

#: the directory dotted module names resolve against, ie the one that
#: *contains* the ``tenet`` package -- so ``tenet.util.qt`` maps to
#: ``<here>/tenet/util/qt.py``. Patched by the fixture tests below.
MODULE_ROOT = os.path.dirname(PACKAGE_DIR)

BUILTINS = set(dir(builtins))

#: module-level names CPython always provides
DUNDERS = {
    "__name__", "__file__", "__doc__", "__package__", "__builtins__",
    "__spec__", "__loader__", "__debug__", "__path__", "__all__",
}


def iter_plugin_sources():
    """Yield ``(relative_path, absolute_path)`` for every plugin module."""
    for directory, subdirs, filenames in os.walk(PACKAGE_DIR):
        subdirs[:] = sorted(d for d in subdirs if d != "__pycache__")
        for filename in sorted(filenames):
            if filename.endswith(".py"):
                path = os.path.join(directory, filename)
                yield os.path.relpath(path, PACKAGE_DIR), path


def resolve_module(dotted):
    """Map a dotted module name to a source file, or None if it is not ours."""
    parts = dotted.split(".") if dotted else []
    base = os.path.join(MODULE_ROOT, *parts)
    for candidate in (base + ".py", os.path.join(base, "__init__.py")):
        if os.path.isfile(candidate):
            return candidate
    return None


def absolute_module(module, level, from_path):
    """Resolve ``from <level>.<module> import ...`` to an absolute dotted name."""
    if not level:
        return module or ""
    package = os.path.relpath(os.path.dirname(from_path), MODULE_ROOT).split(os.sep)
    if package == ["."]:
        package = []
    # level 1 == this package, level 2 == one up, ...
    package = package[:len(package) - (level - 1)]
    if module:
        package = package + module.split(".")
    return ".".join(p for p in package if p and p != ".")


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def module_scope_names(path, in_progress):
    """
    The names a module makes available at its top level.

    That is its own module-scope bindings and imports, plus everything its
    star imports contribute (recursively). Names declared ``global`` from
    inside a function count too -- the Qt shim installs ``QtCore``/``QtGui``/
    ``QtWidgets`` exactly that way.
    """
    if path in in_progress:
        return set()          # a star-import cycle: stop rather than loop
    in_progress = set(in_progress)
    in_progress.add(path)

    table = symtable.symtable(_read(path), path, "exec")
    names = set(s.get_name() for s in table.get_symbols()
                if s.is_local() or s.is_imported())

    # ``global x`` anywhere in the file makes x a module-level name
    for scope in _walk_scopes(table):
        for symbol in scope.get_symbols():
            if symbol.is_declared_global():
                names.add(symbol.get_name())

    for star in _star_imports(path):
        target = resolve_module(star)
        if target is not None:
            names |= module_scope_names(target, in_progress)

    return names


def _walk_scopes(table):
    """Every symbol table in the tree, including nested ones."""
    yield table
    for child in table.get_children():
        for scope in _walk_scopes(child):
            yield scope


def _star_imports(path):
    """Dotted names of the modules ``from X import *`` pulls in."""
    tree = ast.parse(_read(path), path)
    stars = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    stars.append(absolute_module(node.module, node.level, path))
    return stars


def unbound_names(path, _in_progress=None):
    """
    ``(unresolvable_modules, [(name, line), ...])`` for one module.

    A name is unbound when some scope treats it as a global lookup and
    neither the module (including its star imports) nor ``builtins``
    provides it. ``unresolvable_modules`` lists star imports whose source
    could not be found -- those names cannot be enumerated, so the caller
    should skip the file rather than pass judgement on it.
    """
    source = _read(path)
    table = symtable.symtable(source, path, "exec")

    available = module_scope_names(path, set()) | BUILTINS | DUNDERS

    unresolvable = []
    for star in _star_imports(path):
        if resolve_module(star) is None:
            unresolvable.append(star)

    offenders = []
    for scope in _walk_scopes(table):
        for symbol in scope.get_symbols():
            if not symbol.is_referenced():
                continue
            # a global lookup: the name is not a local or parameter of this
            # scope, so it must come from the module or builtins
            if symbol.is_global() and not symbol.is_local():
                name = symbol.get_name()
                if name not in available:
                    offenders.append(name)

    lines = {}
    for node in ast.walk(ast.parse(source, path)):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            lines.setdefault(node.id, node.lineno)

    found = [(name, lines.get(name, 0)) for name in sorted(set(offenders))]
    return sorted(set(unresolvable)), found


def collect_problems():
    """Run the audit over the whole plugin; returns ``({file: ...}, {file: ...})``."""
    problems = {}
    skipped = {}
    for relative, absolute in iter_plugin_sources():
        unresolved, offenders = unbound_names(absolute)
        if unresolved:
            skipped[relative] = unresolved
        elif offenders:
            problems[relative] = offenders
    return problems, skipped


def test_every_referenced_name_is_bound():
    """
    No plugin module may reference a name nothing provides.

    This is the tripwire for the failure this project hit three times: a Qt
    (or IDA) name that imports fine and then raises ``NameError`` the moment
    the code path executes inside IDA -- untestable after the fact, and
    invisible to pyflakes because of the star imports.
    """
    problems, _skipped = collect_problems()

    detail = "\n".join(
        "  %s -> %s" % (relative, ", ".join("%s:%d" % offender
                                            for offender in problems[relative]))
        for relative in sorted(problems)
    )

    assert not problems, (
        "referenced but never bound (fix the import, or bind the name "
        "explicitly):\n" + detail
    )


def test_the_audit_has_nothing_it_had_to_skip():
    """
    Every star import in the plugin must be resolvable to source.

    A skipped file is a blind spot, so the audit silently covering less than
    it claims would be a quiet failure. Keep the blind spots at zero.
    """
    _problems, skipped = collect_problems()
    assert not skipped, "could not analyse: %s" % (
        ", ".join("%s (%s)" % (k, ", ".join(v)) for k, v in sorted(skipped.items())))


def _in_tmp_module_root(directory, path):
    """Run ``unbound_names`` with the resolver pointed at a scratch tree."""
    global MODULE_ROOT
    original = MODULE_ROOT
    try:
        MODULE_ROOT = directory
        return unbound_names(path)
    finally:
        MODULE_ROOT = original


def test_the_audit_detects_a_dropped_star_import():
    """
    Guard the guard.

    An audit that silently reports nothing because it is mis-parsing would be
    worse than no audit at all -- this proves it still notices the exact
    regression it was written for: a bare ``Qt.<enum>`` with no binding.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "broken.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "class Tree(object):\n"
                "    def show(self):\n"
                "        self.setContextMenuPolicy(Qt.CustomContextMenu)\n")

        unresolved, offenders = _in_tmp_module_root(directory, path)

    assert not unresolved
    assert [name for name, _ in offenders] == ["Qt"]


def test_the_audit_accepts_a_name_arriving_via_star_import():
    """The counterpart: a star-imported name must NOT be reported."""
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        with open(os.path.join(directory, "provider.py"), "w",
                  encoding="utf-8") as handle:
            handle.write("Qt = object()\nCORE = 1\n")

        path = os.path.join(directory, "consumer.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "from provider import *\n"
                "def show(self):\n"
                "    return Qt.AlignCenter + CORE\n")

        unresolved, offenders = _in_tmp_module_root(directory, path)

    assert not unresolved
    assert offenders == []


def test_the_audit_ignores_function_locals():
    """
    The failure mode that made the first hand-rolled version unusable: a
    name assigned inside a function is not a module global, and reporting it
    as one drowns the real findings.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "locals.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "def worker(input_path, *extras, **options):\n"
                "    parsed = input_path\n"
                "    handler = lambda item: item * 2\n"
                "    for index in range(3):\n"
                "        parsed += handler(index)\n"
                "    return parsed, extras, options\n")

        unresolved, offenders = _in_tmp_module_root(directory, path)

    assert not unresolved
    assert offenders == []
