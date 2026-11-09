"""Scoped imports for the explicit Astrid shutdown composition root."""
from __future__ import annotations

from contextlib import contextmanager
from importlib import import_module
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder
from pathlib import Path
import sys

from .bootstrap import BootstrapError, _has_symlink_component


class _SelectedAgent(MetaPathFinder):
    def __init__(self, root: Path):
        if not root.is_absolute() or _has_symlink_component(root) or not root.is_dir():
            raise BootstrapError(f"Selected Agent checkout must be an existing absolute symlink-free directory: {root}")
        self.root = root.resolve()

    @staticmethod
    def owns(name):
        return name.split(".", 1)[0] in {"astrid", "astrid_runtime_client"}

    def verify(self, name, origin, locations):
        target = self.root.joinpath(*name.split("."))
        expected = (target / "__init__.py", target.with_suffix(".py"))
        if (not origin or Path(origin) not in expected
                or _has_symlink_component(Path(origin)) or not Path(origin).is_file()):
            raise BootstrapError(f"Selected Agent module {name} has an unselected origin: {origin}; expected {target}")
        if locations is not None and list(locations) != [str(target)]:
            raise BootstrapError(f"Selected Agent package {name} has unselected search locations")

    def find_spec(self, fullname, path=None, target=None):
        if not self.owns(fullname):
            return None
        # Resolve each name directly from the selected root, ignoring both
        # ambient sys.path and a package's possibly widened __path__.
        parent = self.root.joinpath(*fullname.split(".")[:-1])
        spec = PathFinder.find_spec(fullname, [str(parent)])
        if spec is None:
            raise BootstrapError(f"Selected Agent module {fullname} is missing beneath {self.root}")
        self.verify(fullname, spec.origin, spec.submodule_search_locations)
        return spec


@contextmanager
def selected_shutdown_owner(source_checkout: str):
    """Keep lazy Agent/SDK imports selected through shutdown's stop callback.

    An already imported foreign Agent cannot safely be replaced in-process;
    refuse it before preparation or stop effects instead of mixing owners.
    """
    selected = _SelectedAgent(Path(source_checkout).expanduser())
    for name, module in tuple(sys.modules.items()):
        if selected.owns(name):
            selected.verify(name, getattr(module, "__file__", None), getattr(module, "__path__", None))
    sys.meta_path.insert(0, selected)
    try:
        product = import_module("astrid.services")
        helper = getattr(product, "prepare_pack_host_shutdown", None)
        if not callable(helper) or getattr(helper, "__module__", None) != product.__name__:
            raise BootstrapError(f"Selected Agent at {selected.root} does not define prepare_pack_host_shutdown")
        yield helper
    finally:
        sys.meta_path.remove(selected)
