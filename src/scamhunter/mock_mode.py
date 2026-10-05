"""Mock mode: load the local mock exchange (tests/fixtures/mock_exchange) for the agent trial.

Mock mode runs inside the crawler container, which has no route out, with a browser that has no
proxy and may only reach loopback (config.require_loopback_url, sandbox.restrict_to_loopback)."""

import importlib.util
from types import ModuleType

from scamhunter.config import REPO_ROOT

EXCHANGE_DIR = REPO_ROOT / "tests" / "fixtures" / "mock_exchange"


def load_exchange_module() -> ModuleType:
    """The fixture is not a package (it lives under tests/ per DESIGN §2.1), so load by path."""
    spec = importlib.util.spec_from_file_location(
        "mock_exchange_server", EXCHANGE_DIR / "server.py"
    )
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"mock exchange not found in {EXCHANGE_DIR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
