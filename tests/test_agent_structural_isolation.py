"""AST-level guarantee: the agent's model-facing modules cannot reach real state directly.

Same discipline `tests/test_narrate.py` already uses to guarantee
`reasoning/narrate.py` cannot touch `detect.calibration`/`detect.behavioral`:
parse the module's own source and assert the forbidden imports are
structurally absent, rather than trusting that nobody adds one later.

`agent.shopper` (the tool-calling loop) and `agent.llm_client` (the Groq
adapter) are the two modules a model's own output can influence -- a tool
name and arguments chosen by the model flow into `agent.shopper`'s dispatch.
Neither may import the real mandate/key registry, escalation queue, or
service internals directly; the only sanctioned path to any of that is
`agent.tools`, whose three functions are the complete, audited boundary
(see `agent/tools.py`'s own module docstring).
"""

from __future__ import annotations

import ast
import inspect
from types import ModuleType

import agent.llm_client as llm_client_module
import agent.shopper as shopper_module

_FORBIDDEN_MODULES = {
    "service.main",
    "service.state",
    "service.delegation_chain",
    "service.schemas",
    "mandate.verification",
    "mandate.signing",
    "mandate.schema",
    "escalation.queue",
    "escalation.circuit_breaker",
    "escalation.log",
    "escalation.schema",
    "containment.gate",
    "containment.engine",
    "containment.chain",
    "containment.store",
}


def _assert_no_forbidden_imports(module: ModuleType) -> None:
    """Parses a module's source and asserts none of `_FORBIDDEN_MODULES` is imported.

    Args:
        module: The already-imported module object to inspect.
    """
    source = inspect.getsource(module)
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in _FORBIDDEN_MODULES, (
                    f"{module.__name__} imports forbidden module {alias.name!r} directly"
                )
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            assert node.module not in _FORBIDDEN_MODULES, (
                f"{module.__name__} imports from forbidden module {node.module!r} directly"
            )


def test_shopper_module_never_imports_real_registries_directly() -> None:
    """`agent.shopper` (the tool-calling loop) cannot reach mandate/escalation/service internals directly."""
    _assert_no_forbidden_imports(shopper_module)


def test_llm_client_module_never_imports_real_registries_directly() -> None:
    """`agent.llm_client` (the Groq adapter) cannot reach mandate/escalation/service internals directly."""
    _assert_no_forbidden_imports(llm_client_module)


def test_shopper_module_only_calls_the_three_sanctioned_tool_functions() -> None:
    """`agent.shopper` imports exactly `search_catalog`, `propose_purchase`, and `checkout` from `agent.tools`.

    A stronger, more literal reading of "can only reach the three tool
    functions" than the forbidden-module walk above: this asserts the
    *positive* set of `agent.tools` names imported is exactly the three
    real tools (plus the supporting types every tool call's arguments and
    return values are rendered through), not a superset that could include
    something with a wider effect added to `agent.tools` later without a
    matching update here.
    """
    source = inspect.getsource(shopper_module)
    tree = ast.parse(source)
    imported_from_tools: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "agent.tools":
            imported_from_tools.update(alias.name for alias in node.names)

    sanctioned_functions = {"search_catalog", "propose_purchase", "checkout"}
    sanctioned_supporting_types = {
        "CatalogItem",
        "PurchaseProposal",
        "SentinelVerdict",
        "ShopperToolContext",
        "ToolValidationError",
    }
    assert sanctioned_functions <= imported_from_tools
    assert imported_from_tools <= (sanctioned_functions | sanctioned_supporting_types)
