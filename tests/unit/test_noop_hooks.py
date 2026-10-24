"""KS-992: a hook marked `noop_hook` has nothing in it, so no span for it hides nothing."""

import ast
import inspect
import textwrap

import pytest

import keystone.gateway.interceptors as interceptors_package
import keystone.gateway.stubs as stubs
from keystone.core.types import CallContext
from keystone.gateway.hooks import is_noop, noop_hook
from keystone.gateway.interceptors import (
    approval,
    budget,
    credentials,
    flags,
    metering,
    pinning,
    policy,
    ratelimit,
    scan,
)

pytestmark = pytest.mark.phase(9)

MODULES = [
    approval,
    budget,
    credentials,
    flags,
    metering,
    pinning,
    policy,
    ratelimit,
    scan,
    stubs,
]


def marked_hooks() -> list[tuple[str, object]]:
    found: list[tuple[str, object]] = []
    for module in MODULES:
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__:
                continue
            for hook in ("before_call", "after_call"):
                function = cls.__dict__.get(hook)
                if function is not None and is_noop(function):
                    found.append((f"{module.__name__}.{cls.__name__}.{hook}", function))
    return found


def test_the_idle_hooks_are_found() -> None:
    names = [name for name, _ in marked_hooks()]
    # Pinning's after hook and the stubs' hooks are among them; credentials' after hook clears
    # the headers, so it is not.
    assert any(name.endswith("PinningInterceptor.after_call") for name in names)
    assert not any(name.endswith("credentials.CredentialInterceptor.after_call") for name in names)
    assert len(names) >= 8


@pytest.mark.parametrize(("name", "function"), marked_hooks())
def test_a_marked_hook_does_nothing(name: str, function: object) -> None:
    tree = ast.parse(textwrap.dedent(inspect.getsource(function)))  # type: ignore[arg-type]
    [definition] = tree.body
    assert isinstance(definition, ast.AsyncFunctionDef), name
    body = definition.body
    # An optional docstring, then `return None` and nothing else.
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    assert len(body) == 1 and isinstance(body[0], ast.Return), name
    assert body[0].value is None or (
        isinstance(body[0].value, ast.Constant) and body[0].value.value is None
    ), name


def test_the_mark_is_on_the_function_and_visible_through_the_bound_method() -> None:
    class Slot:
        @noop_hook
        async def after_call(self, ctx: CallContext) -> None:
            return None

        async def before_call(self, ctx: CallContext) -> None:
            return None

    slot = Slot()
    assert is_noop(slot.after_call) and not is_noop(slot.before_call)


def test_the_package_is_the_one_the_modules_come_from() -> None:
    assert interceptors_package.__name__ == "keystone.gateway.interceptors"
