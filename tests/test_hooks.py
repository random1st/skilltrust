from __future__ import annotations

from typing import cast

from skilltrust.hooks import (
    MAX_HOOK_OUTPUT_BYTES,
    HookSummary,
    SandboxAdapter,
    SandboxInvocation,
    SandboxProof,
    SandboxResult,
    evaluate_hooks,
    run_hook,
)
from skilltrust.models import HookSpecV1, ValidationStatus


class RecordingSandbox:
    adapter_id = "sandbox-v1"

    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[SandboxInvocation] = []

    def run_argv(self, invocation: SandboxInvocation) -> SandboxResult:
        self.calls.append(invocation)
        return self.result


class MalformedSandbox:
    adapter_id = "sandbox-v1"

    def run_argv(self, invocation: SandboxInvocation) -> object:
        del invocation
        return {"exit_code": 0}


def proof(
    *,
    filesystem_isolated: bool = True,
    secrets_isolated: bool = True,
    network_isolated: bool = True,
    network_allowlist_enforced: bool = True,
) -> SandboxProof:
    return SandboxProof(
        filesystem_isolated=filesystem_isolated,
        secrets_isolated=secrets_isolated,
        network_isolated=network_isolated,
        network_allowlist_enforced=network_allowlist_enforced,
    )


def hook(*, network: str = "none", required: bool = True) -> HookSpecV1:
    if network == "allowlist":
        return HookSpecV1(
            name="policy-check",
            command=("tool", "--scan"),
            timeout_seconds=30,
            network="allowlist",
            allowed_hosts=("api.example.test",),
            required=required,
        )
    return HookSpecV1(
        name="policy-check",
        command=("tool", "--scan"),
        timeout_seconds=30,
        required=required,
    )


def test_required_hook_without_sandbox_is_unknown_and_denies() -> None:
    outcome = run_hook(hook(), None)
    assert outcome.status is ValidationStatus.UNKNOWN
    assert outcome.code == "hook_sandbox_missing"
    assert outcome.denies_execution is True


def test_hook_failure_denies_required_hook() -> None:
    sandbox = RecordingSandbox(SandboxResult(exit_code=7, proof=proof()))
    outcome = run_hook(hook(), sandbox)
    assert outcome.status is ValidationStatus.FAIL
    assert outcome.code == "hook_failed"
    assert sandbox.calls[0].argv == ("tool", "--scan")


def test_hook_timeout_is_unknown() -> None:
    sandbox = RecordingSandbox(SandboxResult(exit_code=None, timed_out=True, proof=proof()))
    outcome = run_hook(hook(), sandbox)
    assert outcome.status is ValidationStatus.UNKNOWN
    assert outcome.code == "hook_timed_out"


def test_malformed_hook_output_is_unknown() -> None:
    outcome = run_hook(hook(), cast(SandboxAdapter, MalformedSandbox()))
    assert outcome.status is ValidationStatus.UNKNOWN
    assert outcome.code == "hook_output_malformed"


def test_networked_hook_requires_allowlist_proof() -> None:
    sandbox = RecordingSandbox(
        SandboxResult(
            exit_code=0,
            proof=proof(network_isolated=False, network_allowlist_enforced=False),
        )
    )
    summary = evaluate_hooks((hook(network="allowlist"),), sandbox)
    assert summary.status is ValidationStatus.UNKNOWN
    assert summary.reason_codes == ("network_isolation_unproven",)
    assert summary.denies_execution is True


def test_all_required_hooks_passing_returns_pass_summary() -> None:
    sandbox = RecordingSandbox(SandboxResult(exit_code=0, proof=proof()))
    summary = evaluate_hooks((hook(),), sandbox)
    assert isinstance(summary, HookSummary)
    assert summary.status is ValidationStatus.PASS
    assert summary.denies_execution is False


def test_adapter_exception_and_large_output_fail_closed() -> None:
    class CrashingSandbox:
        adapter_id = "crash"

        def run_argv(self, invocation: SandboxInvocation) -> SandboxResult:
            raise RuntimeError("secret internal detail")

    class NoisySandbox:
        adapter_id = "noisy"

        def run_argv(self, invocation: SandboxInvocation) -> SandboxResult:
            return SandboxResult(
                exit_code=0,
                proof=proof(),
                stdout=b"x" * (MAX_HOOK_OUTPUT_BYTES + 1),
            )

    crashed = run_hook(hook(), CrashingSandbox())
    noisy = run_hook(hook(), NoisySandbox())
    assert crashed.status is ValidationStatus.UNKNOWN
    assert crashed.code == "hook_sandbox_error"
    assert "secret internal detail" not in crashed.message
    assert noisy.status is ValidationStatus.UNKNOWN
    assert noisy.code == "hook_output_too_large"
