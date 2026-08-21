"""Fail-closed hook execution contracts backed by an explicit sandbox adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from skilltrust.models import HookSpecV1, ValidationStatus

MAX_HOOK_OUTPUT_BYTES = 1_048_576


@dataclass(frozen=True)
class SandboxInvocation:
    """Structured argv-only request passed to a sandbox adapter."""

    argv: tuple[str, ...]
    timeout_seconds: int
    network: str
    allowed_hosts: tuple[str, ...]


@dataclass(frozen=True)
class SandboxProof:
    """Claims that the adapter must prove about the execution environment."""

    filesystem_isolated: bool
    secrets_isolated: bool
    network_isolated: bool
    network_allowlist_enforced: bool


@dataclass(frozen=True)
class SandboxResult:
    """Sandboxed hook execution result."""

    exit_code: int | None
    proof: SandboxProof
    timed_out: bool = False
    stdout: bytes = b""
    stderr: bytes = b""


class SandboxAdapter(Protocol):
    """Runtime contract for hook execution."""

    adapter_id: str

    def run_argv(self, invocation: SandboxInvocation) -> SandboxResult:
        """Execute a hook without invoking a shell."""


@dataclass(frozen=True)
class HookOutcome:
    """Result for one hook."""

    name: str
    required: bool
    status: ValidationStatus
    code: str
    message: str

    @property
    def denies_execution(self) -> bool:
        return self.required and self.status is not ValidationStatus.PASS


@dataclass(frozen=True)
class HookSummary:
    """Aggregate hook evaluation with a fail-closed authorization bit."""

    results: tuple[HookOutcome, ...]
    status: ValidationStatus
    reason_codes: tuple[str, ...]

    @property
    def denies_execution(self) -> bool:
        return any(result.denies_execution for result in self.results)


def run_hook(spec: HookSpecV1, sandbox: SandboxAdapter | None) -> HookOutcome:
    """Execute one hook through the declared sandbox contract."""

    if sandbox is None:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code="hook_sandbox_missing",
            message="hook execution requires an explicit sandbox adapter",
        )

    invocation = SandboxInvocation(
        argv=spec.command,
        timeout_seconds=spec.timeout_seconds,
        network=spec.network,
        allowed_hosts=spec.allowed_hosts,
    )
    try:
        raw_result = sandbox.run_argv(invocation)
    except TimeoutError:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code="hook_timed_out",
            message="sandbox adapter timed out before returning a result",
        )
    except Exception as exc:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code="hook_sandbox_error",
            message=f"sandbox adapter failed safely ({type(exc).__name__})",
        )
    if not isinstance(raw_result, SandboxResult):
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code="hook_output_malformed",
            message="sandbox adapter returned malformed hook output",
        )
    if len(raw_result.stdout) + len(raw_result.stderr) > MAX_HOOK_OUTPUT_BYTES:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code="hook_output_too_large",
            message="sandbox output exceeded the configured control-plane limit",
        )

    proof_error = _proof_error(spec, raw_result.proof)
    if proof_error is not None:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code=proof_error,
            message="sandbox adapter could not prove the required isolation contract",
        )
    if raw_result.timed_out or raw_result.exit_code is None:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.UNKNOWN,
            code="hook_timed_out",
            message="hook execution timed out",
        )
    if raw_result.exit_code == 0:
        return HookOutcome(
            name=spec.name,
            required=spec.required,
            status=ValidationStatus.PASS,
            code="hook_passed",
            message="hook execution completed successfully",
        )
    return HookOutcome(
        name=spec.name,
        required=spec.required,
        status=ValidationStatus.FAIL,
        code="hook_failed",
        message=f"hook exited with status {raw_result.exit_code}",
    )


def evaluate_hooks(hooks: tuple[HookSpecV1, ...], sandbox: SandboxAdapter | None) -> HookSummary:
    """Run all hooks and summarize their authorization impact."""

    results = tuple(run_hook(spec, sandbox) for spec in hooks)
    required_results = tuple(result for result in results if result.required)
    if not required_results:
        return HookSummary(results=results, status=ValidationStatus.PASS, reason_codes=())

    failing = tuple(result for result in required_results if result.status is ValidationStatus.FAIL)
    if failing:
        return HookSummary(
            results=results,
            status=ValidationStatus.FAIL,
            reason_codes=tuple(result.code for result in failing),
        )

    unknown = tuple(
        result for result in required_results if result.status is ValidationStatus.UNKNOWN
    )
    if unknown:
        return HookSummary(
            results=results,
            status=ValidationStatus.UNKNOWN,
            reason_codes=tuple(result.code for result in unknown),
        )

    return HookSummary(results=results, status=ValidationStatus.PASS, reason_codes=())


def _proof_error(spec: HookSpecV1, proof: SandboxProof) -> str | None:
    if not proof.filesystem_isolated:
        return "filesystem_isolation_unproven"
    if not proof.secrets_isolated:
        return "secret_isolation_unproven"
    if spec.network == "none" and not proof.network_isolated:
        return "network_isolation_unproven"
    if spec.network == "allowlist" and not proof.network_allowlist_enforced:
        return "network_isolation_unproven"
    return None


__all__ = [
    "MAX_HOOK_OUTPUT_BYTES",
    "HookOutcome",
    "HookSummary",
    "SandboxAdapter",
    "SandboxInvocation",
    "SandboxProof",
    "SandboxResult",
    "evaluate_hooks",
    "run_hook",
]
