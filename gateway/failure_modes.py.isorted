"""
Configurable failure modes for dependency outages (Sprint 8.4).

Modes:
  - fail_closed: Deny all actions (safest for regulated environments)
  - fail_open: Allow all actions (highest availability)
  - fail_to_queue: Enqueue for human review (balanced)

Per-tenant configuration stored in tenant settings (failure_config column).
"""

import json
from enum import Enum


class FailureMode(str, Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"
    FAIL_TO_QUEUE = "fail_to_queue"


# Default failure modes per dependency
DEFAULTS = {
    "opa": FailureMode.FAIL_CLOSED,
    "redis": FailureMode.FAIL_OPEN,
    "blockchain": FailureMode.FAIL_OPEN,  # audit continues locally
}


def get_failure_mode(tenant: dict, dependency: str) -> FailureMode:
    """Get the failure mode for a dependency from tenant config."""
    config = tenant.get("failure_config", {})
    if isinstance(config, str):
        try:
            config = json.loads(config) if config else {}
        except (json.JSONDecodeError, TypeError):
            config = {}
    mode_str = config.get(
        dependency, DEFAULTS.get(dependency, FailureMode.FAIL_CLOSED).value
    )
    try:
        return FailureMode(mode_str)
    except ValueError:
        return DEFAULTS.get(dependency, FailureMode.FAIL_CLOSED)


def handle_failure(
    tenant: dict, dependency: str, error: Exception, action_data: dict = None
) -> dict:
    """
    Handle a dependency failure according to the tenant's configured mode.
    Returns a decision dict that the caller can use.
    """
    mode = get_failure_mode(tenant, dependency)

    if mode == FailureMode.FAIL_CLOSED:
        return {
            "status": "denied",
            "reason": f"{dependency}_unavailable",
            "failure_mode": "fail_closed",
            "error": str(error),
        }
    elif mode == FailureMode.FAIL_OPEN:
        return {
            "status": "allowed",
            "reason": f"{dependency}_unavailable_fail_open",
            "failure_mode": "fail_open",
            "warning": f"{dependency} is unavailable; action allowed under fail-open policy",
        }
    elif mode == FailureMode.FAIL_TO_QUEUE:
        return {
            "status": "escalated",
            "reason": f"{dependency}_unavailable_queued",
            "failure_mode": "fail_to_queue",
            "message": f"{dependency} is unavailable; action queued for human review",
        }

    # Fallback
    return {
        "status": "denied",
        "reason": f"{dependency}_unavailable",
        "failure_mode": "fail_closed",
        "error": str(error),
    }
