"""Tests for task state machine."""

from uuid import uuid4

import pytest

from aegisvault.orchestration.state_machine import StateMachine, TaskState


def test_valid_transition() -> None:
    """Idle → Classifying is allowed."""
    sm = StateMachine(uuid4())
    status = sm.transition(TaskState.CLASSIFYING)
    assert status.state == TaskState.CLASSIFYING.name


def test_invalid_transition_raises() -> None:
    """Idle → Encrypting is not allowed."""
    sm = StateMachine(uuid4())
    with pytest.raises(ValueError):
        sm.transition(TaskState.ENCRYPTING)


def test_terminal_states_have_no_outbound() -> None:
    """Completed state has no allowed outbound transitions."""
    sm = StateMachine(uuid4(), TaskState.COMPLETED)
    assert not sm.can_transition_to(TaskState.IDLE)
