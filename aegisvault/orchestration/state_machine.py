"""Task state machine for AegisVault."""

from enum import Enum, auto
from uuid import UUID

from aegisvault.api.schemas import TaskStatus


class TaskState(Enum):
    """States of a file processing task."""

    IDLE = auto()
    CLASSIFYING = auto()
    ENCRYPTING = auto()
    INDEXING = auto()
    COMPLETED = auto()
    FAILED = auto()
    QUARANTINED = auto()


class StateMachine:
    """Simple finite state machine for tasks."""

    ALLOWED_TRANSITIONS: dict[TaskState, set[TaskState]] = {
        TaskState.IDLE: {TaskState.CLASSIFYING},
        TaskState.CLASSIFYING: {TaskState.ENCRYPTING, TaskState.QUARANTINED, TaskState.FAILED},
        TaskState.ENCRYPTING: {TaskState.INDEXING, TaskState.FAILED},
        TaskState.INDEXING: {TaskState.COMPLETED, TaskState.FAILED},
        TaskState.COMPLETED: set(),
        TaskState.FAILED: set(),
        TaskState.QUARANTINED: set(),
    }

    def __init__(self, task_id: UUID, initial: TaskState = TaskState.IDLE) -> None:
        self.task_id = task_id
        self.state = initial

    def transition(self, new_state: TaskState) -> TaskStatus:
        """Transition to a new state if allowed."""
        if new_state not in self.ALLOWED_TRANSITIONS[self.state]:
            raise ValueError(
                f"Invalid transition from {self.state.name} to {new_state.name}"
            )
        self.state = new_state
        return TaskStatus(task_id=self.task_id, state=self.state.name)

    def can_transition_to(self, new_state: TaskState) -> bool:
        """Check if transition is allowed."""
        return new_state in self.ALLOWED_TRANSITIONS[self.state]
