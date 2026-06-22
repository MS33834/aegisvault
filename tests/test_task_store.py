"""Tests for TaskStore persistence."""

import sqlite3
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aegisvault.orchestration.state_machine import TaskState
from aegisvault.orchestration.task_store import TaskStore


@pytest.fixture
def task_store(tmp_path: Path) -> TaskStore:
    """Isolated task store for tests."""
    return TaskStore(tmp_path / "tasks.db")


def test_list_recent_returns_created_tasks(task_store: TaskStore) -> None:
    """list_recent returns tasks ordered by most recent update."""
    task_id = uuid4()
    source = Path("/tmp/file.txt")
    task_store.create(task_id, source)

    recent = task_store.list_recent(limit=10)

    assert len(recent) == 1
    assert recent[0].task_id == task_id
    assert recent[0].state == TaskState.IDLE.name
    assert recent[0].source_path == source


def test_list_recent_orders_by_updated_at(task_store: TaskStore) -> None:
    """list_recent orders tasks by updated_at descending."""
    first_id = uuid4()
    second_id = uuid4()
    task_store.create(first_id, Path("/tmp/first.txt"))
    task_store.create(second_id, Path("/tmp/second.txt"))

    recent = task_store.list_recent(limit=10)

    assert [task.task_id for task in recent] == [second_id, first_id]


def test_list_recent_respects_limit(task_store: TaskStore) -> None:
    """list_recent respects the limit parameter."""
    for i in range(5):
        task_store.create(uuid4(), Path(f"/tmp/file{i}.txt"))

    recent = task_store.list_recent(limit=3)

    assert len(recent) == 3


def test_list_recent_includes_state_and_message(task_store: TaskStore) -> None:
    """list_recent surfaces the latest state and message."""
    task_id = uuid4()
    task_store.create(task_id, Path("/tmp/file.txt"))
    task_store.update_state(task_id, TaskState.ENCRYPTING, "working")

    recent = task_store.list_recent(limit=1)

    assert len(recent) == 1
    assert recent[0].state == TaskState.ENCRYPTING.name
    assert recent[0].message == "working"


def test_list_recent_source_path_is_optional(task_store: TaskStore) -> None:
    """list_recent handles tasks with no source_path."""
    task_id = uuid4()
    conn = sqlite3.connect(task_store.db_path)
    conn.execute(
        "INSERT INTO tasks (task_id, state, source_path) VALUES (?, ?, ?)",
        (str(task_id), TaskState.IDLE.name, None),
    )
    conn.commit()
    conn.close()

    recent = task_store.list_recent(limit=1)

    assert len(recent) == 1
    assert recent[0].task_id == task_id
    assert recent[0].source_path is None


def test_load_incomplete_unchanged(task_store: TaskStore) -> None:
    """load_incomplete continues to exclude terminal states."""
    incomplete_id = uuid4()
    completed_id = uuid4()
    task_store.create(incomplete_id, Path("/tmp/incomplete.txt"))
    task_store.create(completed_id, Path("/tmp/completed.txt"))
    task_store.update_state(completed_id, TaskState.COMPLETED)

    incomplete = task_store.load_incomplete()

    assert len(incomplete) == 1
    assert UUID(incomplete[0]["task_id"]) == incomplete_id


def test_counts_by_state_returns_empty_dict_for_empty_store(task_store: TaskStore) -> None:
    """counts_by_state returns an empty dict when no tasks exist."""
    assert task_store.counts_by_state() == {}


def test_counts_by_state_groups_by_state(task_store: TaskStore) -> None:
    """counts_by_state aggregates tasks by their current state."""
    idle_id = uuid4()
    completed_id = uuid4()
    failed_id = uuid4()
    task_store.create(idle_id, Path("/tmp/idle.txt"))
    task_store.create(completed_id, Path("/tmp/done.txt"))
    task_store.update_state(completed_id, TaskState.COMPLETED)
    task_store.create(failed_id, Path("/tmp/failed.txt"))
    task_store.update_state(failed_id, TaskState.FAILED)

    counts = task_store.counts_by_state()

    assert counts[TaskState.IDLE.name] == 1
    assert counts[TaskState.COMPLETED.name] == 1
    assert counts[TaskState.FAILED.name] == 1


def test_list_active_returns_only_non_terminal_states(task_store: TaskStore) -> None:
    """list_active returns IDLE/CLASSIFYING/ENCRYPTING/INDEXING tasks."""
    idle_id = uuid4()
    completed_id = uuid4()
    failed_id = uuid4()
    quarantined_id = uuid4()
    task_store.create(idle_id, Path("/tmp/idle.txt"))
    task_store.create(completed_id, Path("/tmp/done.txt"))
    task_store.update_state(completed_id, TaskState.COMPLETED)
    task_store.create(failed_id, Path("/tmp/failed.txt"))
    task_store.update_state(failed_id, TaskState.FAILED)
    task_store.create(quarantined_id, Path("/tmp/bad.txt"))
    task_store.update_state(quarantined_id, TaskState.QUARANTINED)

    active = task_store.list_active(limit=10)

    assert len(active) == 1
    assert active[0].task_id == idle_id


def test_list_active_orders_by_updated_at(task_store: TaskStore) -> None:
    """list_active orders tasks by most recent update."""
    first_id = uuid4()
    second_id = uuid4()
    task_store.create(first_id, Path("/tmp/first.txt"))
    task_store.create(second_id, Path("/tmp/second.txt"))

    active = task_store.list_active(limit=10)

    assert [task.task_id for task in active] == [second_id, first_id]


def test_list_active_respects_limit(task_store: TaskStore) -> None:
    """list_active respects the limit parameter."""
    for i in range(5):
        task_store.create(uuid4(), Path(f"/tmp/file{i}.txt"))

    active = task_store.list_active(limit=3)

    assert len(active) == 3


def test_list_attention_returns_failed_and_quarantined(task_store: TaskStore) -> None:
    """list_attention returns only FAILED and QUARANTINED tasks."""
    idle_id = uuid4()
    failed_id = uuid4()
    quarantined_id = uuid4()
    task_store.create(idle_id, Path("/tmp/idle.txt"))
    task_store.create(failed_id, Path("/tmp/failed.txt"))
    task_store.update_state(failed_id, TaskState.FAILED, "broken")
    task_store.create(quarantined_id, Path("/tmp/bad.txt"))
    task_store.update_state(quarantined_id, TaskState.QUARANTINED, "suspicious")

    attention = task_store.list_attention(limit=10)

    assert len(attention) == 2
    assert {task.task_id for task in attention} == {failed_id, quarantined_id}
    assert attention[0].state in {TaskState.FAILED.name, TaskState.QUARANTINED.name}


def test_list_attention_orders_by_updated_at(task_store: TaskStore) -> None:
    """list_attention orders tasks by most recent update."""
    first_id = uuid4()
    second_id = uuid4()
    task_store.create(first_id, Path("/tmp/first.txt"))
    task_store.update_state(first_id, TaskState.FAILED)
    task_store.create(second_id, Path("/tmp/second.txt"))
    task_store.update_state(second_id, TaskState.QUARANTINED)

    attention = task_store.list_attention(limit=10)

    assert [task.task_id for task in attention] == [second_id, first_id]


def test_list_attention_respects_limit(task_store: TaskStore) -> None:
    """list_attention respects the limit parameter."""
    for i in range(5):
        task_id = uuid4()
        task_store.create(task_id, Path(f"/tmp/file{i}.txt"))
        task_store.update_state(task_id, TaskState.FAILED)

    attention = task_store.list_attention(limit=3)

    assert len(attention) == 3
