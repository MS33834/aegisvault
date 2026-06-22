"""Watch Inbox directory for new files."""

from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from aegisvault.api.schemas import FileEvent


class InboxEventHandler(FileSystemEventHandler):
    """Handle file creation events in the Inbox."""

    def __init__(self, callback: Callable[[FileEvent], None]) -> None:
        self.callback = callback

    def on_created(self, event: FileSystemEvent) -> None:
        """Process created file events."""
        if event.is_directory:
            return
        path = Path(str(event.src_path))
        file_event = FileEvent(
            event_id=uuid4(),
            source_path=path,
            event_type="created",
        )
        self.callback(file_event)


class InboxWatcher:
    """Watchdog-based Inbox watcher."""

    def __init__(self, inbox_path: Path, callback: Callable[[FileEvent], None]) -> None:
        self.inbox_path = inbox_path
        self.callback = callback
        self.observer = Observer()
        self.handler = InboxEventHandler(callback)

    def start(self) -> None:
        """Start watching."""
        self.inbox_path.mkdir(parents=True, exist_ok=True)
        self.observer.schedule(self.handler, str(self.inbox_path), recursive=False)  # type: ignore[no-untyped-call]
        self.observer.start()  # type: ignore[no-untyped-call]

    def stop(self) -> None:
        """Stop watching."""
        self.observer.stop()  # type: ignore[no-untyped-call]
        self.observer.join()
