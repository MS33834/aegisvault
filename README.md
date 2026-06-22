# AegisVault

Local private content management agent.

## Development

```bash
poetry install --with dev
poetry run pytest
poetry run ruff check .
poetry run mypy aegisvault
```

The GUI components require the `gui` extra:

```bash
pip install 'aegisvault[gui]'
# or with Poetry
poetry install --with dev,gui --extras gui
```

## Phase 1 Goal

Inbox → classify → encrypt → Vault pipeline with local offline model.
