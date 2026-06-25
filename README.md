# AegisVault

A local-first, privacy-focused content management agent that ingests files from an **Inbox**, classifies them with an LLM, encrypts sensitive content with **AES-256-GCM**, and stores it in a structured **Vault**.

**Core design goals**

- Keep your data on your machine.
- Encrypt before it touches disk in the Vault.
- Use local models by default; cloud connections only when explicitly enabled.
- Run untrusted tooling inside a sandbox with no network access.
- Record every security-relevant action in a tamper-evident audit log.

---

## Table of contents

- [Quick start](#quick-start)
- [Architecture overview](#architecture-overview)
- [Configuration](#configuration)
- [Security model](#security-model)
- [CLI usage](#cli-usage)
- [Container usage](#container-usage)
- [Development](#development)
- [Platform notes](#platform-notes)

---

## Quick start

### 1. Install

```bash
pip install aegisvault[gui]
```

For headless / server use omit `[gui]`:

```bash
pip install aegisvault
```

### 2. Configure

The first run will create a default configuration in your platform config directory:

- Linux: `~/.config/AegisVault/settings.json`
- macOS: `~/Library/Application Support/AegisVault/settings.json`
- Windows: `%APPDATA%\AegisVault\settings.json`

Key paths default to `~/AegisVault/Inbox` and `~/AegisVault/Vault`. You can change them via the GUI or by editing `settings.json`.

### 3. Add a model connection

AegisVault needs a chat-capable model for classification. The GUI can add a connection, or you can create one programmatically via `aegisvault.platform.ConnectionManager`.

Recommended local options:

- [Ollama](https://ollama.com/) running on `http://127.0.0.1:11434/v1`
- [llama.cpp server](https://github.com/ggerganov/llama.cpp/blob/master/examples/server/README.md) with an OpenAI-compatible endpoint
- [vLLM](https://docs.vllm.ai/) on localhost

Cloud providers work only when you explicitly mark them as authorised (`is_cloud_authorized=True`) in the connection settings.

### 4. Run

Headless mode:

```bash
aegisvault --no-tray
```

With system tray (requires `[gui]` extra):

```bash
aegisvault
```

Drop files into the Inbox folder. The pipeline will classify, encrypt, and move them into the Vault automatically.

---

## Architecture overview

```
Inbox
  │
  ▼
FileSystemEvent ──▶ InboxWatcher
  │
  ▼
AegisAgent ──▶ Pipeline (StateMachine)
  │
  ├──▶ Classifier (LLM)
  │      ├── category, sensitivity, summary, disguise_name, extension
  │
  ├──▶ VaultManager (AES-256-GCM encryption)
  │
  ├──▶ TaskStore (SQLite + FTS5 + vector embeddings)
  │
  └──▶ AuditLogger (NDJSON + HMAC-SHA256)
```

Main packages:

| Package | Responsibility |
|---------|----------------|
| `aegisvault.security` | Encryption, key hierarchy, audit log, sandbox, firewall, offline verification, password stores |
| `aegisvault.platform` | Connection models, connection manager, field-level credential sealing |
| `aegisvault.model` | Classifier, embedding providers, OpenAI-compatible provider |
| `aegisvault.orchestration` | Agent, pipeline, state machine, task store |
| `aegisvault.execution` | Inbox watcher, vault manager |
| `aegisvault.presentation` | PyQt6 tray, vault browser, settings/connection dialogs |
| `aegisvault.api` | JSON-RPC protocol and Pydantic schemas |

---

## Configuration

Configuration is managed by `aegisvault.config.AegisConfig` and can be controlled through:

1. `settings.json` (highest precedence after explicit code).
2. Environment variables (Pydantic-Settings, e.g. `AEGISVAULT_SECURITY__MASTER_KEY_PROVIDER=filepassword`).
3. Built-in defaults.

Sensitive fields such as `master_key_password` and `password_store_password` are **never written to disk** by `save_to_file()`.

### Environment variables

| Variable | Example | Meaning |
|----------|---------|---------|
| `AEGISVAULT_PATHS__INBOX` | `/home/user/drop` | Inbox directory |
| `AEGISVAULT_PATHS__VAULT` | `/home/user/vault` | Vault directory |
| `AEGISVAULT_SECURITY__MASTER_KEY_PROVIDER` | `filepassword` | Master-key provider (`filepassword`, `dpapi`, `tpm`) |
| `AEGISVAULT_SECURITY__MASTER_KEY_PASSWORD` | — | Password for the file-password provider |
| `AEGISVAULT_MODEL__BASE_URL` | `http://127.0.0.1:11434/v1` | Default model endpoint |
| `AEGISVAULT_MODEL__MODEL_NAME` | `qwen2.5:7b` | Default model name |

---

## Security model

### Key hierarchy

1. **Master key** — derived from a password (Argon2id), protected by Windows DPAPI, or sealed by the TPM.
2. **Vault key** — derived from the master key with HKDF-SHA256.
3. **File key** — derived from the vault key + per-file salt with Argon2id.

### Encryption format

Encrypted files are written with the following header layout:

```
[1B version][32B salt][12B nonce][ciphertext][16B GCM tag]
```

Writes are atomic: data is written to a temporary file and renamed into place. Decryption authenticates the full ciphertext before overwriting the destination.

### Network policy

Sensitive operations require a **trusted local connection** (`127.0.0.1`, `::1`, or `localhost`). Cloud providers are used only when the connection is explicitly marked `is_cloud_authorized=True` **and** `security.cloud_fallback_enabled=True` is set.

Optionally enable `security.enforce_offline_policy=True` to raise a `SecurityPolicyError` when sensitive operations are invoked while the process has active outbound client connections.

### Sandboxing

- **Linux**: `bubblewrap` (`bwrap`) with `--unshare-all`, network disabled, and a minimal read-only filesystem.
- **Windows**: AppContainer-based isolation via PowerShell/Win32 helpers.

Untrusted external tools such as `keepassxc-cli` or `pass` run inside the sandbox.

### Audit log

Every security-relevant event is appended to an NDJSON log. Each line is protected by HMAC-SHA256 with a key stored separately from the log. The log can be verified offline for tampering.

---

## CLI usage

```bash
# Show help
aegisvault --help

# Run headless (no system tray)
aegisvault --no-tray
```

The CLI launches an `AegisAgent` that monitors the Inbox and processes files automatically.

---

## Container usage

A headless Docker image is available. The GUI extra is excluded to keep the image small, and the image runs as an unprivileged `aegisvault` user (UID 1000).

```bash
docker build -t aegisvault .
docker run --rm -it \
  --user $(id -u):$(id -g) \
  -v /path/to/inbox:/inbox \
  -v /path/to/vault:/vault \
  -e AEGISVAULT_PATHS__INBOX=/inbox \
  -e AEGISVAULT_PATHS__VAULT=/vault \
  aegisvault --no-tray
```

**Notes:**

- `bubblewrap` is installed in the image, but the Linux sandbox requires the container runtime to allow user namespaces (`--security-opt seccomp=unconfined` or an equivalent policy).
- Mount host directories with the same UID/GID as the container user (1000:1000) so the unprivileged process can read and write the Inbox and Vault.
- The configuration directory (`~/.config/AegisVault/` inside the container) should be mounted if you need to persist settings across container restarts, or use environment variables (`AEGISVAULT_PATHS__INBOX`, etc.) instead.

---

## Development

```bash
poetry install --with dev
poetry run pytest
poetry run ruff check .
poetry run mypy aegisvault
```

For GUI work also install the `gui` extra:

```bash
poetry install --with dev,gui --extras gui
```

### Running the test suite

```bash
poetry run pytest
```

Some tests target Windows-only APIs and are skipped on Linux; integration tests that require external tools such as `keepassxc-cli` or `pass` are deselected by default.

---

## Platform notes

- **Windows**: DPAPI and TPM master-key providers are available. Windows Hello verification is supported.
- **Linux**: File-password provider and optional TPM2 integration are available. The sandbox requires `bubblewrap`.
- **macOS**: File-password provider works; DPAPI/TPM providers are not supported.

---

## License

See the repository for license details.

## Phase 1 Goal

Inbox → classify → encrypt → Vault pipeline with local offline model.
