# AegisVault Tauri 技术评估报告

> **文档归属**: Phase 3.4 · 3.5 — Tauri 前端技术选型与迁移路径设计
>
> **决策依据**: ADR-001（Phase 1 决策 #2: "Re-evaluate Tauri in Phase 3"）
>
> **分析日期**: 2026-06-25

---

## 目录

1. [技术对比矩阵](#1-技术对比矩阵)
2. [Tauri 架构设计](#2-tauri-架构设计)
3. [迁移成本评估](#3-迁移成本评估)
4. [原型方案](#4-原型方案)
5. [分阶段迁移路线图](#5-分阶段迁移路线图)
6. [风险与缓解](#6-风险与缓解)

---

## 1. 技术对比矩阵

### 1.1 整体对比

| 维度 | PyQt6 (当前) | Tauri v2 | Electron | Flutter Desktop |
|------|-------------|----------|----------|-----------------|
| **安装包体积** | ~200-250 MB<br>(含 Python 运行时 + PyQt6 + 依赖) | ~8-12 MB<br>(Rust 二进制 + WebView) | ~150-180 MB<br>(Chromium + Node.js) | ~40-60 MB<br>(Flutter Engine) |
| **运行时内存** | ~100-120 MB<br>(Python 解释器 + Qt Widgets) | ~50-70 MB<br>(Rust 后端 + WebView 渲染) | ~200-300 MB<br>(Chromium 多进程) | ~70-100 MB<br>(Flutter Engine) |
| **启动速度** | 慢 (1.5-3s)<br>(Python 解释器初始化 + PyQt6 加载) | 快 (0.5-1s)<br>(原生二进制，WebView 预热) | 慢 (2-4s)<br>(Chromium 启动) | 中 (1-2s)<br>(Dart VM + Engine) |
| **跨平台** | ✅ Windows / macOS / Linux | ✅ Windows / macOS / Linux<br>+ 移动端 (v2 beta) | ✅ Windows / macOS / Linux | ✅ Windows / macOS / Linux<br>+ iOS / Android |
| **Rust 后端集成** | ❌ 无原生 Rust 集成<br>需通过 FFI/PyO3 桥接 | ✅ **原生 Rust 后端**<br>直接调用，零开销 | ❌ Node.js 后端<br>Rust 需通过 napi-rs | ❌ Dart 后端<br>Rust 需通过 FFI |
| **安全沙箱** | 手动实现<br>(bubblewrap / AppContainer 由 Python 侧管理) | **内置 CSP + IPC 隔离**<br>WebView 沙箱 + Rust 侧系统隔离 | 手动配置<br>(Chromium sandbox) | 手动配置 |
| **生态系统** | Python<br>(PyPI 丰富但 GUI 生态窄) | Rust + JS/TS<br>(crates.io + npm) | Node.js + npm<br>(最大的 Web 生态) | Dart + pub.dev<br>(Google 维护) |
| **前端技术** | Qt Widgets (C++ 绑定) | **Web 技术栈**<br>(HTML/CSS/JS + React/Vue/Svelte) | Web 技术栈<br>(HTML/CSS/JS) | Dart Widgets<br>(自绘引擎) |
| **热更新** | ❌ 不支持 | ❌ 不支持 (App Store 策略) | ✅ 支持 (electron-updater) | ❌ 不支持 |
| **GPU 加速** | ✅ Qt 原生硬件加速 | ⚠️ WebView 限制<br>(WebGL/Canvas) | ✅ Chromium 硬件加速 | ✅ Skia 引擎 |
| **IPC 性能** | N/A (单进程) | **高** (Rust ↔ JS 命令调用) | 中 (主进程 ↔ 渲染进程) | N/A (单进程) |
| **TypeScript 支持** | ❌ | ✅ (前端) | ✅ | ❌ (Dart) |
| **代码签名** | 手动 (Python 打包工具链) | **内置** (tauri-bundler 签名) | 手动 | 手动 |

### 1.2 与当前架构的匹配度

| 需求 | PyQt6 (当前) | Tauri | 匹配度分析 |
|------|-------------|-------|-----------|
| 系统托盘 | ✅ `QSystemTrayIcon` | ✅ `tauri-plugin-tray` | Tauri tray API 成熟，支持菜单和事件 |
| 多窗口对话框 | ✅ `QDialog` / `QWizard` | ✅ 多 WebView 窗口 | Tauri v2 原生支持多窗口管理 |
| 文件系统浏览 | ✅ `QFileDialog` | ✅ WebView + Rust `tauri-plugin-dialog` | Tauri 提供原生文件对话框 |
| 表格/列表视图 | ✅ `QTableWidget` / `QListWidget` | ✅ HTML `<table>` + CSS Grid / 虚拟滚动 | 需自行实现，但 Web 生态有成熟方案 |
| 进度条 | ✅ `QProgressBar` | ✅ HTML `<progress>` / CSS | 简单，Web 原生支持 |
| SQLite 访问 | ✅ Python sqlite3 (直接) | ⚠️ Rust rusqlite (重写) 或 sidecar | 核心风险点，见第 2 节 |
| AES-256-GCM 加密 | ✅ cryptography 库 | ✅ Rust `aes-gcm` crate | Rust 侧可直接复用算法逻辑 |
| LLM API 调用 | ✅ httpx → OpenAI-compatible | ✅ Rust reqwest / sidecar Python | 两种方案，见第 2 节 |
| 平台特定 API | ✅ Python ctypes / win32api | ✅ Rust winapi / windows-rs | Rust 平台集成能力更优 |
| Windows Hello | ✅ ctypes 调用 | ✅ Rust windows-rs 直接调用 | Tauri 方案更原生、更可靠 |

### 1.3 决策矩阵

基于 AegisVault 的核心设计原则评估：

| 原则 | PyQt6 | Tauri | 结论 |
|------|-------|-------|------|
| **Local-First** | ✅ | ✅ | 两者皆可 |
| **Encrypt Before Persist** | ✅ Python cryptography | ✅ Rust crypto crates | Rust 加密生态更成熟 |
| **Zero-Trust Model** | ✅ | ✅ | Tauri CSP 提供额外隔离层 |
| **Defense in Depth** | ⚠️ 手动 | ✅ **内置沙箱 + CSP** | Tauri 显著优势 |
| **Minimal Supply Chain** | ⚠️ PyQt6 ~200MB 依赖链 | ✅ **~10MB** 最小二进制 | Tauri 压倒性优势 |
| **安全审计简易度** | 中 (Python 可读性强) | 高 (无 JIT 运行时，静态链接) | Tauri 优势 |

---

## 2. Tauri 架构设计

### 2.1 整体分层架构

```
┌─────────────────────────────────────────────────────┐
│                  Tauri Frontend                       │
│  ┌───────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ System Tray   │  │ Vault    │  │ Settings /   │  │
│  │ (Tray App)    │  │ Browser  │  │ Connection   │  │
│  └───────┬───────┘  └────┬─────┘  └──────┬───────┘  │
│          │               │               │           │
│  ┌───────┴───────────────┴───────────────┴───────┐  │
│  │         React/Vue/Svelte UI Layer              │  │
│  │         (HTML + CSS + TypeScript)              │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │ IPC (invoke)                  │
├──────────────────────┼──────────────────────────────┤
│                Tauri Core (Rust)                     │
│  ┌───────────────────┴───────────────────────────┐  │
│  │         Tauri Commands (API Layer)             │  │
│  │  - list_vault_items                            │  │
│  │  - decrypt_item                                │  │
│  │  - get_task_status                             │  │
│  │  - manage_connections                          │  │
│  └───────────┬───────────────────┬───────────────┘  │
│              │                   │                   │
│  ┌───────────┴───────┐ ┌────────┴──────────────┐   │
│  │  Strategy A:       │ │  Strategy B:           │   │
│  │  全 Rust 加密层   │ │  Rust 壳 + Python      │   │
│  │  (crypto/keytree/  │ │  Sidecar (bridge)      │   │
│  │   sandbox 重写)    │ │  通过 JSON-RPC         │   │
│  └───────────────────┘ └───────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### 2.2 Rust 后端层：两种策略对比

#### 策略 A: 全 Rust 重写

**方案描述**: 将全部业务逻辑（security / model / orchestration / platform）用 Rust 重写。

| 维度 | 评估 |
|------|------|
| **加密层** (crypto.py, keytree.py, master_key.py, secure_storage.py) | Rust 有成熟的 `aes-gcm`, `argon2`, `hkdf` crate。cryptography 库的 API 到 Rust 几乎 1:1 映射。总代码量约 2,000 行 Python → 约 2,500 行 Rust (含类型标注和安全检查)。 |
| **分类器** (classifier.py, provider.py) | LLM API 调用可用 `reqwest` 直接实现。但 sentence-transformers 嵌入模型无 Rust 等价物。若保留语义搜索，此块必须保留 Python。代码量约 930 行 Python。 |
| **任务编排** (pipeline.py, state_machine.py, task_store.py) | 复杂状态机 + SQLite 操作。Rust 可用 `rusqlite` 重写，但 1,014 行的 task_store.py 翻译成本高。 |
| **平台集成** (manager.py, sandbox.py, win32_appcontainer.py) | Rust 的 winapi/windows-rs 生态比 Python ctypes 更健壮。bubblewrap 调用逻辑可直接翻译。 |
| **优势** | 无 Python 运行时依赖、最小二进制体积 (~10MB)、类型安全、卓越性能、可静态链接 |
| **劣势** | 开发成本极高 (~16-20 周)、sentence-transformers 无替代、社区生态窄、Python 相关工具链 (KeePassXC-cli 集成、watchdog) 需全部重写 |
| **工时估算** | 16-20 周 (1 人) |

#### 策略 B: Rust 壳 + Python Sidecar（推荐）

**方案描述**: Tauri 作为前端壳，核心 Python 业务逻辑以 sidecar 子进程运行，通过 JSON-RPC over stdio 通信。安全关键路径逐步移植到 Rust。

```
┌─────────────────────┐     JSON-RPC (stdio)     ┌─────────────────────┐
│   Tauri (Rust 壳)   │◄────────────────────────►│  Python Sidecar     │
│                     │                           │                     │
│  - WebView UI       │   → classify_file        │  - LLM 分类器        │
│  - Tray 管理        │   → encrypt_file          │  - 加密/解密         │
│  - 文件对话框       │   → search_vault          │  - 任务存储          │
│  - 安全沙箱 (CSP)   │   → manage_connections    │  - 平台连接管理       │
│  - 平台原生集成     │   ← result / error        │  - sentence-transform│
│                     │                           │  - KeePassXC 集成    │
└─────────────────────┘                           └─────────────────────┘
```

| 维度 | 评估 |
|------|------|
| **迁移速度** | 现有 Python 代码几乎零改动，仅需添加 JSON-RPC 适配层 |
| **二进制体积** | Tauri 壳 ~10MB + Python 打包 (如 PyInstaller) ~60-80MB，共 ~90MB。对比当前 PyQt6 的 ~200MB，仍有 55% 减少 |
| **开发成本** | Phase A 仅需 4 周搭建 sidecar 通信 + 最小前端 |
| **风险** | IPC 延迟 (JSON-RPC over stdio 通常 <1ms)、Python 进程生命周期管理 |
| **灵活性** | 可渐进式地将安全关键路径（crypto/keytree/sandbox）移植到 Rust，Python 逐步缩减 |
| **工时估算** | 4 周 (Phase A 原型) + 8 周 (Phase B 对等) |

#### 推荐策略: 策略 B

**理由**:

1. **低风险迁移**: 现有 7,628 行核心业务代码全部保留，验证成本最低
2. **渐进演进**: 安全关键路径（crypto/keytree/sandbox）可后续用 Rust 重写，Python 逐步退役
3. **ML 依赖保留**: sentence-transformers 无 Rust 等价物，策略 B 自然保留此能力
4. **资源经济**: 相比全 Rust 重写的 16-20 周，策略 B 仅需 12 周达全功能对等
5. **用户无感**: Tauri 壳与 PyQt6 可并行运行，现有用户不受影响

---

## 3. 迁移成本评估

### 3.1 GUI 模块逐文件映射

基于实际代码分析（共 5 个 GUI 模块，2,397 行）：

| 当前文件 (PyQt6) | 行数 | 核心组件 | Tauri 前端组件 (React) | 迁移复杂度 | 工时 |
|---|---|---|---|---|---|
| `tray.py` | 734 | `TrayApplication` (系统托盘)<br>`SearchVaultDialog` (Vault 搜索) | `<TrayApp>` + `<SearchDialog>`<br>使用 `tauri-plugin-tray` | ⭐⭐⭐ 中 | 3d |
| `vault_browser.py` | 837 | `VaultBrowser` (表格/网格视图)<br>批量操作、分类树、预览面板 | `<VaultBrowser>`<br>使用 react-table / react-virtuoso<br>HTML5 `<canvas>` 图片预览 | ⭐⭐⭐⭐ 高 | 5d |
| `connection_dialog.py` | 278 | `ConnectionEditDialog` (表单)<br>`ConnectionManagerDialog` (表格管理) | `<ConnectionManager>`<br>表单组件 + react-table | ⭐⭐ 低 | 2d |
| `settings_dialog.py` | 236 | `SettingsDialog` (多分组配置表单) | `<Settings>`<br>分组表单 + 文件路径选择 | ⭐⭐ 低 | 1.5d |
| `first_run_wizard.py` | 310 | `FirstRunWizard` (5 步向导)<br>含密码强度检测、LLM 连接测试 | `<SetupWizard>`<br>使用 xstate 状态机管理步骤<br>密码强度纯前端计算 | ⭐⭐⭐ 中 | 2.5d |
| **总计** | **2,397** | | | | **~14d** |

### 3.2 核心业务逻辑保留策略

代码库现状（基于实际 `wc -l` 统计）：

| 模块 | 行数 | 保留策略 | 说明 |
|------|------|----------|------|
| **security/** | 4,303 | **阶段 A: 保留 Python**<br>阶段 C: 优先移植 crypto/keytree | 加密核心，移植后安全性提升最大 |
| `crypto.py` (97行) | 轻量 | 优先移植 | AES-256-GCM 加密/解密，Rust `aes-gcm` 直接等价 |
| `keytree.py` (40行) | 轻量 | 优先移植 | 三级密钥派生，Rust `hkdf` 直接等价 |
| `master_key.py` (897行) | 重 | C 阶段移植 | Windows DPAPI/TPM/Hello 集成，Rust winapi 方案更健壮 |
| `password_store.py` (786行) | 重 | 保留 Python | KeePassXC-cli/pass 集成，依赖外部 CLI，无移植收益 |
| `sandbox.py` (555行) | 中 | C 阶段移植 | bubblewrap 沙箱，Rust 重写更简洁 |
| `win32_appcontainer.py` (528行) | 中 | C 阶段移植 | Windows AppContainer，Rust winapi 更可靠 |
| `audit_log.py` (426行) | 中 | C 阶段移植 | HMAC 审计日志，Rust 有原生支持 |
| **model/** | 930 | **长期保留 Python** | |
| `classifier.py` (655行) | 重 | **保留 Python** | LLM prompt 构建 + 响应解析，无移植必要 |
| `provider.py` (167行) | 中 | **保留 Python** | OpenAI-compatible 客户端，可用 Rust reqwest 替代 |
| `embedding.py` (86行) | 轻 | **永久保留 Python** | sentence-transformers，Rust 无等价物 |
| **orchestration/** | 1,509 | 阶段 A-B: 保留 Python | |
| `task_store.py` (1,014行) | 重 | A-B: Python, C: Rust | SQLite 操作重写成本高 |
| `pipeline.py` (186行) | 中 | A-B: Python | 流程编排，逻辑简单 |
| `agent.py` (260行) | 中 | A-B: Python | Agent 调度 |
| **platform/** | 367 | A-B: 保留 Python | 连接管理逻辑，非性能关键 |
| **execution/** | 173 | A-B: 保留 Python | Inbox 监听 + Vault 管理 |
| **api/** | 155 | 保持不变 | Pydantic schema，被 JSON-RPC 直接引用 |

**保留总量**: ~6,700 行 Python (阶段 A-B) → ~3,000 行 Python (阶段 C，仅保留 ML + 外部工具集成)

### 3.3 预估工期

| 阶段 | 工作内容 | 工时 | 说明 |
|------|----------|------|------|
| **3.4 选型与原型** | 本文档 + 最小原型 | 已完成 | 本次交付 |
| **阶段 A 并行运行** | Tauri 壳 + Python sidecar + 托盘 + 状态 | 4 周 | 2 人并行 |
| **阶段 B 功能对等** | 4 个模块迁移 + 测试 | 8 周 | 2 人并行 |
| **阶段 C 全 Rust 核心** | crypto/keytree/sandbox/task_store 移植 | 12 周 | 2 人 |
| **总计** | | **24 周** | 阶段 B 结束即可发布 |

| 对比项 | 策略 A (全 Rust 重写) | 策略 B (Rust 壳 + Python) |
|--------|----------------------|--------------------------|
| 总工期 | 16-20 周 | 12 周 (到功能对等) + 12 周 (全 Rust 核心) = 24 周 |
| 首次可发布 | 16 周后 | **4 周后** (最小可用) |
| 风险 | 高 (全部重写) | 低 (渐进迁移) |
| ML 能力 | ❌ 丢失 | ✅ 完整保留 |

---

## 4. 原型方案

### 4.1 最小可行的 Tauri 项目结构

```
/workspace/aegisvault/                          # 现有项目根目录
├── src-tauri/                                   # Tauri Rust 后端壳
│   ├── Cargo.toml                               # Rust 依赖声明
│   ├── tauri.conf.json                          # Tauri 配置 (窗口/权限/插件)
│   ├── icons/                                   # 应用图标 (多尺寸 .png)
│   ├── capabilities/                            # Tauri v2 权限声明
│   │   └── default.json                         # 默认权限 (window/dialog/fs)
│   ├── src/
│   │   ├── main.rs                              # 入口: 启动 Tauri + 注册命令 + 管理 Python sidecar
│   │   ├── commands.rs                          # Tauri commands (Rust ↔ JS IPC)
│   │   ├── sidecar.rs                           # Python 子进程管理 + JSON-RPC 通信
│   │   └── crypto.rs                            # (阶段 C) 本机加密模块
│   └── binaries/                                # Sidecar 二进制存放目录
│       └── aegisvault-sidecar-{target-triple}   # Python 打包的 sidecar (PyInstaller)
├── src/                                         # 前端 Web 应用 (React/Vue/Svelte)
│   ├── index.html                               # HTML 入口
│   ├── main.tsx                                 # React 入口
│   ├── App.tsx                                  # 根组件 (路由/布局)
│   ├── components/
│   │   ├── TrayMenu.tsx                         # 托盘菜单组件
│   │   ├── VaultBrowser.tsx                     # 保险库浏览器
│   │   ├── ConnectionManager.tsx                # 连接管理器
│   │   ├── Settings.tsx                         # 设置页面
│   │   └── SetupWizard.tsx                      # 首次运行向导
│   ├── hooks/
│   │   ├── useRpc.ts                            # JSON-RPC 调用 hook
│   │   ├── useVaultItems.ts                     # Vault 数据查询 hook
│   │   └── useConnectionStatus.ts               # 连接状态 hook
│   ├── lib/
│   │   └── rpc-client.ts                        # JSON-RPC 客户端 (Rust ↔ Python)
│   └── styles/
│       └── global.css                           # 全局样式 + 暗色主题
├── aegisvault/                                  # 现有 Python 代码 (不变)
│   ├── security/                                # (阶段 C 逐步迁移到 Rust)
│   ├── model/                                   # (ML 相关长期保留)
│   ├── orchestration/                           # (阶段 A-B 保留)
│   ├── platform/
│   ├── execution/
│   └── api/
│       └── jsonrpc_server.py                    # [新增] JSON-RPC 服务端 (stdio)
├── tests/                                       # 现有测试 (不变)
├── pyproject.toml                               # 现有 Python 包配置
├── package.json                                 # [新增] 前端依赖 (React, TypeScript 等)
└── tsconfig.json                                # [新增] TypeScript 配置
```

### 4.2 关键文件内容框架

#### `src-tauri/Cargo.toml` (框架)

```toml
[package]
name = "aegisvault"
version = "0.4.0"
edition = "2021"

[dependencies]
tauri = { version = "2", features = ["tray-icon"] }
tauri-plugin-dialog = "2"
tauri-plugin-shell = "2"      # Python sidecar 管理
tauri-plugin-fs = "2"
tauri-plugin-notification = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
# 阶段 C 新增:
# aes-gcm = "0.10"
# argon2 = "0.5"
# rusqlite = { version = "0.31", features = ["bundled"] }
```

#### `src-tauri/src/main.rs` (框架)

```rust
// 核心职责:
// 1. 启动 Tauri 应用
// 2. 管理 Python sidecar 生命周期
// 3. 注册 Tauri commands

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .setup(|app| {
            // 启动 Python sidecar (通过 tauri-plugin-shell)
            // 连接 JSON-RPC stdio 通道
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::rpc_call,           // 通用 JSON-RPC 调用
            commands::get_tray_status,    // 托盘状态查询
            commands::open_inbox,         // 打开 Inbox 目录
        ])
        .run(tauri::generate_context!())
        .expect("error while running AegisVault");
}
```

#### `src-tauri/src/sidecar.rs` (框架)

```rust
// Python 子进程管理器
//
// 职责:
// - 启动 Python sidecar 进程 (PyInstaller 打包的 aegisvault-sidecar)
// - 建立 JSON-RPC over stdio 双向通信
// - 心跳检测与自动重启
// - 请求/响应匹配 (JSON-RPC id 关联)
//
// 通信协议:
// Request:  {"jsonrpc": "2.0", "id": 1, "method": "classify_file", "params": {...}}
// Response: {"jsonrpc": "2.0", "id": 1, "result": {...}}
// Error:    {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "..."}}
```

#### `src-tauri/src/commands.rs` (框架)

```rust
// Tauri Commands - 前端可调用的 Rust 函数
//
// 每个 command 对应一个前端 invoke() 调用:
//
// #[tauri::command]
// async fn rpc_call(method: String, params: Value) -> Result<Value, String> {
//     // 将调用转发到 Python sidecar via JSON-RPC
//     sidecar::call(method, params).await
// }
//
// #[tauri::command]
// async fn get_tray_status() -> Result<TrayStatus, String> {
//     // 聚合 Vault 状态、连接状态、任务数
// }

#[derive(serde::Serialize)]
struct TrayStatus {
    vault_item_count: u32,
    connection_status: String,  // "online" | "offline"
    active_tasks: u32,
    vault_size: String,         // "128.5 MB"
}
```

#### `aegisvault/api/jsonrpc_server.py` (框架，新增文件)

```python
"""JSON-RPC 2.0 服务端，通过 stdio 与 Tauri sidecar 通信。

本模块不依赖 PyQt6，仅依赖 aegisvault.api.schemas 和核心业务逻辑。
在 PyInstaller 打包时作为独立入口点。
"""

import sys
import json
import asyncio
from typing import Any


class JsonRpcServer:
    """JSON-RPC 2.0 over stdio 服务端。

    读取 stdin 的 JSON-RPC 请求，处理后写入 stdout。
    支持的方法:
      - classify_file(path, connection_id) -> ClassificationResult
      - encrypt_file(path, vault_key, salt) -> VaultPath
      - search_vault(keyword, filters) -> list[SearchResult]
      - get_task_status(task_id) -> TaskStatus
      - manage_connections(action, params) -> ConnectionResult
      - health_check() -> {"status": "ok", "version": "..."}
    """

    def __init__(self) -> None:
        self._methods: dict[str, Any] = {}
        self._register_methods()

    def _register_methods(self) -> None:
        """注册所有可调用的 JSON-RPC 方法."""
        # 延迟导入以避免循环依赖
        self._methods = {
            "health_check": self._handle_health_check,
            "classify_file": self._handle_classify,
            "search_vault": self._handle_search,
            "get_task_status": self._handle_task_status,
            # ... 其他方法
        }

    async def run(self) -> None:
        """主循环: 逐行读取 stdin，处理并写入 stdout."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(
            lambda: protocol, sys.stdin
        )

        while True:
            line = await reader.readline()
            if not line:
                break
            response = await self._handle_request(line.decode().strip())
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

    async def _handle_request(self, raw: str) -> dict[str, Any]:
        """解析并处理单个 JSON-RPC 请求."""
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            return {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}

        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")

        handler = self._methods.get(method)
        if handler is None:
            return {"jsonrpc": "2.0", "error": {"code": -32601, "message": f"Method not found: {method}"}, "id": req_id}

        try:
            result = await handler(**params) if asyncio.iscoroutinefunction(handler) else handler(**params)
            return {"jsonrpc": "2.0", "result": result, "id": req_id}
        except Exception as exc:
            return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(exc)}, "id": req_id}
```

#### `src/lib/rpc-client.ts` (框架)

```typescript
// JSON-RPC 客户端 (前端 TypeScript)
//
// 通过 Tauri invoke() 调用 Rust commands.rs 中的 rpc_call,
// Rust 侧转发到 Python sidecar.

import { invoke } from '@tauri-apps/api/core';

export interface JsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  id: number;
  result?: T;
  error?: { code: number; message: string };
}

let _nextId = 1;

export async function rpcCall<T = unknown>(
  method: string,
  params: Record<string, unknown> = {}
): Promise<T> {
  const id = _nextId++;
  const response = await invoke<JsonRpcResponse<T>>('rpc_call', {
    method,
    params,
    id,
  });

  if (response.error) {
    throw new Error(`RPC Error [${response.error.code}]: ${response.error.message}`);
  }
  return response.result as T;
}

// 类型化封装
export async function classifyFile(path: string, connectionId?: string) {
  return rpcCall<ClassificationResult>('classify_file', { path, connection_id: connectionId });
}

export async function searchVault(keyword: string, filters?: SearchFilters) {
  return rpcCall<SearchResult[]>('search_vault', { keyword, filters });
}
```

### 4.3 通信协议设计

#### JSON-RPC over stdio 协议规范

```
┌──────────────────────────────────────────────────────────────┐
│                   AegisVault JSON-RPC Protocol                │
├──────────────────────────────────────────────────────────────┤
│ Transport:  stdio (stdin/stdout pipes)                       │
│ Format:     JSON-RPC 2.0, one JSON object per line (NDJSON)  │
│ Encoding:   UTF-8                                            │
│ Direction:  Bidirectional (Tauri → Python, Python → Tauri)   │
├──────────────────────────────────────────────────────────────┤
│ Request Format:                                              │
│   {"jsonrpc":"2.0","id":<int>,"method":"<string>",          │
│    "params":{<object>}}                                     │
│                                                              │
│ Response Format:                                             │
│   {"jsonrpc":"2.0","id":<int>,"result":<object>}            │
│                                                              │
│ Error Format:                                                │
│   {"jsonrpc":"2.0","id":<int>,                              │
│    "error":{"code":<int>,"message":"<string>"}}             │
├──────────────────────────────────────────────────────────────┤
│ Standard Error Codes:                                        │
│   -32700  Parse error                                        │
│   -32600  Invalid request                                    │
│   -32601  Method not found                                   │
│   -32602  Invalid params                                     │
│   -32603  Internal error                                     │
│   -32000  Application error (custom message)                 │
├──────────────────────────────────────────────────────────────┤
│ Predefined Methods:                                          │
│                                                              │
│ classify_file                                                │
│   » 分类文件 (调用 LLM 生成 ClassificationResult)            │
│   params: {path: str, connection_id?: str}                   │
│   returns: {disguise_name, category, sensitivity, tags,      │
│             summary, disguise_extension}                     │
│                                                              │
│ encrypt_file                                                 │
│   » 加密文件并写入 Vault                                      │
│   params: {path: str, vault_key_b64: str, salt_b64: str}     │
│   returns: {vault_path: str, file_size: int}                 │
│                                                              │
│ search_vault                                                 │
│   » 搜索 Vault (FTS5 + 语义)                                 │
│   params: {keyword?: str, category?: str,                    │
│            sensitivity?: str, tags?: [str]}                  │
│   returns: [{task_id, disguise_name, category, ...}, ...]    │
│                                                              │
│ get_task_status                                              │
│   » 获取任务状态统计                                          │
│   params: {}                                                 │
│   returns: {total, completed, failed, active, quarantined}   │
│                                                              │
│ manage_connections                                           │
│   » CRUD 连接配置                                             │
│   params: {action: "list"|"add"|"update"|"delete"|"test",   │
│            connection?: {...}}                               │
│   returns: depending on action                               │
│                                                              │
│ health_check                                                 │
│   » 心跳检测                                                  │
│   params: {}                                                 │
│   returns: {status: "ok", version: str, uptime: float}       │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. 分阶段迁移路线图

### 阶段 A: 并行运行（4 周）

**目标**: 在不影响现有 PyQt6 用户的前提下，搭建 Tauri 壳 + Python 后端的最小可用系统。

**交付物**:
- [ ] Tauri v2 项目骨架 (`src-tauri/` + `src/`)
- [ ] Python JSON-RPC sidecar 服务端 (`aegisvault/api/jsonrpc_server.py`)
- [ ] Rust sidecar 管理器 (启动/监控/重启 Python 进程)
- [ ] 系统托盘 (Tray) 最小实现 — 图标 + 基础状态 + 快捷菜单
- [ ] 基础状态面板 — 连接状态 + 任务计数 + Vault 大小
- [ ] JSON-RPC 通信可用 (`health_check` + `get_task_status` + `classify_file`)
- [ ] Tauri 壳与 PyQt6 GUI **并行运行**，用户可选择使用哪一个

**技术细节**:

```
┌─────────────────────────────────────────────────┐
│ 阶段 A 架构                                      │
├─────────────────────────────────────────────────┤
│                                                  │
│  PyQt6 GUI (不变)          Tauri GUI (新增)       │
│  ├─ tray.py               ├─ TrayMenu.tsx        │
│  ├─ vault_browser.py      ├─ StatusPanel.tsx     │
│  └─ ...                   └─ App.tsx             │
│       │                         │                │
│       │ (直接调用 Python)       │ (JSON-RPC)      │
│       ▼                         ▼                │
│  ┌─────────────────────────────────────────┐    │
│  │     Python 业务逻辑 (不变)               │    │
│  │     security / model / orchestration /   │    │
│  │     platform / execution                │    │
│  └─────────────────────────────────────────┘    │
│                                                  │
│  安装方式:                                        │
│  - PyQt6: pip install aegisvault[gui]            │
│  - Tauri: .msi / .dmg / .AppImage 安装包          │
└─────────────────────────────────────────────────┘
```

**关键决策**:
- PyInstaller 打包 Python sidecar → 存放在 `src-tauri/binaries/`
- Tauri bundler 将 sidecar 二进制嵌入安装包
- JSON-RPC server 无 PyQt6 依赖，可独立运行

**风险缓解**: 若 JSON-RPC 通信不可靠，可退回到阶段 A 仅实现 Tauri 原生功能（托盘 + 文件对话框），暂不依赖 Python sidecar。

---

### 阶段 B: 功能对等（8 周）

**目标**: 将所有 PyQt6 GUI 功能迁移到 Tauri 前端，Python sidecar 逐步缩减为纯 API 服务。

**模块迁移顺序** (按依赖关系):

| 周次 | 模块 | 迁移内容 | 验收标准 |
|------|------|----------|----------|
| W1-2 | **连接管理** (ConnectionDialog) | CRUD 表单 + 连接测试 | 可添加/编辑/删除/测试连接，与原 PyQt6 功能等价 |
| W3-4 | **设置页面** (SettingsDialog) | 安全设置 + 路径配置 + 模型配置 | 所有设置可修改保存，验证逻辑一致 |
| W5-6 | **Vault Browser** (VaultBrowser) | 表格/网格视图 + 分类树 + 预览 + 批量操作 | 浏览/搜索/解密/删除功能完整 |
| W7 | **首次运行向导** (FirstRunWizard) | 5 步向导 + 密码强度 + 连接测试 | 新用户可完成首次配置 |
| W8 | **集成测试 + 回归测试** | 全功能 E2E 测试 | 与现有 550 个测试通过（含 GUI 测试适配） |

**每个模块的迁移流程** (标准流程):
1. 分析现有 PyQt6 代码的 UI 状态和数据流
2. 在 Python 侧添加对应 JSON-RPC method（如 `manage_connections`）
3. 用 React 组件实现前端 UI
4. 编写集成测试（Rust 命令 → Python sidecar → 数据库）
5. 人工验收（与 PyQt6 版本对比）
6. 标记 PyQt6 对应模块为 deprecated

**Python sidecar 缩减**:

```
阶段 A: Python sidecar 提供全部业务逻辑 (~7,600 行)
         │
         ▼
阶段 B: 新增 JSON-RPC 适配层 (~200 行)
         原有业务代码不变
         │
         ▼
阶段 C: 逐步将安全模块移植到 Rust
         Python 缩减至 ~3,000 行 (ML + 外部工具)
```

---

### 阶段 C: 全 Rust 核心（12 周）

**目标**: 将安全关键路径移植到 Rust，最终 Python 仅作为可选依赖（语义搜索需要时存在）。

**移植顺序** (按安全关键度):

| 周次 | 子模块 | Python → Rust 映射 | 行数变化 | 安全收益 |
|------|--------|---------------------|----------|----------|
| W1-2 | `crypto.py` (97行) | `aes-gcm` + `rand` crate | 97 → ~120 | AES-256-GCM 直接在 Rust 执行，消除 Python GC 侧信道 |
| W3 | `keytree.py` (40行) | `argon2` + `hkdf` crate | 40 → ~60 | 密钥派生脱离 Python 解释器 |
| W4-5 | `master_key.py` (897行) | `windows-rs` + Security Framework | 897 → ~1,100 | DPAPI/TPM/Hello 原生调用，不再依赖 ctypes |
| W6-7 | `sandbox.py` (555行) | `nix` + libseccomp 绑定 | 555 → ~500 | bubblewrap 配置用 Rust 生成，减少注入风险 |
| W8-9 | `win32_appcontainer.py` (528行) | `windows-rs` LowBox API | 528 → ~450 | 原生 Win32 API，更可靠 |
| W10 | `audit_log.py` (426行) | `hmac` + `sha2` crate | 426 → ~350 | HMAC 审计更高效 |
| W11-12 | `task_store.py` (1,014行) | `rusqlite` | 1,014 → ~900 | SQLite 操作 Rust 化 |

**移植后架构**:

```
┌─────────────────────────────────────────────────────┐
│                 Tauri Frontend                        │
│              (React + TypeScript)                     │
└──────────────────────┬──────────────────────────────┘
                       │ IPC (invoke)
┌──────────────────────┴──────────────────────────────┐
│               Tauri Core (Rust)                       │
│  ┌─────────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ Crypto      │  │ Sandbox  │  │ Task Store     │  │
│  │ (aes-gcm,   │  │ (bwrap,  │  │ (rusqlite,     │  │
│  │  argon2,    │  │  seccomp)│  │  FTS5)         │  │
│  │  hkdf)      │  │          │  │                │  │
│  └─────────────┘  └──────────┘  └────────────────┘  │
│  ┌──────────────────────────────────────────────┐   │
│  │ Sidecar Manager (管理 Python，按需启动)       │   │
│  └──────────────┬───────────────────────────────┘   │
└─────────────────┼───────────────────────────────────┘
                  │ JSON-RPC (stdio)  [仅语义搜索时需要]
┌─────────────────┴───────────────────────────────────┐
│   Python Sidecar (可选)                               │
│  ├─ model/classifier.py  (LLM 分类)                  │
│  ├─ model/embedding.py   (sentence-transformers)     │
│  └─ security/password_store.py (KeePassXC 集成)      │
└─────────────────────────────────────────────────────┘
```

---

## 6. 风险与缓解

### 6.1 风险矩阵

| ID | 风险 | 影响 | 概率 | 严重度 | 缓解措施 |
|----|------|------|------|--------|----------|
| **R1** | **JSON-RPC 通信性能瓶颈**<br>stdio 管道高频调用时延迟 | 中 | 中 | **高** | ① 批量请求合并 (batch JSON-RPC)<br>② 热路径数据 (任务状态、Vault 列表) 缓存在 Rust 侧<br>③ 对性能敏感操作 (分类) 使用异步通知而非阻塞等待<br>④ 基准测试: stdio 管道延迟 <1ms，足够满足 GUI 响应需求 |
| **R2** | **Python sidecar 进程崩溃** | 中 | 中 | **高** | ① Rust 侧实现 heartbeat 探测 (10s 间隔)<br>② 自动重启 + 指数退避 (1s → 2s → 4s → ... → 60s max)<br>③ 前端显示 "后端服务不可用" 降级 UI<br>④ 崩溃前保存状态到文件，重启后恢复 |
| **R3** | **PyInstaller 打包兼容性** | 高 | 低 | **中** | ① 在 CI 中对 Windows/macOS/Linux 三种目标分别构建<br>② 锁定 Python 版本 (3.12) + 依赖版本<br>③ 使用虚拟环境隔离打包<br>④ 参考现有 Dockerfile 验证依赖完整性 |
| **R4** | **PyQt6 → Web UI 功能差异** | 中 | 中 | **中** | ① 每个模块迁移后编写集成测试并运行现有 550 测试套件<br>② 保留 PyQt6 GUI 共存直到所有功能验收通过<br>③ 逐模块验收，禁止批量切换 |
| **R5** | **安全性降级**<br>WebView 引入新攻击面 | 高 | 低 | **中** | ① 启用 Tauri CSP (Content-Security-Policy)，禁止 inline script 和外部资源<br>② 关闭 WebView 的 `dangerousRemotePageIpc` 权限<br>③ Python sidecar 不做 HTTP 服务器，仅接受 stdio 管道输入<br>④ 安全审计 (Phase 3 Review 同等标准) |
| **R6** | **sentence-transformers 无 Rust 替代** | 中 | 高 | **中** | ① 语义搜索列为可选功能 (需 Python)<br>② 基础搜索使用 SQLite FTS5 (已在 Rust 中通过 rusqlite 实现)<br>③ 长期关注 ONNX Runtime Rust binding 进展 |
| **R7** | **团队 Rust 技能缺口** | 中 | 中 | **中** | ① 阶段 A 仅需基础 Rust (sidecar 管理 + Tauri API 调用)<br>② 阶段 C 前安排 2 周 Rust 专项学习<br>③ 优先移植简单模块 (crypto 97行, keytree 40行) 建立信心 |
| **R8** | **Tauri 版本稳定性**<br>(v2 仍在活跃开发) | 中 | 低 | **低** | ① 锁定 Tauri v2 稳定版 (当前 v2.0-rc → v2.1+)<br>② 关注 breaking change 公告并预留适配缓冲<br>③ 暂不使用 beta/experimental 功能 (如移动端) |
| **R9** | **现有 550 测试回归** | 高 | 中 | **高** | ① Python 核心代码不变，现有 unit test 继续运行<br>② 新增 sidecar integration test<br>③ 新增 Tauri E2E test (前端 + Rust + Python 链路) |
| **R10** | **Windows 特定功能迁移** (DPAPI / Hello / AppContainer) | 中 | 中 | **中** | ① 阶段 A-B 保留 Python 侧 Windows 集成<br>② 阶段 C 使用 `windows-rs` crate 重写，API 更稳定<br>③ Windows Hello 在 Rust 中有官方示例代码参考 |

### 6.2 回滚策略

```
阶段 A 失败 → 删除 src-tauri/ + src/ 目录，PyQt6 不受影响
阶段 B 失败 → 回退到阶段 A (Tauri 壳可用)，PyQt6 仍完整可用
阶段 C 失败 → 回退到阶段 B (Python sidecar 全功能)，Rust 加密模块可选
```

---

## 附录

### A. 推荐技术选型

| 层 | 选型 | 版本 | 理由 |
|----|------|------|------|
| 前端框架 | **React** + TypeScript | React 18, TS 5.5 | 生态成熟，社区最大，与 Tauri 示例最多 |
| 状态管理 | Zustand | 4.x | 轻量 (1KB)，无模板代码，适合中等复杂度 GUI |
| UI 组件库 | shadcn/ui + Tailwind CSS | — | 无运行时依赖，暗色主题原生支持，可定制 |
| 表格/虚拟滚动 | @tanstack/react-table + @tanstack/react-virtual | 8.x | 支持大数据量表格，性能优秀 |
| 拖拽排序 | @dnd-kit/core | 6.x | 轻量、可访问、TypeScript 原生 |
| 打包工具 | Vite | 6.x | Tauri 官方推荐，HMR 极快 |
| 测试 (前端) | Vitest + Playwright | 2.x | 单元测试 + E2E，与 Vite 深度集成 |
| Rust HTTP 客户端 | reqwest | 0.12 | 用于阶段 C Rust ↔ LLM API 直连 |
| Rust 加密 | aes-gcm + argon2 + hkdf | 0.10 / 0.5 / 0.12 | 与 Python cryptography 库 API 1:1 映射 |

### B. 关键参考资料

- [Tauri v2 文档](https://v2.tauri.app/)
- [Tauri sidecar 指南](https://v2.tauri.app/develop/sidecar/)
- [Tauri Plugin 系统](https://v2.tauri.app/learn/security/capabilities/)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)
- [PyInstaller 打包指南](https://pyinstaller.org/en/stable/)
- [ADR-001: Phase 1 Architecture Decision](../docs/decisions/ADR-001.md) — UI 栈决策参考
- [ADR-002: Platform Connection Management](../docs/decisions/ADR-002.md) — 连接模型参考

---

*文档版本: 1.0 · 作者: AegisVault 架构团队 · 审核状态: 待审核*
