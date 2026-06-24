# AegisVault 项目计划书

## 项目愿景

**AegisVault** 是一个本地优先、隐私至上的智能内容管理 Agent。自动分类、加密并存储用户文件到结构化保险库，全程使用本地 AI 模型，数据永不出本地。

## 核心设计原则

| # | 原则 | 说明 |
|---|------|------|
| 1 | **Local-First** | 数据存本地，云端连接需显式授权 |
| 2 | **Encrypt Before Persist** | 加密先于存储，AES-256-GCM + 三级密钥 |
| 3 | **Zero-Trust Model Service** | 敏感操作强制离线，云模型仅用于非敏感分类 |
| 4 | **Defense in Depth** | 密钥分层、沙箱隔离、网络策略、HMAC 审计日志 |
| 5 | **Minimal Supply Chain** | 自建 Agent，零遥测，精简依赖 |

---

## Phase 1: Core Pipeline（→ 100%）

**当前进度**: ████████████████░ ~95%

### 已完成 ✅

- [x] 文件监听（watchdog InboxWatcher）
- [x] LLM 分类器（OpenAI-compatible Provider，~8 类分类 prompt）
- [x] AES-256-GCM 流式加密/解密（原子写入）
- [x] 三级密钥层次（Master→Vault→File，Argon2id + HKDF-SHA256）
- [x] SQLite FTS5 全文搜索
- [x] NDJSON + HMAC-SHA256 审计日志
- [x] PyQt6 系统托盘 + 连接/设置/保险库浏览器对话框
- [x] Vault Browser 增强（文件预览、网格视图、排序、批量操作）
- [x] JSON-RPC API + Pydantic Schema
- [x] KeePassXC-cli / pass 密码管理器集成
- [x] Windows DPAPI / TPM / Windows Hello 支持
- [x] Linux bubblewrap 沙箱 + Windows AppContainer
- [x] 网络防火墙出站拦截
- [x] 离线策略检测与强制执行
- [x] CLI 子命令（search/status/list）
- [x] Docker 镜像 + docker-compose.yml
- [x] PyPI 发布准备（pyproject.toml 完整、.pypirc 模板）
- [x] CI/CD pipeline（lint / type / test / build）
- [x] 用户安装使用文档（中文 USER_GUIDE.md）
- [x] 分类 Prompt 优化（8 类，中文关键词提示）
- [x] 414 个测试全部通过

### 待完成

| ID | 任务 | 优先级 | 状态 |
|----|------|--------|------|
| 1.7 | **首次运行引导向导** | P2 | 待开始 |
| 1.2 | **真实 LLM E2E 集成测试** | P0 | 待开始 |

---

## Phase 2: Hardened Security（0%）

**目标**: 安全基础设施从"可用"到"生产级"

| ID | 任务 | 优先级 | 预计工时 |
|----|------|--------|----------|
| 2.1 | **bubblewrap 沙箱生产落地**（实际隔离运行） | P0 | 8h |
| 2.2 | **Windows AppContainer 改用 Win32 API**（替换 PowerShell） | P0 | 8h |
| 2.3 | **KeePassXC API 深度集成**（密码自动填充、条目管理） | P1 | 6h |
| 2.4 | **审计日志实时告警与导出** | P1 | 4h |
| 2.5 | **主密钥轮换策略**（周期性自动轮换） | P1 | 6h |
| 2.6 | **敏感文件类型检测扩展**（身份证、合同、凭证自动识别） | P2 | 6h |
| 2.7 | **安全白皮书 v1.0** | P2 | 4h |

---

## Phase 3: Smart Vault（0%）

**目标**: 从"文件仓库"升级为"语义智能保险库"

| ID | 任务 | 优先级 | 预计工时 |
|----|------|--------|----------|
| 3.1 | **语义搜索正式启用**（sentence-transformers 向量检索） | P0 | 6h |
| 3.2 | **混合搜索**（FTS5 + 语义向量联合排序） | P0 | 4h |
| 3.3 | **文档相似度聚类与自动分组** | P1 | 6h |
| 3.4 | **Tauri 前端技术选型与原型** | P1 | 8h |
| 3.5 | **GUI 从 PyQt6 到 Tauri 迁移路径设计** | P2 | 4h |

---

## Phase 4: Multi-Device Sync（0%）

**目标**: 零信任跨设备同步

| ID | 任务 | 优先级 | 预计工时 |
|----|------|--------|----------|
| 4.1 | **端到端加密同步协议设计** | P0 | 8h |
| 4.2 | **P2P 局域网设备发现** | P0 | 6h |
| 4.3 | **增量同步引擎** | P1 | 8h |
| 4.4 | **冲突解决策略**（LWW/CRDT） | P1 | 6h |
| 4.5 | **设备授权与撤销管理** | P2 | 4h |

---

## Phase 5: Cross-Platform & Mobile（0%）

**目标**: 全平台覆盖

| ID | 任务 | 优先级 | 预计工时 |
|----|------|--------|----------|
| 5.1 | **macOS 全功能支持**（Keychain 主密钥、沙箱） | P0 | 8h |
| 5.2 | **iOS 伴侣 App**（只读保险库查看器） | P1 | 16h |
| 5.3 | **Android 伴侣 App** | P1 | 16h |
| 5.4 | **平台原生 UX 适配**（通知、文件选择器） | P2 | 6h |

---

## 技术栈

| 层 | 技术 | 说明 |
|----|------|------|
| 语言 | Python 3.11+ | 全栈 |
| 包管理 | Poetry 1.8.3 | 依赖管理 |
| 加密 | AES-256-GCM, Argon2id, HKDF-SHA256 | cryptography + argon2-cffi |
| 数据 | SQLite + FTS5 | 任务存储 + 全文搜索 |
| 向量 | sentence-transformers | 语义搜索（可选） |
| GUI | PyQt6 → Tauri (Phase 3) | 桌面界面 |
| 沙箱 | bubblewrap / AppContainer | 进程隔离 |
| AI | OpenAI-compatible API | 分类与嵌入 |
| CI/CD | GitHub Actions | lint/type/test/build |

## 仓库

- GitHub: `github.com/MS33834/aegisvault`
- GitCode: `gitcode.com/badhope/AegisVault`
- 同步命令: `bash sync.sh`
