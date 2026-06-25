# AegisVault 用户指南

> 版本: 0.1.0 | 最后更新: 2026-06-25

---

## 1. 简介

**AegisVault** 是一个本地优先、隐私至上的智能内容管理工具。它可以自动识别、分类、加密并归档您的文件，全程使用本地 AI 模型，数据永不离开您的设备。

### 它能解决什么问题？

| 痛点 | AegisVault 的解决方案 |
|------|-----------------------|
| 文件堆积杂乱，找不到想要的内容 | 自动分类 + 全文/语义搜索 |
| 敏感文件（身份证、合同、账单）随意存放 | 自动识别敏感级别，分级加密存储 |
| 云存储隐私担忧 | 全部数据本地处理，零上传 |
| 手动整理文件耗时费力 | 丢入 Inbox 即自动处理 |

### 工作流程

```
您丢文件到 Inbox  →  AI 自动分类  →  AES-256 加密  →  存入 Vault
                                                          ↓
                                              随时搜索、查看、导出
```

---

## 2. 安装

### 系统要求

| 项目 | 最低要求 |
|------|----------|
| 操作系统 | Linux、Windows 10+、macOS（实验性） |
| Python | 3.11 或更高版本 |
| 内存 | 4 GB（含本地模型运行时建议 8 GB+） |
| 磁盘 | 500 MB（不含模型和保险库空间） |
| 本地模型 | Ollama / LM Studio / llama.cpp 任意一种 |

### 方式一：pip 安装（推荐）

```bash
# 基础安装
pip install aegisvault

# 安装图形界面支持（可选）
pip install aegisvault[gui]

# 安装语义搜索支持（可选，需要额外磁盘空间）
pip install aegisvault[semantic]

# 安装全部可选功能
pip install aegisvault[gui,semantic]
```

### 方式二：源码安装

```bash
git clone https://github.com/MS33834/aegisvault.git
cd aegisvault
pip install -e .
```

### 方式三：Docker 运行

```bash
# 构建镜像
docker build -t aegisvault .

# 运行容器（映射 Inbox、Vault 和配置目录）
# 重要：Config 目录需包含 settings.json 配置文件
docker run -d \
  -v ~/AegisVault/Inbox:/app/Inbox \
  -v ~/AegisVault/Vault:/app/Vault \
  -v ~/AegisVault/Config:/app/Config \
  -p 11434:11434 \
  aegisvault
```

> **注意**: Docker 模式下需要额外配置本地模型服务的网络访问。

---

## 3. 首次运行

### 3.1 启动前的准备

AegisVault 需要一个 **本地 AI 模型服务** 来进行文件分类。推荐以下任一方案：

- **[Ollama](https://ollama.com)**（推荐，跨平台最简单）
  ```bash
  # 安装 Ollama 后拉取模型
  ollama pull qwen2.5:7b
  ```

- **[LM Studio](https://lmstudio.ai)**（Windows/macOS 图形化）
- **[llama.cpp](https://github.com/ggerganov/llama.cpp)**（Linux 高级用户）

### 3.2 首次启动

```bash
aegisvault
```

首次运行后，AegisVault 会自动在 `~/AegisVault/` 目录下创建以下结构：

```
~/AegisVault/
├── Inbox/          ← 您把文件丢到这里
├── Vault/          ← 加密后的文件存到这里
├── Index/          ← 搜索索引用
├── Logs/           ← 运行日志
└── Config/
    ├── settings.json       ← 主配置文件
    └── connections.json    ← 模型连接配置
```

### 3.3 配置向导

首次运行时，系统会使用默认配置。您可以通过以下方式自定义：

**方法一：修改配置文件**

编辑 `~/AegisVault/Config/settings.json`：

```json
{
  "model": {
    "base_url": "http://127.0.0.1:11434/v1",
    "model_name": "qwen2.5:7b"
  },
  "security": {
    "encryption": "AES-256-GCM",
    "master_key_provider": "FilePassword",
    "enable_semantic_search": false
  },
  "paths": {
    "inbox": "/home/yourname/AegisVault/Inbox",
    "vault": "/home/yourname/AegisVault/Vault"
  }
}
```

**方法二：环境变量**

```bash
export AEGISVAULT_MODEL__BASE_URL="http://127.0.0.1:11434/v1"
export AEGISVAULT_MODEL__MODEL_NAME="qwen2.5:7b"
export AEGISVAULT_SECURITY__ENABLE_SEMANTIC_SEARCH="true"
```

**方法三：命令行参数**

```bash
aegisvault --inbox /path/to/inbox --vault /path/to/vault --debug
```

### 3.4 设置主密钥密码

如果使用 `FilePassword` 主密钥提供程序（默认），首次运行时会提示设置密码：

```bash
export AEGISVAULT_SECURITY__MASTER_KEY_PASSWORD="your-strong-password"
```

> **警告**: 此密码无法找回。请务必妥善保管。

---

## 4. 日常使用

### 4.1 丢文件到 Inbox

这是 AegisVault 的核心操作方式 —— **拖放即自动处理**。

1. 将任意文件（PDF、图片、Word 文档等）放入 `~/AegisVault/Inbox/`
2. AegisVault 自动检测新文件
3. AI 分析文件内容/类型，生成分类结果
4. 文件被 AES-256-GCM 加密
5. 加密后的文件移入 Vault 目录

整个过程无需任何手动操作。您可以在系统托盘中看到处理进度。

### 4.2 查看 Vault 中的文件

```bash
# 列出所有已归档文件
aegisvault list

# 按分类筛选
aegisvault list finance       # 财务类
aegisvault list identity      # 身份类
aegisvault list legal         # 合同/法律类
aegisvault list media         # 媒体类
aegisvault list documents     # 文档/笔记类
```

### 4.3 搜索文件

```bash
# 关键词搜索（基于文件元数据和分类标签）
aegisvault search "银行 2024"

# 如果启用了语义搜索，也可以用自然语言
aegisvault search "去年的租房合同"
```

搜��结果会显示文件路径、分类、摘要和匹配分数。

### 4.4 查看系统状态

```bash
aegisvault status
```

输出示例：

```
=== AegisVault Status ===
  Inbox files : 3
  Vault files : 127

Recent tasks:
  550e8400...  [completed]  /home/user/AegisVault/Inbox/contract.pdf
  550e8401...  [completed]  /home/user/AegisVault/Inbox/id_card.jpg
  550e8402...  [processing] /home/user/AegisVault/Inbox/bank_statement.pdf
```

---

## 5. CLI 命令参考

### `aegisvault search` — 搜索保险库内容

```bash
aegisvault search <关键词>

# 示例
aegisvault search "发票"
aegisvault search "合同 2024"
```

### `aegisvault status` — 查看运行状态

```bash
aegisvault status
```

显示 Inbox 待处理数量、Vault 已归档数量、最近任务列表。

### `aegisvault list` — 列出归档文件

```bash
# 列出全部
aegisvault list

# 按分类筛选
aegisvault list finance
aegisvault list media
```

### 主程序参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `--no-tray` | 无 GUI 模式运行 | `aegisvault --no-tray` |
| `--inbox PATH` | 自定义 Inbox 路径 | `aegisvault --inbox /data/inbox` |
| `--vault PATH` | 自定义 Vault 路径 | `aegisvault --vault /data/vault` |
| `--index PATH` | 自定义索引路径 | `aegisvault --index /data/index` |
| `--connections PATH` | 自定义连接配置文件 | `aegisvault --connections /etc/aegis/conn.json` |
| `--debug` | 开启调试日志 | `aegisvault --debug` |

---

## 6. 安全最佳实践

### 6.1 主密钥密码

- **强度要求**: 至少 16 个字符，包含大小写字母、数字和符号
- **使用密码短语**: 推荐使用长密码短语而非短随机字符，例如 `correct-horse-battery-staple`
- **单独存储**: 不要将主密码与配置文件放在同一设备上

### 6.2 备份主密钥

主密钥文件位于 `~/AegisVault/Config/master_key.bin`。请执行以下备份操作：

```bash
# 将主密钥文件复制到安全的外部存储
cp ~/AegisVault/Config/master_key.bin /media/usb-drive/backup/

# 或写入冷存储（离线 U 盘）
```

> **关键**: 主密钥丢失 = 所有 Vault 文件永久无法解密。请务必多份备份，分开存放。

### 6.3 离线使用

AegisVault 默认使用本地模型，无需联网即可工作。为确保完全离线：

```json
{
  "security": {
    "cloud_fallback_enabled": false,
    "enforce_offline_policy": true
  }
}
```

这样设置后，即使配置了云端连接，系统也会强制使用本地模型。

### 6.4 密码管理器集成

AegisVault 支持通过外部密码管理器管理凭据：

- **KeePassXC**: 设置 `password_store = "keepassxc"`
- **pass**: 设置 `password_store = "pass"`
- **禁用**: 设置 `password_store = "none"`

### 6.5 Windows 安全增强

在 Windows 上可以启用：

- **Windows Hello**: 需要生物识别/PIN 才能解锁主密钥
- **DPAPI**: 使用 Windows 数据保护 API 加密主密钥
- **TPM**: 绑定主密钥到硬件安全模块

### 6.6 定期审计

查看审计日志确认无异常操作：

```bash
cat ~/AegisVault/Logs/audit.log.ndjson | tail -100
```

日志记录所有关键操作（登录、加密、解密、配置变更），并通过 HMAC 防篡改。

---

## 7. 常见问题

### Q1: 启动后报错 "No suitable chat connection found"

**A**: AegisVault 需要本地模型服务。请先安装并启动 Ollama：

```bash
ollama serve
ollama pull qwen2.5:7b
```

然后确认 `settings.json` 中的 `base_url` 指向正确的地址。

### Q2: 如何确认模型服务正在运行？

```bash
curl http://127.0.0.1:11434/v1/models
```

如果返回模型列表，说明服务正常。

### Q3: 忘记主密码，Vault 文件还能恢复吗？

**A**: **不能。** 主密码是唯一解密入口。如果丢失且没有备份 `master_key.bin` 文件，所有 Vault 文件将永久无法解密。请务必按第 6 章的安全实践备份主密钥。

### Q4: 能否在多个设备间同步 Vault？

**A**: Phase 1 版本暂不支持多设备同步。您可以手动将 Vault 目录复制到其他设备，但需要同时迁移 `master_key.bin`。多设备加密同步计划在 Phase 4 实现。

### Q5: 支持哪些文件类型？

**A**: AegisVault 可以处理任何文件类型。AI 分类器会根据文件名和元数据进行识别。常见支持类型包括：

- PDF 文档（合同、报告、账单）
- 图片（JPEG、PNG、TIFF）
- Office 文档（Word、Excel、PowerPoint）
- 纯文本、Markdown、CSV

### Q6: 文件加密后可以解密导出吗？

**A**: 可以。Vault 管理器支持将加密文件解密到指定位置。通过系统托盘或 API 可以执行解密操作。

### Q7: Inbox 中的文件处理后原文件还在吗？

**A**: 默认情况下，文件加密成功后原文件会从 Inbox 中删除。文件内容已安全转移到 Vault 中。

### Q8: 如何更换本地模型？

**A**: 修改 `settings.json` 中的模型配置：

```json
{
  "model": {
    "base_url": "http://127.0.0.1:11434/v1",
    "model_name": "llama3.1:8b"
  }
}
```

支持任何 OpenAI 兼容 API 的模型（Ollama、LM Studio、vLLM 等）。

### Q9: 如何查看详细运行日志？

```bash
# 启用 debug 模式
aegisvault --debug

# 或查看日志文件
tail -f ~/AegisVault/Logs/*.log
```

### Q10: 项目是开源的吗？许可证是什么？

**A**: AegisVault 是开源项目，采用 MIT 许可证。代码仓库: [github.com/MS33834/aegisvault](https://github.com/MS33834/aegisvault)

---

## 8. 更新日志

完整的版本更新记录请查看 GitHub Releases 页面：

- [AegisVault Releases](https://github.com/MS33834/aegisvault/releases)

### 当前版本 (v0.1.0)

- 文件监听（watchdog InboxWatcher）
- LLM 分类器（OpenAI-compatible Provider）
- AES-256-GCM 流式加密/解密
- 三级密钥层次（Argon2id + HKDF-SHA256）
- SQLite FTS5 全文搜索
- HMAC-SHA256 审计日志
- PyQt6 系统托盘 + 设置界面
- Windows DPAPI / TPM / Windows Hello 支持
- KeePassXC / pass 密码管理器集成
- 网络防火墙出站拦截
- 离线策略强制执行

---

> 有问题或建议？欢迎提交 [GitHub Issue](https://github.com/MS33834/aegisvault/issues)。
