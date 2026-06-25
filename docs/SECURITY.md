# AegisVault 安全白皮书

> 版本: 0.1.0 | 最后更新: 2026-06-25 | 语言: 简体中文

---

## 1. 安全架构概述

AegisVault 采用纵深防御策略，核心安全模型基于**三层密钥体系**：

```
┌─────────────────────────────────────────────────────────┐
│                    Layer 1: 主密钥 (Master Key)          │
│  来源: FilePassword / DPAPI / TPM                        │
│  保护: 密码派生(Argon2id) / 操作系统安全存储 / 硬件TPM  │
│  长度: 256-bit (32 bytes)                                │
│  生命周期: 生成后持久化, 会话内缓存                      │
└───────────────────────┬─────────────────────────────────┘
                        │ HKDF-SHA256
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  Layer 2: 保险库密钥 (Vault Key)         │
│  派生: HKDF-SHA256(master_key, info="vault-key-v1")     │
│  长度: 256-bit (32 bytes)                                │
│  作用域: 整个保险库的所有文件                            │
│  生命周期: 派生后立即使用, 不持久化                      │
└───────────────────────┬─────────────────────────────────┘
                        │ Argon2id(pass=vault_key, salt)
                        ▼
┌─────────────────────────────────────────────────────────┐
│                   Layer 3: 文件密钥 (File Key)           │
│  派生: Argon2id(vault_key, per-file 32-byte salt)       │
│  长度: 256-bit (32 bytes)                                │
│  作用域: 单个文件                                        │
│  生命周期: 派生后立即使用, 不持久化                      │
└─────────────────────────────────────────────────────────┘
```

**核心安全特性：**

- **零信任模型**：即使是本地服务也不被信任，需要通过策略检查
- **网络隔离**：核心进程默认无外网访问能力（防火墙规则 + 沙箱）
- **审计不可篡改**：每条日志带 HMAC-SHA256 签名，支持离线验证
- **离线优先**：默认禁止云连接，敏感操作必须使用本地服务（127.0.0.1）

---

## 2. 威胁模型

### 2.1 假定的攻击者能力

AegisVault 假定攻击者具有以下能力：

| 能力 | 假设 | 防护措施 |
|------|------|----------|
| 本地文件系统读取 | 攻击者可读取用户磁盘文件 | AES-256-GCM 加密所有 Vault 文件 |
| 网络中间人 | 攻击者可拦截/篡改本地网络流量 | 强制使用 localhost/127.0.0.1 连接 |
| 进程内存读取 | 攻击者可读取运行中进程的内存 | 密钥使用后即时清零(secure_zero) |
| 日志篡改 | 攻击者可修改磁盘上的审计日志 | HMAC-SHA256 防篡改签名链 |
| 恶意外部工具 | 沙箱内执行的工具可能恶意 | 沙箱隔离、最简文件系统、无网络 |

### 2.2 不假定防御的能力

AegisVault **不防御**以下威胁：

- **内核级 rootkit**：攻击者若已控制操作系统内核，任何用户态防护均无效
- **物理访问 + 冷启动攻击**：未加密的 RAM 内容可能被读取
- **侧信道攻击**：如时序、功耗、电磁辐射等硬件层面攻击
- **供应链攻击**：上游 Python 包被投毒（需额外防范，如 pip hash 校验）
- **社会工程学**：攻击者通过欺骗获取用户主密码

### 2.3 信任边界

```
┌──────────────────────────────────────────────────────┐
│  可信域 (Trusted)               不可信域 (Untrusted)  │
│                                                      │
│  ┌──────────┐                  ┌───────────────┐     │
│  │  AegisVault│  localhost:    │  外部 LLM 服务  │     │
│  │  核心进程  │  ═══╪══════    │  (默认禁用)     │     │
│  └──────────┘       ║          └───────────────┘     │
│       │             ║                                │
│       │ 沙箱隔离 ═══╝                                │
│       ▼                                              │
│  ┌──────────┐   ┌───────────────┐                   │
│  │ Vault 目录│   │ 外部命令行工具  │                  │
│  │ (加密)    │   │ (沙箱内运行)    │                  │
│  └──────────┘   └───────────────┘                   │
│       │                                              │
│       │ 防火墙规则                                     │
│       ▼                                              │
│  ┌──────────────────────────┐                        │
│  │  Windows Defender Firewall│   阻止所有外发连接      │
│  └──────────────────────────┘                        │
└──────────────────────────────────────────────────────┘
```

---

## 3. 密钥管理

### 3.1 主密钥 Provider

| Provider | 平台 | 密钥来源 | 安全等级 | 适用场景 |
|----------|------|----------|----------|----------|
| **FilePassword** | 跨平台 | 用户密码经 Argon2id 派生 | ★★☆ | 开发/测试, 用户可记忆密码 |
| **DPAPI** | Windows | 操作系统 DPAPI 保护 | ★★★ | 生产环境, 无感解锁 |
| **TPM** | Windows (TPM 2.0) | TPM 硬件绑定 | ★★★★ | 高安全需求, 硬件级保护 |

#### FilePasswordProvider (密码派生)

```
用户密码 ──→ Argon2id ──→ 主密钥 (32 bytes)
              │   salt: 持久化随机 32 bytes
              │   time_cost: 3
              │   memory_cost: 65536 KB (64 MB)
              │   parallelism: 4
```

- 密码不落盘；salt 存储于 `filepassword.salt`
- Argon2id 参数对抗 GPU/ASIC 暴力破解

#### DpapiMasterKeyProvider (Windows DPAPI)

```
第一次运行: 随机生成 32 bytes ──→ DPAPI.Protect ──→ 加密 blob 写入磁盘
后续运行: 加密 blob ──→ DPAPI.Unprotect ──→ 主密钥
```

- 密钥与当前 Windows 用户账号绑定
- 用户登录后自动解密（无需密码）
- 非 Windows 平台不可用

#### TpmMasterKeyProvider (TPM 硬件)

> **平台限制**: TPM Master Key Provider **仅支持 Windows**（需要 TPM 2.0 硬件）。
> Linux/macOS 用户请使用 `FilePassword` 或 `DPAPI`（Windows 无感解锁）方案。

```
第一次运行: 随机生成 32 bytes ──→ TPM RSA-2048 加密 ──→ 加密 blob
后续运行: 加密 blob ──→ TPM RSA-2048 解密 ──→ [可选 HKDF] ──→ 主密钥
```

- TPM 私钥永远不离开 TPM 芯片
- 可选 Windows Hello 二次派生（`hello_salt` HKDF）
- 提供最强的硬件反篡改保护

### 3.2 密钥生命周期

```
生成: os.urandom(32)  ← CSPRNG
  │
派生: HKDF-SHA256 → Vault Key
  │      │
  │      └──→ Argon2id → File Key (per-file salt)
  │
使用: AES-256-GCM encrypt/decrypt
  │
清零: secure_zero() — mutable bytearray overwrite + scope drop
  │
销毁: 引用释放, GC 回收 (Python bytes 不可原地覆写)
```

**安全注意事项：**
- 主密钥在 `MasterKeyProvider` 实例生命周期内缓存于内存
- `clear()` 方法使用 mutable bytearray + 逐字节清零（best-effort）
- Python 的 bytes 对象不可变，清零效果有限；未来考虑使用 C 扩展或 `mmap` 实现真正的安全内存

### 3.3 密钥轮转

**状态：已实现**

AegisVault 支持两种主密钥轮转模式：

1. **常规轮转** (`rotate_master_key`) — 生成新主密钥，用新 vault key 重新加密所有 vault 文件。适用于定期密钥更新。
2. **紧急轮转** (`emergency_rotate`) — 在检测到密钥泄露时，用新主密钥封装（wrap）现有 vault key，无需重新加密所有文件。适用于快速响应安全事件。

**关键特性：**
- 轮转前自动备份原有加密密钥
- 轮转失败时自动回滚
- 每次轮转记录审计日志（含轮转类型、文件数量、时间戳）
- 支持 `should_rotate_key()` 根据密钥年龄（默认 90 天）判断是否需要轮转

---

## 4. 加密方案

### 4.1 AES-256-GCM 文件加密格式

单文件加密格式（写入 Vault 目录）：

```
┌────────┬──────────┬──────────┬──────────────┬──────────┐
│ 1 byte │ 32 bytes │ 12 bytes │  variable    │ 16 bytes │
├────────┼──────────┼──────────┼──────────────┼──────────┤
│Version │  Salt    │  Nonce   │  Ciphertext  │   Tag    │
└────────┴──────────┴──────────┴──────────────┴──────────┘
```

| 字段 | 大小 | 说明 |
|------|------|------|
| Version | 1 byte | 固定为 `\x01` |
| Salt | 32 bytes | 随机生成，用于派生 File Key |
| Nonce | 12 bytes | 随机生成，AES-GCM 每次加密必须唯一 |
| Ciphertext | variable | AES-256-GCM 加密的密文（含 16-byte 认证标签） |
| Tag | 16 bytes | GCM 认证标签（`ciphertext` 的最后 16 bytes） |

### 4.2 密钥派生细节

```
Master Key (32 bytes)
    │
    │ HKDF-SHA256(salt=None, info="vault-key-v1", length=32)
    ▼
Vault Key (32 bytes)
    │
    │ Argon2id(password=VaultKey, salt=file_salt,
    │          time_cost=3, memory_cost=65536, parallelism=4)
    ▼
File Key (32 bytes) ──→ AES-256-GCM(file_data, nonce, aad=version+salt)
```

### 4.3 加密安全保证

- **机密性**: AES-256 提供 256-bit 安全强度
- **完整性**: GCM 模式提供认证加密 (AEAD)，任何篡改都会导致解密失败
- **防重放**: 每个文件使用独立的随机 salt 和 nonce
- **原子写入**: `encrypt_file_stream()` 先写临时文件再原子 rename

### 4.4 解密安全保证

```
解密流程:
1. 读取版本号 → 校验
2. 读取 salt → 派生 File Key
3. 读取 nonce + ciphertext
4. AESGCM.decrypt(nonce, ciphertext, aad) → 认证+解密
5. 原子写入目标文件 (临时文件 + rename)
```

- **全有或全无**: 在 GCM 认证通过之前，目标文件不被修改（临时文件写入策略确保不会损坏已有文件）
- **认证失败**: 解密函数抛出异常，目标文件保持不变

---

## 5. 网络隔离

### 5.1 沙箱架构

AegisVault 使用沙箱技术隔离外部命令行工具（如 keepassxc-cli、pass）：

**Linux (bwrap/bubblewrap):**

```
┌─────────────────────────────────────────────────┐
│  bwrap 命名空间隔离                                │
│                                                 │
│  --unshare-net     # 无网络                      │
│  --unshare-ipc     # 无进程间通信                   │
│  --unshare-uts     # 隔离主机名                    │
│  --unshare-pid     # 独立 PID 命名空间              │
│  --unshare-user    # 独立用户命名空间               │
│  --as-pid-1        # 进程以 PID 1 运行             │
│                                                 │
│  文件系统:                                        │
│  /    → tmpfs (空)                               │
│  /usr → 只读绑定挂载                               │
│  /lib → 只读绑定挂载                               │
│  /tmp → tmpfs (可写)                             │
│  Vault → 只读绑定挂载                              │
│                                                 │
│  可选: --seccomp <BPF> 系统调用过滤                │
└─────────────────────────────────────────────────┘
```

**Windows (AppContainer):**

- Win32 API 优先级：`CreateAppContainerProfile` + `run_in_appcontainer`
- PowerShell 降级方案（当 Win32 API 不可用时）
- 沙箱名称：`AegisVaultSandbox`
- Capability SIDs：空集（最低权限）
- Vault 目录：只读访问

### 5.2 防火墙规则

在 Windows 上，AegisVault 可配置 Windows Defender Firewall 规则：

```
规则名称: AegisVault-Core-Outbound-Block
方向: Outbound
动作: Block
程序: <aegisvault 核心进程路径>
配置: Any (Domain + Private + Public)
```

- 完全阻止核心进程的所有外发连接
- 不影响 Web UI 所需的入站连接（如果有）
- 非 Windows 平台使用标准防火墙工具（iptables/nftables）等价配置

### 5.3 离线策略

AegisVault 支持严格的离线执行模式：

- **策略开关**: `security.enforce_offline_policy = True`
- **检测方式**: 解析 `/proc/<pid>/net/tcp` (Linux) 或 `GetExtendedTcpTable` (Windows)
- **仅限 ESTABLISHED / CLOSE_WAIT 状态**的连接
- **排除回环地址** (`127.0.0.1`, `::1`, `0.0.0.0`)
- **排除知名端口** (<= 1024, 视为服务端监听)
- **违规处理**: 抛出 `NetworkIsolationError` 并记录审计日志

---

## 6. 审计与合规

### 6.1 审计日志格式

日志以 NDJSON (Newline-Delimited JSON) 格式写入：

```json
{
  "timestamp": "2026-06-25T12:34:56.789012+00:00",
  "event_type": "file_ingested",
  "details": {"task_id": "abc-123", "file_name": "document.pdf"},
  "hmac": "a1b2c3d4e5f6..."
}
```

**事件类型 (event_type):**

| 事件类型 | 严重级别 | 说明 |
|----------|----------|------|
| `file_ingested` | INFO | 文件进入 Inbox |
| `classified` | INFO | 文件分类完成 |
| `encrypted` | INFO | 文件加密完成 |
| `decrypted` | INFO | 文件解密完成 |
| `connection_tested` | INFO | 连接测试 |
| `policy_violation` | HIGH | 策略违规 |
| `offline_policy_violation` | HIGH | 离线策略违规 |
| `cloud_fallback_used` | HIGH | 云连接降级使用 |
| `login_attempt` | INFO | 登录尝试 |
| `master_key_changed` | CRITICAL | 主密钥变更 |
| `sandbox_escape_attempt` | CRITICAL | 沙箱逃逸尝试 |
| `audit_write_failed` | HIGH | 审计日志写入失败 |
| `password_store_operation` | MEDIUM | 密码存储操作 |
| `sandbox_run_failed` | MEDIUM | 沙箱运行失败 |

### 6.2 HMAC 防篡改机制

每条日志记录包含 HMAC-SHA256 签名：

```
hmac = HMAC-SHA256(key=.audit.key, data=canonical_json(record_without_hmac))
```

- **密钥**: 256-bit，首次运行随机生成，持久化于 `.audit.key` (权限 600)
- **规范化**: JSON 按 key 排序 + 紧凑格式 (无空格)，确保签名确定性
- **验证**: `verify()` 方法逐行重新计算 HMAC 并与存储值比对
- **防时序攻击**: 使用 `hmac.compare_digest()` 进行常数时间比较

### 6.3 日志轮转

```
audit.log.ndjson         ← 当前日志 (≤ 100 MB)
audit.log.1.ndjson       ← 轮转后旧日志
```

- 日志文件达到 100 MB 时自动轮转
- 当前实现：简单单文件轮转（保留 1 份历史）
- 未来计划：可配置保留策略（按数量/时间）

### 6.4 日志导出

支持两种导出格式：

- **NDJSON**: 原始格式，包含完整的 HMAC 签名，可离线验证
- **CSV**: 人类可读格式（timestamp, event_type, details_json, hmac）

导出前自动进行完整性验证，篡改日志无法导出。

### 6.5 实时告警

审计日志内置告警规则，支持注册外部回调：

```
严重级别:
  CRITICAL: 解密失败 ≥ 3 次、主密钥变更、沙箱逃逸尝试
  HIGH:     云连接降级使用、策略违规、审计日志写入失败
  MEDIUM:   沙箱运行失败、密码存储操作、首次云连接
```

---

## 7. 安全最佳实践

### 7.1 用户指南

#### 密码管理
- 使用强主密码（≥ 16 字符，含大小写字母、数字、符号）
- 推荐使用密码管理器（KeePassXC / pass）存储密码，而非直接输入
- 不同环境使用不同密码（开发 ≠ 生产）
- 定期更换主密码（3-6 个月）

#### 备份策略
- 定期备份 Vault 目录到加密的外部存储
- 备份时包含所有辅助文件（salt 文件、审计日志密钥）
- 测试恢复流程：从备份恢复后验证数据完整性
- 备份介质应与主设备物理隔离

#### 系统更新
- 及时更新 Python 依赖（关注 `pip list --outdated`）
- 关注 AegisVault 安全公告
- 升级前备份配置文件和数据
- 测试沙箱工具版本（bwrap、keepassxc-cli）兼容性

### 7.2 部署建议

#### 生产环境
```
[推荐] FilePassword (非 Windows) / DPAPI (Windows 客户端) / TPM (Windows 服务器)
[推荐] sandbox_enabled = true
[推荐] enforce_offline_policy = true
[推荐] cloud_fallback_enabled = false
[推荐] windows_hello_enabled = true (Windows)
```

#### 开发环境
```
[可用] FilePassword (任何平台)
[可用] sandbox_enabled = false (如沙箱工具未安装)
[可用] cloud_fallback_enabled = true (测试用)
```

### 7.3 安全操作清单

- [ ] 确认主密钥 Provider 已正确配置
- [ ] 确认沙箱状态（`sandbox_enabled`）
- [ ] 确认离线策略状态（`enforce_offline_policy`）
- [ ] 确认云连接白名单（需授权才能绕过策略）
- [ ] 验证审计日志完整性（`AuditLogger.verify()`）
- [ ] 检查最近的告警事件
- [ ] 确认文件系统权限（Vault 目录 700, 审计日志 600）
- [ ] 确认防火墙规则已应用（Windows）

---

## 8. 已知限制与未来计划

### 8.1 已知限制

| 限制 | 影响 | 缓解措施 |
|------|------|----------|
| Python bytes 不可原地覆写 | 主密钥在内存中残留 | `secure_zero()` best-effort, 未来使用 mmap |
| 日志轮转仅保留 1 份 | 历史审计数据可能丢失 | 使用外部日志收集系统 |
| HMAC 密钥无独立备份机制 | 密钥丢失后无法验证旧日志 | 手动备份 `.audit.key` |
| TPM/DPAPI 仅 Windows | Linux 用户必须使用 FilePassword | 未来支持 Linux TPM (tpm2_unseal) |
| 无硬件安全模块 (HSM) | 密钥仅受操作系统或 TPM 保护 | 未来支持 PKCS#11 / yubikey |
| 无双因素认证 | 仅密码即可派生密钥 | 未来支持 FIDO2 / WebAuthn |
| bubblewrap 依赖外部安装 | Linux 沙箱需手动安装 bwrap | 提供安装脚本 |
| AES-GCM nonce 重用风险 | 同一 key 重用的 nonce 会灾难性失败 | 每次加密使用 os.urandom(12) |

### 8.2 未来计划

#### 短期 (v0.2 - v0.3)
- [ ] 内存安全：使用 Rust/PyO3 重写密钥派生模块（真正的安全清零）
- [ ] FIDO2/WebAuthn 支持：USB 安全密钥作为第二因素
- [ ] 审计日志弹性：可配置轮转策略（按时间/数量/大小）
- [ ] 日志转发：支持 syslog / SIEM 集成

#### 中期 (v0.4 - v0.5)
- [ ] Linux TPM 支持：使用 tpm2-tss 用户态库
- [ ] 密钥分片/秘密共享：Shamir's Secret Sharing 备份方案
- [ ] 威胁检测：异常模式检测（如异常高频解密请求）
- [ ] SELinux/AppArmor 配置文件：强制访问控制策略
- [ ] 安全远程擦除：远程吊销主密钥

#### 长期 (v1.0+)
- [ ] 形式化验证：使用 ProVerif/Tamarin 验证密钥交换协议
- [ ] 同态加密探索：对加密数据执行有限操作
- [ ] 多方计算 (MPC)：分布式密钥管理与计算
- [ ] 后量子密码学：评估 CRYSTALS-Kyber 等 PQ 算法
- [ ] FIPS 140-3 合规：使用 FIPS 认证的密码模块

---

## 附录 A: 密码学参数参考

| 参数 | 值 | 标准/来源 |
|------|----|-----------| 
| 主密钥长度 | 256-bit | NIST SP 800-131Ar2 |
| 密钥派生 (Vault Key) | HKDF-SHA256 | RFC 5869 |
| 密钥派生 (File Key) | Argon2id | RFC 9106 |
| 对称加密 | AES-256-GCM | NIST SP 800-38D |
| Nonce 长度 | 96-bit (12 bytes) | GCM 推荐 |
| 认证标签 | 128-bit (16 bytes) | GCM 默认 |
| 审计日志 HMAC | HMAC-SHA256 | FIPS 198-1 |
| 审计密钥长度 | 256-bit | NIST SP 800-107r1 |
| 随机数生成 | `os.urandom()` → `/dev/urandom` | 内核 CSPRNG |

## 附录 B: 报告安全问题

如发现安全漏洞，请通过以下渠道报告（而非公开 Issue）：

- GPG 密钥: [待发布]
- 安全邮箱: security@aegisvault.dev (示例)
- 响应时间: 48 小时内确认，7 天内提供修复方案

我们遵循协调漏洞披露 (CVD) 原则，在修复发布前不会公开漏洞细节。

---

> *此文档随 AegisVault 版本迭代持续更新。最新版本请参见项目仓库。*
