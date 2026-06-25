# AegisVault 移动端架构文档

> 版本: 1.0 | 基于 AegisVault Phase 5 服务端架构 | 最后更新: 2026-06-26

---

## 目录

1. [移动端架构概述](#1-移动端架构概述)
2. [API 端点映射](#2-api-端点映射)
3. [iOS App 技术方案](#3-ios-app-技术方案)
4. [Android App 技术方案](#4-android-app-技术方案)
5. [App 核心功能设计](#5-app-核心功能设计)
6. [安全注意事项](#6-安全注意事项)

---

## 1. 移动端架构概述

### 1.1 系统架构图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AegisVault 移动端架构                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐           ┌──────────────────┐                    │
│  │   iOS App        │           │  Android App      │                    │
│  │   (Swift/SwiftUI)│           │  (Kotlin/Compose)  │                    │
│  │                  │           │                   │                    │
│  │ ┌──────────────┐ │           │ ┌───────────────┐ │                    │
│  │ │ UI Layer     │ │           │ │ UI Layer      │ │                    │
│  │ │ SwiftUI+     │ │           │ │ Jetpack       │ │                    │
│  │ │ Combine      │ │           │ │ Compose       │ │                    │
│  │ └──────┬───────┘ │           │ └──────┬────────┘ │                    │
│  │        │         │           │        │          │                    │
│  │ ┌──────┴───────┐ │           │ ┌──────┴────────┐ │                    │
│  │ │ Network      │ │           │ │ Network       │ │                    │
│  │ │ Alamofire/   │ │           │ │ OkHttp/       │ │                    │
│  │ │ URLSession   │ │           │ │ Retrofit      │ │                    │
│  │ └──────┬───────┘ │           │ └──────┬────────┘ │                    │
│  │        │         │           │        │          │                    │
│  │ ┌──────┴───────┐ │           │ ┌──────┴────────┐ │                    │
│  │ │ Security     │ │           │ │ Security      │ │                    │
│  │ │ Keychain     │ │           │ │ EncryptedSP   │ │                    │
│  │ └──────────────┘ │           │ └───────────────┘ │                    │
���  └────────┬─────────┘           └────────┬──────────┘                    │
│           │                              │                               │
│           │     HTTPS (TLS 1.3)          │                               │
│           │     Certificate Pinning      │                               │
│           │                              │                               │
│           └──────────┬───────────────────┘                               │
│                      │                                                   │
│                      ▼                                                   │
│  ┌──────────────────────────────────────┐                                │
│  │        AegisVault API Server          │                                │
│  │        (FastAPI + Uvicorn)            │                                │
│  │                                       │                                │
│  │  ┌─────────────────────────────────┐  │                                │
│  │  │ Bearer Token Authentication     │  │                                │
│  │  │ (AEGISVAULT_API_TOKEN 环境变量)  │  │                                │
│  │  └─────────────────────────────────┘  │                                │
│  │                                       │                                │
│  │  ┌──────────┐ ┌──────────┐           │                                │
│  │  │ Vault    │ │ Sync     │           │                                │
│  │  │ Endpoints│ │ Endpoints│           │                                │
│  │  │ (7 个)   │ │ (2 个)   │           │                                │
│  │  └────┬─────┘ └────┬─────┘           │                                │
│  │       │            │                  │                                │
│  └───────┼────────────┼──────────────────┘                                │
│          │            │                                                   │
│          ▼            ▼                                                   │
│  ┌──────────────────────────────────────┐                                │
│  │        AegisVault Core               │                                │
│  │                                       │                                │
│  │  ┌────────┐ ┌────────┐ ┌──────────┐  │                                │
│  │  │Agent   │ │Task    │ │Security  │  │                                │
│  │  │Orch.   │ │Store   │ │KeyTree   │  │                                │
│  │  └────────┘ └────────┘ └──────────┘  │                                │
│  │                                       │                                │
│  │  ┌────────┐ ┌────────┐ ┌──────────┐  │                                │
│  │  │Sync    │ │Model   │ │Vault     │  │                                │
│  │  │Engine  │ │(AI/ML) │ │Manager   │  │                                │
│  │  └────────┘ └────────┘ └──────────┘  │                                │
│  └──────────────────────────────────────┘                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 通信协议

| 协议类型 | 用途 | 传输方式 |
|---------|------|---------|
| REST API (HTTPS) | 保险库浏览、搜索、文件下载、分类、同步状态查询、同步触发 | HTTP/1.1 over TLS 1.3 |
| WebSocket (计划) | 实时通知推送（文件变更、同步进度） | WSS over TLS 1.3 |
| Bearer Token | API 身份认证 | `Authorization: Bearer <token>` 请求头 |

### 1.3 安全模型

AegisVault 采用**端到端加密 (E2EE)** 安全模型。核心设计原则：

```
用户设备                     API 服务器                  存储层
   │                           │                          │
   │  ┌─────────────────────┐  │                          │
   │  │ 明文文档             │  │                          │
   │  └─────────┬───────────┘  │                          │
   │            │ 加密          │                          │
   │            ▼              │                          │
   │  ┌─────────────────────┐  │                          │
   │  │ AES-256-GCM 密文     │──┼──► 存储密文 ──────────► 加密文件
   │  └─────────────────────┘  │                          │
   │                           │                          │
   │  移动端请求下载            │                          │
   │  ──────────────────────►  │                          │
   │                           │  读取密文                 │
   │                           │  ─────────────────────►  │
   │                           │                          │
   │                           │  服务端解密               │
   │                           │  (VaultManager.decrypt)   │
   │                           │                          │
   │  明文内容 (TLS加密传输)    │                          │
   │  ◄──────────────────────  │                          │
   │                           │                          │
   ▼                           │                          │
 ┌─────────────────────┐       │                          │
 │ 显示/查看            │       │                          │
 │ (不在设备端缓存)      │       │                          │
 └─────────────────────┘       │                          │
```

**关键约束**：
- App 端**不解密**——解密操作在 API 服务器端执行（`api/server.py:274-287`）
- App 端**不持久化缓存**解密后的文件内容
- 传输过程全程 **TLS 1.3** 加密
- API 服务器绑定 `127.0.0.1`，设计为通过 VPN/内网代理访问

---

## 2. API 端点映射

### 2.1 端点总览

以下端点来源于 `api/server.py` 的实际实现：

| 端点 | 方法 | 用途 | 移动端场景 | 请求参数 | 响应格式 |
|------|------|------|-----------|---------|---------|
| `/health` | GET | 健康检查 | App 连接测试 | 无 | `{"status":"ok","version":"1.0.0"}` |
| `/vault/status` | GET | 保险库状态 | 首页仪表盘 | Bearer Token | 文件计数 + 分类统计 + 最近任务 |
| `/vault/files` | GET | 文件列表 | 保险库浏览 | `category`, `offset`, `limit` | 分页文件列表 |
| `/vault/files/{file_id}` | GET | 文件元数据 | 文件详情页 | UUID 格式 file_id | 元数据 + 标签 |
| `/vault/files/{file_id}/download` | GET | 文件下载(解密) | 文件查看 | UUID 格式 file_id | `FileResponse` (二进制) |
| `/vault/search` | POST | 搜索 | 全量搜索 | `SearchQuery` JSON | `[SearchResult]` 数组 |
| `/vault/classify` | POST | 手动分类 | 触发分类 | Bearer Token | 操作确认 |
| `/sync/status` | GET | 同步状态 | 同步页面 | Bearer Token | 同步引擎状态 |
| `/sync/trigger` | POST | 触发同步 | 手动同步 | Bearer Token | 操作确认 |

### 2.2 各端点详细设计

#### 2.2.1 保险库浏览 — `GET /vault/files`

**请求**：
```
GET /vault/files?category=financial&offset=0&limit=20
Authorization: Bearer <token>
```

**参数说明**：
| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `category` | string | 否 | - | 分类过滤（如 `financial`、`identity`、`medical`） |
| `offset` | int | 否 | 0 | 分页偏移 (>= 0) |
| `limit` | int | 否 | 50 | 每页数量 (1-500) |

**响应**（`api/server.py:198-212`）：
```json
{
  "total": 142,
  "offset": 0,
  "limit": 20,
  "files": [
    {
      "task_id": "550e8400-e29b-41d4-a716-446655440000",
      "vault_path": "/vault/financial/2024_tax_return.pdf.enc",
      "category": "financial",
      "summary": "2024年度个人所得税申报表",
      "tags": ["税务", "2024", "个人"]
    }
  ]
}
```

**移动端实现要点**：
- 使用无限滚动（Infinite Scroll），`offset += limit` 加载更多
- 缓存首页数据以支持离线浏览（加密的元数据，不含文件内容）
- 分类筛选器作为顶部 Tab 或侧边筛选菜单

#### 2.2.2 文件搜索 — `POST /vault/search`

**请求**：
```json
POST /vault/search
Authorization: Bearer <token>
Content-Type: application/json

{
  "query": "2024年税务申报",
  "top_k": 10,
  "semantic": true
}
```

**参数说明**（`api/schemas.py:72-77`）：
| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `query` | string | 是 | - | 自然语言搜索查询 |
| `top_k` | int | 否 | 5 | 返回结果数 (1-100) |
| `semantic` | bool | 否 | false | 是否启用语义搜索 |

**响应**（`api/schemas.py:80-86`）：
```json
[
  {
    "vault_path": "/vault/financial/2024_tax_return.pdf.enc",
    "category": "financial",
    "summary": "2024年度个人所得税申报表",
    "score": 0.92
  }
]
```

**移动端实现要点**：
- 搜索栏应提供语义搜索开关（Toggle）
- 关键词搜索（`semantic=false`）：基于文件元数据/摘要的快速匹配
- 语义搜索（`semantic=true`）：基于 AI embedding 的语义相似度搜索
- 建议添加搜索历史记录（本地存储，加密）
- 结果列表点击进入文件详情

#### 2.2.3 文件下载 — `GET /vault/files/{file_id}/download`

**请求**：
```
GET /vault/files/550e8400-e29b-41d4-a716-446655440000/download
Authorization: Bearer <token>
```

**说明**（`api/server.py:247-292`）：
- 服务器端执行解密：`derive_vault_key → VaultManager.decrypt`
- 返回原始文件（解密后），作为 `FileResponse` 流式传输
- file_id 必须是有效 UUID 格式，否则返回 400
- 文件不存在或解密失败返回 404/500

**移动端实现要点**：
- 使用流式下载 + 临时文件存储
- 显示下载进度指示器
- 支持预览（PDF/图片/文本）或"打开方式"（系统分享）
- **严禁**缓存解密后的文件内容——预览完毕后立即删除临时文件
- 建议在 App 进入后台时清理所有临时解密文件

#### 2.2.4 同步状态 — `GET /sync/status`

**请求**：
```
GET /sync/status
Authorization: Bearer <token>
```

**响应**（`api/server.py:320-331`）：
```json
{
  "available": true,
  "message": "Sync engine active"
}
```

**移动端实现要点**：
- 在同步页面轮询此端点（建议间隔 30 秒）
- 当 `available=false` 时显示"同步引擎未启动"提示
- 扩展响应体以包含对等设备列表、最后同步时间等（需服务端扩展）

#### 2.2.5 触发同步 — `POST /sync/trigger`

**请求**：
```
POST /sync/trigger
Authorization: Bearer <token>
```

**响应**（`api/server.py:335-342`）：
```json
{
  "message": "Sync triggered successfully"
}
```

**移动端实现要点**：
- 提供"手动同步"按钮
- 触发后轮询 `/sync/status` 显示进度
- 支持下拉刷新手势触发同步

---

## 3. iOS App 技术方案

### 3.1 技术栈

| 层级 | 技术选型 | 版本要求 |
|------|---------|---------|
| 语言 | Swift 5.9+ | Xcode 15+ |
| UI 框架 | SwiftUI | iOS 17+ |
| 响应式编程 | Combine | 系统内置 |
| 网络层 | Alamofire | 5.9+ |
| 图片加载 | Kingfisher | 8.0+ |
| 安全存储 | Keychain Services | 系统框架 |
| 生物识别 | LocalAuthentication | 系统框架 |
| WebSocket | URLSessionWebSocketTask | 系统框架 |
| JSON 解析 | Codable | 系统框架 |
| 依赖管理 | Swift Package Manager (SPM) | Xcode 集成 |

### 3.2 推荐目录结构

```
AegisVault-iOS/
├── AegisVaultApp.swift              # App 入口 + 生命周期
├── AppDelegate.swift                # 推送通知注册
├── Info.plist                       # 配置 + ATS 例外
│
├── Models/                          # 数据模型层
│   ├── VaultFile.swift              # 文件模型 (Codable)
│   ├── SearchQuery.swift            # 搜索请求模型
│   ├── SearchResult.swift           # 搜索结果模型
│   ├── VaultStatus.swift            # 保险库状态模型
│   ├── SyncStatus.swift             # 同步状态模型
│   └── DeviceInfo.swift             # 设备信息模型
│
├── Networking/                      # 网络层
│   ├── APIClient.swift              # API 客户端 (Alamofire)
│   ├── APIRouter.swift              # 路由定义 (URLRequestConvertible)
│   ├── AuthInterceptor.swift        # Bearer Token 注入
│   ├── CertificatePinning.swift     # 证书固定
│   └── WebSocketManager.swift       # WebSocket 管理
│
├── Security/                        # 安全层
│   ├── KeychainManager.swift        # Keychain 读写封装
│   ├── BiometricAuth.swift          # Face ID/Touch ID
│   ├── CryptoUtilities.swift        # 密码学工具函数
│   └── SecureEnclave.swift          # Secure Enclave 操作
│
├── ViewModels/                      # 视图模型层
│   ├── VaultBrowserViewModel.swift   # 保险库浏览
│   ├── FileDetailViewModel.swift     # 文件详情
│   ├── SearchViewModel.swift         # 搜索
│   ├── SyncViewModel.swift           # 同步管理
│   ├── PairingViewModel.swift        # 设备配对
│   └── SettingsViewModel.swift       # 设置
│
├── Views/                           # 视图层
│   ├── MainTabView.swift            # 主 Tab 导航
│   ├── Dashboard/                   # 首页仪表盘
│   │   └── DashboardView.swift
│   ├── Vault/                       # 保险库
│   │   ├── VaultBrowserView.swift
│   │   ├── VaultFileRow.swift
│   │   └── FileDetailView.swift
│   ├── Search/                      # 搜索
│   │   └── SearchView.swift
│   ├── Sync/                        # 同步
│   │   ├── SyncView.swift
│   │   └── DevicePairingView.swift
│   ├── Preview/                     # 文件预览
│   │   └── FilePreviewView.swift
│   └── Settings/                    # 设置
│       └── SettingsView.swift
│
├── Services/                        # 业务服务层
│   ├── VaultService.swift           # 保险库业务逻辑
│   ├── SyncService.swift            # 同步业务逻辑
│   └── PairingService.swift         # 配对业务逻辑
│
├── Utilities/                       # 工具类
│   ├── DateFormatter+Extensions.swift
│   ├── FileTypeDetector.swift
│   └── UIDevice+Extensions.swift
│
└── Resources/                       # 资源
    ├── Assets.xcassets
    └── Localizable.xcstrings        # 多语言字符串
```

### 3.3 关键依赖列表

```swift
// Package.swift 或 Xcode SPM 依赖
dependencies: [
    // 网络层
    .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.9.0"),
    
    // 图片缓存 (用于文件缩略图)
    .package(url: "https://github.com/onevcat/Kingfisher.git", from: "8.0.0"),
    
    // 密钥管理 (可选 - 简化 Keychain 操作)
    .package(url: "https://github.com/kishikawakatsumi/KeychainAccess.git", from: "4.2.0"),
    
    // 加密 (可选 - iOS 系统 CryptoKit 可满足大部分需求)
    // 当需要与 Python cryptography 库互通时使用
    .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
]
```

---

## 4. Android App 技术方案

### 4.1 技术栈

| 层级 | 技术选型 | 版本要求 |
|------|---------|---------|
| 语言 | Kotlin | 2.0+ |
| UI 框架 | Jetpack Compose | BOM 2024.06+ |
| 最低 SDK | minSdk 26 (Android 8.0) | Keystore 支持 |
| 目标 SDK | targetSdk 34 (Android 14) | |
| 网络层 | OkHttp 4 + Retrofit 2 | 最新稳定版 |
| 图片加载 | Coil | 3.0+ |
| 安全存储 | EncryptedSharedPreferences | AndroidX Security |
| 生物识别 | BiometricPrompt | AndroidX Biometric |
| 依赖注入 | Hilt (Dagger) | 2.51+ |
| JSON 解析 | Moshi / kotlinx.serialization | 最新稳定版 |
| 协程 | Kotlin Coroutines + Flow | 1.8+ |
| WebSocket | OkHttp WebSocket | 4.x |

### 4.2 推荐目录结构

```
AegisVault-Android/
├── app/
│   ├── build.gradle.kts
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── java/com/aegisvault/android/
│   │   │   ├── AegisVaultApp.kt          # Application 类 (Hilt)
│   │   │   ├── MainActivity.kt            # 主 Activity
│   │   │   │
│   │   │   ├── data/                      # 数据层
│   │   │   │   ├── model/                 # 数据模型
│   │   │   │   │   ├── VaultFile.kt
│   │   │   │   │   ├── SearchQuery.kt
│   │   │   │   │   ├── SearchResult.kt
│   │   │   │   │   ├── VaultStatus.kt
│   │   │   │   │   ├── SyncStatus.kt
│   │   │   │   │   └── DeviceInfo.kt
│   │   │   │   │
│   │   │   │   ├── remote/                # 远程数据源
│   │   │   │   │   ├── ApiService.kt      # Retrofit 接口定义
│   │   │   │   │   ├── AuthInterceptor.kt # Bearer Token 拦截器
│   │   │   │   │   └── CertificatePinner.kt
│   │   │   │   │
│   │   │   │   ├── local/                 # 本地数据源
│   │   │   │   │   └── SecurePreferences.kt
│   │   │   │   │
│   │   │   │   └── repository/            # 数据仓库
│   │   │   │       ├── VaultRepository.kt
│   │   │   │       ├── SearchRepository.kt
│   │   │   │       └── SyncRepository.kt
│   │   │   │
│   │   │   ├── domain/                    # 领域层 (可选)
│   │   │   │   └── usecase/
│   │   │   │       ├── BrowseVaultUseCase.kt
│   │   │   │       ├── SearchFilesUseCase.kt
│   │   │   │       └── DownloadFileUseCase.kt
│   │   │   │
│   │   │   ├── ui/                        # UI 层
│   │   │   │   ├── theme/
│   │   │   │   │   ├── Theme.kt
│   │   │   │   │   ├── Color.kt
│   │   │   │   │   └── Type.kt
│   │   │   │   │
│   │   │   │   ├── navigation/
│   │   │   │   │   └── NavGraph.kt
│   │   │   │   │
│   │   │   │   ├── dashboard/
│   │   │   │   │   ├── DashboardScreen.kt
│   │   │   │   │   └── DashboardViewModel.kt
│   │   │   │   │
│   │   │   │   ├── vault/
│   │   │   │   │   ├── VaultBrowserScreen.kt
│   │   │   │   │   ├── VaultBrowserViewModel.kt
│   │   │   │   │   └── FileDetailScreen.kt
│   │   │   │   │
│   │   │   │   ├── search/
│   │   │   │   │   ├── SearchScreen.kt
│   │   │   │   │   └── SearchViewModel.kt
│   │   │   │   │
│   │   │   │   ├── sync/
│   │   │   │   │   ├── SyncScreen.kt
│   │   │   │   │   ├── SyncViewModel.kt
│   │   │   │   │   └── PairingScreen.kt
│   │   │   │   │
│   │   │   │   ├── preview/
│   │   │   │   │   └── FilePreviewScreen.kt
│   │   │   │   │
│   │   │   │   └── settings/
│   │   │   │       └── SettingsScreen.kt
│   │   │   │
│   │   │   ├── security/                  # 安全模块
│   │   │   │   ├── BiometricManager.kt
│   │   │   │   ├── KeystoreManager.kt
│   │   │   │   └── CryptoUtils.kt
│   │   │   │
│   │   │   ├── di/                        # 依赖注入
│   │   │   │   ├── NetworkModule.kt
│   │   │   │   ├── SecurityModule.kt
│   │   │   │   └── RepositoryModule.kt
│   │   │   │
│   │   │   └── util/
│   │   │       ├── Extensions.kt
│   │   │       └── FileTypeDetector.kt
│   │   │
│   │   └── res/
│   │       ├── values/
│   │       │   ├── strings.xml
│   │       │   └── themes.xml
│   │       └── ...
│   │
│   └── src/test/                          # 单元测试
│   └── src/androidTest/                   # 仪器测试
│
├── build.gradle.kts                       # 项目级构建
├── gradle.properties
└── settings.gradle.kts
```

### 4.3 关键依赖列表

```kotlin
// app/build.gradle.kts

dependencies {
    // Compose BOM (统一版本管理)
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    
    // Jetpack Compose
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.0")
    
    // 网络层
    implementation("com.squareup.retrofit2:retrofit:2.11.0")
    implementation("com.squareup.retrofit2:converter-moshi:2.11.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.okhttp3:logging-interceptor:4.12.0")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    
    // 图片加载
    implementation("io.coil-kt:coil-compose:2.6.0")
    
    // 安全存储
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    
    // 生物识别
    implementation("androidx.biometric:biometric:1.4.0")
    
    // 依赖注入
    implementation("com.google.dagger:hilt-android:2.51")
    kapt("com.google.dagger:hilt-android-compiler:2.51")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")
    
    // 协程
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")
    
    // FCM 推送
    implementation("com.google.firebase:firebase-messaging-ktx:24.0.0")
    
    // DataStore (替代 SharedPreferences 用于非敏感设置)
    implementation("androidx.datastore:datastore-preferences:1.1.1")
}
```

---

## 5. App 核心功能设计

### 5.1 保险库浏览

#### 交互流程

```
┌─────────────────────────────────────────────────────────────┐
│  保险库浏览                                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  [全部] [财务] [身份] [医疗] [法律] [其他]            │  │  ← 分类 Tab
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  🔍 搜索保险库文件...                                 │  │  ← 搜索入口
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐     │
│  │ 📄       │ │ 📄       │ │ 📄       │ │ 📄       │     │
│  │ 文件名    │ │ 文件名    │ │ 文件名    │ │ 文件名    │     │
│  │ 分类标签  │ │ 分类标签  │ │ 分类标签  │ │ 分类标签  │     │
│  │ 摘要...   │ │ 摘要...   │ │ 摘要...   │ │ 摘要...   │     │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘     │
│                                                             │
│  ← 下拉刷新         加载更多 →                              │
└─────────────────────────────────────────────────────────────┘
```

#### 数据流

```
View (Compose/SwiftUI)
    │
    │ 用户操作 (下拉/滚动/点击)
    ▼
ViewModel
    │
    │ 发起 API 请求
    ▼
Repository → ApiService
    │
    │ GET /vault/files?category=X&offset=N&limit=20
    ▼
API Server → TaskStore.list_vault_files()
    │
    │ 分页响应
    ▼
ViewModel.updateState()
    │
    │ StateFlow / @Published
    ▼
View 自动刷新
```

#### 关键状态管理

```
数据加载状态：
  Loading → 显示骨架屏 (Skeleton)
  Success → 显示文件列表
  Empty   → 显示空状态插图
  Error   → 显示错误信息 + 重试按钮

分页状态：
  hasMore == true  → 允许继续滚动加载
  hasMore == false → 显示"已加载全部"
  isLoadingMore   → 底部显示加载指示器
```

### 5.2 文件搜索

#### 搜索界面

```
┌─────────────────────────────────────────────────────────────┐
│  搜索                                                        │
├─────��───────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────────────────┐ ┌──────────┐    │
│  │  输入搜索关键词...                    │ │ 语义搜索  │    │
│  └──────────────────────────────────────┘ └──────────┘    │
│                                         [开启/关闭]         │
│                                                             │
│  ── 搜索结果 (5) ──────────────────────────────────────     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 📄 2024年度税务申报.pdf                                │  │
│  │    分类: 财务  |  匹配度: 92%  |  标签: 税务, 2024    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 📄 工商银行流水_2024.pdf                               │  │
│  │    分类: 财务  |  匹配度: 87%  |  标签: 银行, 流水    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ── 搜索历史 ──────────────────────────────────────────     │
│  📌 税务申报    📌 身份证    📌 合同                         │
└─────────────────────────────────────────────────────────────┘
```

#### 语义搜索开关说明

| 模式 | semantic | 原理 | 速度 | 准确度 |
|------|----------|------|------|--------|
| 关键词匹配 | `false` | 基于文件摘要/标签的字符串匹配 | 快 | 精确匹配 |
| 语义搜索 | `true` | 基于 embedding 向量相似度 | 较慢 | 理解语义 |

#### ViewModel 核心逻辑 (伪代码)

```kotlin
// SearchViewModel.kt
class SearchViewModel(
    private val searchRepository: SearchRepository
) : ViewModel() {
    
    private val _searchResults = MutableStateFlow<List<SearchResult>>(emptyList())
    val searchResults: StateFlow<List<SearchResult>> = _searchResults
    
    private val _isSearching = MutableStateFlow(false)
    val isSearching: StateFlow<Boolean> = _isSearching
    
    private val _semanticEnabled = MutableStateFlow(false)
    val semanticEnabled: StateFlow<Boolean> = _semanticEnabled
    
    fun search(query: String) {
        viewModelScope.launch {
            _isSearching.value = true
            try {
                val results = searchRepository.search(
                    SearchQuery(
                        query = query,
                        topK = 10,
                        semantic = _semanticEnabled.value
                    )
                )
                _searchResults.value = results
                saveSearchHistory(query) // 本地加密存储
            } catch (e: Exception) {
                // 错误处理
            } finally {
                _isSearching.value = false
            }
        }
    }
    
    fun toggleSemantic() {
        _semanticEnabled.value = !_semanticEnabled.value
    }
}
```

### 5.3 文件解密查看

#### 安全下载与预览流程

```
用户点击文件
    │
    ▼
┌─────────────────────────────┐
│ 生物特征验证                  │
│ (Face ID / Touch ID /       │
│  Android Biometric)          │
│                             │
│  验证通过? ──否──► 拒绝访问   │
│   │                         │
│   是                        │
└─────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│ 下载解密文件                  │
│ GET /vault/files/{id}/      │
│     download                 │
│                             │
│ ████████████░░░░ 75%        │
└─────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│ 临时存储 (App 沙盒 tmp/)      │
│ 文件解密后内容               │
└─────┬───────────────────────┘
      │
      ▼
┌─────��───────────────────────┐
│ 预览 / 分享                  │
│ - PDF: PDFKit/PDFRenderer   │
│ - 图片: 原生预览              │
│ - 文本: 文本查看器            │
│ - 其他: "打开方式" 分享菜单   │
└─────┬───────────────────────┘
      │
      ▼
┌─────────────────────────────┐
│ 清理                         │
│ - 用户关闭预览 → 删除临时文件  │
│ - App 进入后台 → 删除临时文件  │
│ - 30分钟超时 → 自动清理       │
└─────��───────────────────────┘
```

#### 关键安全措施

```
// iOS - 临时文件管理
class TempFileManager {
    private let fileManager = FileManager.default
    private let tempDir: URL
    
    init() {
        tempDir = fileManager.temporaryDirectory
            .appendingPathComponent("aegisvault-decrypted")
        try? fileManager.createDirectory(at: tempDir, 
            withIntermediateDirectories: true)
    }
    
    func storeTemp(data: Data, filename: String) -> URL {
        let url = tempDir.appendingPathComponent(filename)
        // 设置文件保护级别 - 设备锁定时不可访问
        try? data.write(to: url, options: .completeFileProtection)
        return url
    }
    
    func cleanup() {
        try? fileManager.removeItem(at: tempDir)
    }
}

// 在 SceneDelegate / Application 生命周期中注册清理
func applicationDidEnterBackground(_ application: UIApplication) {
    TempFileManager().cleanup()
}
```

### 5.4 设备配对流程

#### PAKE 配对协议（基于 `sync/auth.py` 实现）

```
┌───────────────────┐                         ┌───────────────────┐
│   Device A (主设备) │                         │  Device B (新设备)  │
│   (配对发起方)      │                         │  (配对接受方)       │
└─────────┬─────────┘                         └─────────┬─────────┘
          │                                             │
          │ 1. 生成 6 位配对码 (5分钟有效)                │
          │    生成 X25519 密钥对                         │
          │    ┌─────────────────────┐                  │
          │    │ 配对码: 482917      │                  │
          │    │ 公钥: pub_A         │                  │
          │    └─────────────────────┘                  │
          │                                             │
          │ 2. 用户手动输入配对码                         │
          │    到 Device B                               │
          │ ═══════════════════════►                   │
          │                                             │
          │                                    3. 生成 X25519 密钥对
          │                                       公钥: pub_B
          │                                             │
          │                     4. 发送 pub_B + 配对码     │
          │ ◄═══════════════════════                    │
          │                                             │
          │ 5. 验证配对码                                 │
          │    DH 计算: shared = X25519(priv_A, pub_B)  │
          │    HKDF(salt=配对码) → 32字节共享密钥         │
          │                                             │
          │                                        6. DH 计算:
          │                                           shared = X25519(priv_B, pub_A)
          │                                           HKDF → 相同共享密钥
          │                                             │
          │ 7. 双方: 密封共享密钥到设备存储                │
          │    iOS: Keychain | Android: EncryptedSP      │
          │                                             │
          │ 8. 配对完成                                  │
          │    双方可进行端到端加密同步                    │
          └                                             ┘
```

#### 移动端配对 UI 流程

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Step 1          │     │  Step 2          │     │  Step 3          │
│  显示配对码       │ ──► │  扫描设备/输入码  │ ──► │  配对确认         │
│                  │     │                  │     │                  │
│ ┌──────────────┐ │     │ ┌──────────────┐ │     │ 设备名称:         │
│ │              │ │     │ │  输入配对码    │ │     │ "我的 iPhone"    │
│ │   482917     │ │     │ │              │ │     │                  │
│ │              │ │     │ │  [4][8][2]   │ │     │ 配对码: 482917   │
│ │              │ │     │ │  [9][1][7]   │ │     │                  │
│ │  5分钟有效    │ │     │ │              │ │     │ [确认配对]        │
│ └──────────────┘ │     │ └──────────────┘ │     │                  │
│                  │     │                  │     │                  │
│ [复制] [分享]    │     │ 或扫描二维码      │     │ 配对成功 ✓       │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

#### 配对状态机

```
                    ┌─────────┐
                    │  IDLE   │
                    └────┬────┘
                         │ 生成配对码
                         ▼
                    ┌─────────┐
             ┌─────►│WAITING  │◄─────┐
             │      └────┬────┘      │
             │           │            │
             │ 超时       │ 收到请求    │ 配对码错误
             │           ▼            │
             │      ┌─────────┐      │
             │      │VERIFYING├──────┘
             │      └────┬────┘
             │           │ 验证通过
             │           ▼
             │      ┌─────────┐
             │      │DERIVING │  (HKDF 密钥派生)
             │      └────┬──��─┘
             │           │ 完成
             │           ▼
             │      ┌─────────┐
             └──────│EXPIRED  │──────► 重新生成
                    └─────────┘
                           │
                           ▼
                    ┌─────────┐
                    │ PAIRED  │  配对成功
                    └─────────┘
```

### 5.5 同步触发与状态显示

#### 同步页面设计

```
┌─────────────────────────────────────────────────────────────┐
│  设备同步                                                     │
├─────��───────────────────────────────────────────────────────┤
│                                                             │
│  同步状态: 🟢 在线                   最后同步: 2分钟前        │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                                                      │  │
│  │         ┌──────┐         ┌──────┐         ┌──────┐  │  │
│  │         │ 📱   │ ═══════ │ 💻   │ ═══════ │ 📱   │  │  │
│  │         │ 本机  │  已同步  │ Mac  │  已同步  │ iPad │  │  │
│  │         └──────┘         └──────┘         └──────┘  │  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ── 已配对设备 ─────────────────────────────────────────     │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 🟢 MacBook Pro          最后同步: 2 分钟前            │  │
│  │    文件: 142 个 | 版本一致                            │  │
│  └──────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 🟢 iPad Air             最后同步: 1 小时前            │  │
│  │    文件: 142 个 | 版本一致                            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────���───────────────────────────────────────────────┐  │
│  │              [ 手动同步 ]                              │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ── 同步日志 ──────────────────────────────────────────     │
│  14:32  与 MacBook Pro 同步完成 - 0 个文件更新               │
│  13:15  与 iPad 同步完成 - 3 个新文件                       │
│  11:00  自动同步检查 - 无需同步                             │
└─────────────────────────────────────────────────────────────┘
```

#### 同步操作 API 调用序列

```
触发同步顺序:

1. POST /sync/trigger          → 启动同步引擎
2. 轮询 GET /sync/status       → 获取同步状态
   (每 5 秒，持续直到状态稳定)
3. GET /vault/status           → 刷新保险库状态
   (文件计数变更)
4. GET /vault/files            → 刷新文件列表
   (获取新增/修改的文件)

连接状态枚举:
  DISCONNECTED  → 同步引擎未启动
  CONNECTING    → 正在连接对等设备
  SYNCING       → 正在同步文件
  SYNCED        → 同步完成
  ERROR         → 同步出错
```

### 5.6 推送通知

#### 通知架构

```
┌──────────┐     ┌──────────────┐     ┌──────────┐     ┌──────────┐
│ 服务端    │     │  APNs / FCM  │     │  iOS     │     │ Android  │
│ 事件发生  │     │              │     │  设备     │     │  设备     │
└────┬─────┘     └──────┬───────┘     └────┬─────┘     └────┬─────┘
     │                  │                 │                 │
     │ 1. 发送通知       │                 │                 │
     │─────────────────►│                 │                 │
     │                  ���                 │                 │
     │                  │ 2a. 推送        │                 │
     │                  │────────────────►│                 │
     │                  │                 │                 │
     │                  │ 2b. 推送                         │
     │                  │────────────────────────────────►│
     │                  │                 │                 │
     │                  │                 │ 3. App 处理     │
     │                  │                 │ - 显示横幅      │
     │                  │                 │ - 更新角标      │
     │                  │                 │ - 刷新数据      │
```

#### 通知类型设计

| 通知类型 | 触发时机 | 标题 | 内容 | 操作 |
|---------|---------|------|------|------|
| `sync_complete` | 同步完成 | 同步完成 | 已同步 N 个文件 | 打开同步页面 |
| `new_file` | 新文件入库 | 新文件已入库 | `{分类}`: `{摘要}` | 打开文件详情 |
| `pairing_request` | 设备配对请求 | 新设备配对请求 | `{设备名}` 请求配对 | 打开配对确认 |
| `security_alert` | 安全事件 | 安全提醒 | 检测到异常登录 | 查看详情 |

#### 静默推送（Silent Push）

用于后台数据刷新，不显示用户可见通知：

```json
{
  "aps": {
    "content-available": 1
  },
  "type": "background_sync",
  "vault_version": 15
}
```

App 收到静默推送后，在后台调用 `GET /vault/status` 检查数据变更，如有变更则预加载最新文件列表。

---

## 6. 安全注意事项

### 6.1 网络安全

#### TLS 传输加密

| 要求 | 实现方式 |
|------|---------|
| 最低 TLS 版本 | TLS 1.3 |
| 证书验证 | 严格验证证书链 |
| 证书固定 (Certificate Pinning) | 嵌入服务器公钥哈希，防止中间人攻击 |
| ATS (iOS) | 启用 App Transport Security，仅允许 HTTPS |
| 网络安全配置 (Android) | `network_security_config.xml` 限制明文流量 |

**iOS Certificate Pinning 实现**:

```swift
// CertificatePinning.swift
import Alamofire

final class PinnedSessionDelegate: SessionDelegate {
    override func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverCertificateData = SecCertificateCopyData(certificate) as Data
        let pinnedHash = "SHA256_HASH_OF_SERVER_CERTIFICATE"
        let serverHash = SHA256.hash(data: serverCertificateData).hexString
        
        if serverHash == pinnedHash {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

**Android Certificate Pinning**:

```kotlin
// CertificatePinner.kt
val certificatePinner = CertificatePinner.Builder()
    .add(
        "api.aegisvault.local",
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    .build()

val okHttpClient = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

#### API 认证

- 使用 Bearer Token 认证（`AEGISVAULT_API_TOKEN` 环境变量）
- Token 通过安全通道（线下/已认证渠道）分发给移动端
- Token 存储在 Keychain/EncryptedSharedPreferences 中
- 每次 API 请求通过拦截器自动附加 Token

```
Authorization: Bearer <token>
```

### 6.2 本地安全存储

#### iOS Keychain

```swift
// KeychainManager.swift
import Security

final class KeychainManager {
    static let shared = KeychainManager()
    
    private let service = "com.aegisvault.ios"
    
    func store(key: String, data: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary) // 删除旧值
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }
    
    func retrieve(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess ? (result as? Data) : nil
    }
    
    func delete(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
}
```

#### Android EncryptedSharedPreferences

```kotlin
// SecurePreferences.kt
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecurePreferences(context: Context) {
    
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    
    private val prefs = EncryptedSharedPreferences.create(
        context,
        "aegisvault_secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
    
    fun storeString(key: String, value: String) {
        prefs.edit().putString(key, value).apply()
    }
    
    fun getString(key: String): String? {
        return prefs.getString(key, null)
    }
    
    fun remove(key: String) {
        prefs.edit().remove(key).apply()
    }
}
```

#### Android Keystore (硬件级密钥保护)

```kotlin
// KeystoreManager.kt
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class KeystoreManager {
    
    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "aegisvault_pairing_key"
    }
    
    fun generateKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true) // 需要用户认证
                .build()
        )
        return keyGenerator.generateKey()
    }
    
    fun getKey(): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        return keyStore.getKey(KEY_ALIAS, null) as? SecretKey
    }
}
```

### 6.3 生物特征解锁

#### 实现要点

| 平台 | API | 说明 |
|------|-----|------|
| iOS | `LocalAuthentication` | Face ID / Touch ID |
| Android | `BiometricPrompt` (AndroidX) | 指纹 / 面部识别 / 虹膜 |

**iOS 实现**:

```swift
// BiometricAuth.swift
import LocalAuthentication

final class BiometricAuth {
    static let shared = BiometricAuth()
    
    private let context = LAContext()
    private var error: NSError?
    
    var availableBiometry: LABiometryType {
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        return context.biometryType
        // .faceID 或 .touchID
    }
    
    func authenticate(reason: String = "验证身份以访问保险库") async -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "取消"
        
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
        } catch {
            return false
        }
    }
}
```

**Android 实现**:

```kotlin
// BiometricManager.kt
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

class BiometricManager(private val activity: FragmentActivity) {
    
    private val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("身份验证")
        .setSubtitle("验证身份以访问保险库")
        .setNegativeButtonText("取消")
        .setConfirmationRequired(true)
        .build()
    
    fun authenticate(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val prompt = BiometricPrompt(activity, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                onSuccess()
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onError(errString.toString())
            }
            
            override fun onAuthenticationFailed() {
                onError("验证失败，请重试")
            }
        })
        prompt.authenticate(promptInfo)
    }
}
```

#### 解锁策略

```
App 启动
    │
    ▼
┌─────────────────────┐
│ 检查解锁状态          │
│                     │
│ 首次启动? ──是──► 设置密码/生物特征 │
│  │                                 │
│  否                                │
│  │                                 │
│  ▼                                 │
│ 设备解锁? ──是──► 自动跳过验证      │
│  │              (App 打开 < 1分钟)  │
│  否                                │
│  │                                 │
│  ▼                                 │
│ ┌───────────────────────┐          │
│ │ Face ID / 指纹验证     │          │
│ │                       │          │
│ │ 连续失败 3 次           │          │
│ │ → 要求输入设备解锁密码   │          │
│ └───────────────────────┘          │
└─────────────────────────────────────┘
```

### 6.4 数据安全策略

| 策略 | 实现 |
|------|------|
| 不在 App 端解密文件内容 | 解密由服务端执行（`VaultManager.decrypt`） |
| 不在 App 端缓存解密后的文件 | 使用临时目录，预览完毕立即删除 |
| 后台清理 | App 进入后台时清理所有临时解密文件 |
| 内存保护 | 敏感数据使用完毕后立即清零（`memset_s` / `Arrays.fill`） |
| 剪切板保护 | 不将配对码/密钥复制到系统剪切板（iOS 14+ 可检测剪切板访问） |
| 截屏保护 | iOS: `UIApplication.shared.isProtectedDataAvailable` 检查<br>Android: `FLAG_SECURE` 防止截屏/录屏 |
| 日志脱敏 | 日志中不输出 Token、密钥、文件内容等敏感信息 |

### 6.5 安全检查清单

```
□ TLS 1.3 强制启用
□ Certificate Pinning 已实施
□ Bearer Token 存储在 Keychain/EncryptedSharedPreferences
□ 生物特征解锁 App（Face ID / Touch ID / Android Biometric）
□ 不在 App 本地存储解密后的文件
□ App 进入后台时清理临时解密文件
□ API 请求超时设置（连接 10s，读取 30s）
□ 网络错误重试策略（最多 3 次，指数退避）
□ 禁止明文 HTTP 流量（iOS ATS / Android cleartextTrafficPermitted=false）
□ 截屏/录屏保护已启用
□ 日志不包含敏感信息
□ ProGuard / R8 代码混淆（Android Release）
□ App 完整性校验（可选 - 防止重打包）
```

---

## 附录 A: API 端点速查表

```
┌────────────────────────────────────────────────────────────────────────┐
│                          API 端点速查                                   │
├─────��──┬─────────────────────────────────┬────────────────────────────┤
│ 方法   │ 路径                             │ 认证     │ 用途            │
├────────┼─────────────────────────────────┼──────────┼─────────────────┤
│ GET    │ /health                         │ 否       │ 健康检查         │
│ GET    │ /vault/status                   │ Bearer   │ 保险库状态       │
│ GET    │ /vault/files                    │ Bearer   │ 文件列表(分页)    │
│ GET    │ /vault/files/{id}               │ Bearer   │ 文件元数据        │
│ GET    │ /vault/files/{id}/download      │ Bearer   │ 文件下载(解密)    │
│ POST   │ /vault/search                   │ Bearer   │ 搜索(关键字/语义) │
│ POST   │ /vault/classify                 │ Bearer   │ 手动分类触发      │
│ GET    │ /sync/status                    │ Bearer   │ 同步状态          │
│ POST   │ /sync/trigger                   │ Bearer   │ 触发同步          │
└────────┴─────────────────────────────────┴──────────┴─────────────────┘
```

## 附录 B: 错误码规范

| HTTP 状态码 | 场景 | 响应内容 |
|------------|------|---------|
| 200 | 成功 | 正常响应体 |
| 400 | 请求参数错误 | `{"detail": "Invalid file ID format"}` |
| 401 | Token 缺失/无效 | `{"detail": "Invalid or missing authentication token"}` |
| 404 | 资源不存在 | `{"detail": "File not found"}` |
| 500 | 服务端错误 | `{"detail": "Failed to decrypt file: ..."}` |

## 附录 C: 术语表

| 术语 | 英文 | 说明 |
|------|------|------|
| 保险库 | Vault | AegisVault 加密存储文件的主目录 |
| 同步引擎 | Sync Engine | 端到端加密多设备 P2P 同步引擎 |
| 设备配对 | Device Pairing | PAKE 协议下的设备授权流程 |
| 密封密钥 | Sealed Secret | 经 `secure_storage.seal()` 加密存储的共享密钥 |
| 语义搜索 | Semantic Search | 基于 AI embedding 的相似度搜索 |
| 证书固定 | Certificate Pinning | 将服务器证书公钥哈希嵌入 App 防止中间人攻击 |
| 收件箱 | Inbox | 待分类处理的文件目录 |
