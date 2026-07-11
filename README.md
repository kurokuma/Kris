# Malware Runtime Timeline Workbench 開発設計書

開発環境は .NET SDK 9.0、Visual Studio Build Tools 2026、MSVC 19.51、Windows SDK 10.0.26100 を使用する。
C#プロジェクトは net9.0-windows を対象にする。
C++プロジェクトは MSVC x64、C++20、/EHsc を指定してビルドする。
CMakeは現時点で必須にせず、初期実装は Visual Studio solution / csproj / vcxproj 構成で作成する。

## 0. 目的

Windows上でEXE/DLLなどの検体を実行し、プロセス、API、ネットワーク、ファイル、レジストリなどの実行時イベントを1つの統合タイムラインで分析できるローカル型マルウェア分析ツールを開発する。

既存のProcmon、API Monitor、Process Explorer、TCPView、Network Monitor、ProcDOTのように個別観測するのではなく、検体実行単位で以下を同一UI上に統合表示する。

```text
- プロセスツリー
- API呼び出し
- ファイル操作
- レジストリ操作
- DNS/ネットワーク接続
- 実行前後差分
- 表層解析
- Artifact一覧
- HTML/CSV/JSON/JSONL export
```

このツールは「自動検知エンジン」ではない。
主目的は、マルウェア分析者が実行時挙動を時系列・プロセス文脈・artifact文脈で追えるようにすること。

## 1. 製品コンセプト

名称仮：

```text
Malware Runtime Timeline Workbench
```

短縮名仮：

```text
MRTW
```

コンセプト：

```text
API Monitor + Process Explorer + Network Monitor + Procmon を、
マルウェア分析向けの1つの統合タイムラインUIに再構成する。
```

重要方針：

```text
- ルールベース検知を主目的にしない
- 収集したイベントを同一process_guidとtimestampで統合する
- Raw APIログをそのまま大量表示しない
- 初期表示は分析に重要なイベント中心にする
- 詳細ペインでRaw情報まで掘れるようにする
- HTML/CSV/JSON/JSONLで外部共有できるようにする
```

## 2. 対象ユーザー

```text
- マルウェア分析者
- CTIリサーチャー
- SOC/DFIR担当者
- Windows実行時挙動を調査したいセキュリティエンジニア
```

## 3. 対象環境

初期対応：

```text
OS:
- Windows 10 x64
- Windows 11 x64

Architecture:
- x64プロセス
- x86プロセスはP1以降で対応

Runtime:
- .NET 8
- C++20
```

推奨実行環境：

```text
- 分析用VM
- ネットワーク隔離済み環境
- スナップショット復元可能な環境
```

本ツールは検体を実行するため、通常業務端末での実行を想定しない。

## 4. 非目的

以下は初期実装の対象外。

```text
- 完全なサンドボックス機能
- 自動マルウェア判定
- 高度なATT&CK自動分類
- カーネルドライバ
- WFPドライバ
- HTTPS本文復号
- メモリダンプ解析
- 自動外部IOC照会
- EDR回避検知
- ルールベース検知エンジン
```

ただし将来的に追加可能な設計にする。

## 5. 技術選定

### 5.1 全体

```text
GUI:
- C# / .NET 8 / WPF

Core:
- C# / .NET 8

ETW Collector:
- C# / Microsoft.Diagnostics.Tracing.TraceEvent

Native Hook:
- C++20
- MinHook

Native Injector:
- C++20

Storage:
- SQLite
- JSONL raw event log

IPC:
- Named Pipe
- UTF-8 JSON Lines
  初期実装ではMessagePackではなくJSON Linesでよい

Export:
- HTML
- CSV
- JSON
- JSONL
- SQLite bundle
- ZIP package
```

### 5.2 採用理由

```text
WPF:
- Windows専用UIとして実装が速い
- TreeView、DataGrid、Timeline表示、Detailsペインを作りやすい
- WinUIより初期開発が単純

C#:
- ETW、SQLite、JSON、HTML export、UIの実装効率が高い

C++:
- MinHook、DLL Injection、WinAPI HookはC++で実装するのが妥当

ETW:
- プロセス生成/終了、DNS、TCP/IPなどの骨格イベントを安定して取得する

MinHook:
- ETWだけでは見えにくいAPI引数やWinHTTP/WinINet、Registry/File APIの詳細を補完する

SQLite:
- UI上の検索、フィルタ、タイムライン表示、case保存に向く

JSONL:
- 生ログ保全と外部解析に向く
```

## 6. リポジトリ構成

以下の構成で実装する。

```text
mrtw/
  README.md
  docs/
    architecture.md
    ui_spec.md
    event_model.md
    build.md
    safety.md

  src/
    MRTW.App/
      WPF UI
      MainWindow
      ViewModels
      Views
      Resources

    MRTW.Core/
      Domain models
      Event normalization
      Process context
      Artifact extraction
      Event compression
      Severity tagging

    MRTW.Collectors.Etw/
      ETW process collector
      ETW network collector
      ETW DNS collector

    MRTW.Collectors.Snapshot/
      File snapshot
      Registry snapshot
      Services snapshot
      Scheduled tasks snapshot
      Startup snapshot

    MRTW.Storage/
      SQLite schema
      Repository classes
      Migration
      JSONL writer

    MRTW.Export/
      HTML export
      CSV export
      JSON export
      ZIP export

    MRTW.StaticAnalysis/
      PE metadata parser
      Hashing
      Strings extraction
      Import/export table extraction
      Entropy calculation

    MRTW.Native/
      injector/
        injector.cpp
        injector.h
        CMakeLists.txt

      hook/
        hook.cpp
        hook.h
        pipe_client.cpp
        pipe_client.h
        api_hooks_file.cpp
        api_hooks_registry.cpp
        api_hooks_process.cpp
        api_hooks_network.cpp
        api_hooks_credential.cpp
        CMakeLists.txt

  tests/
    MRTW.Core.Tests/
    MRTW.Storage.Tests/
    MRTW.StaticAnalysis.Tests/

  samples/
    benign/
      README.md
```

## 7. アプリケーション全体アーキテクチャ

```text
[WPF App]
  ├─ Target selection
  ├─ Execution profile
  ├─ Case session management
  ├─ UI display
  └─ Export

[Execution Manager]
  ├─ EXE実行
  ├─ DLL rundll32実行
  ├─ 任意コマンドライン実行
  ├─ timeout管理
  └─ process tree kill

[ETW Collector]
  ├─ Process start/exit
  ├─ DNS query
  ├─ TCP connect
  └─ Image load

[Native Injector]
  ├─ target processをsuspended起動
  ├─ hook DLLを注入
  └─ ResumeThread

[Hook DLL]
  ├─ MinHook初期化
  ├─ File API Hook
  ├─ Registry API Hook
  ├─ Process API Hook
  ├─ Network API Hook
  ├─ Credential API Hook
  └─ Named PipeへJSONL送信

[Normalizer]
  ├─ Raw eventを統一形式へ変換
  ├─ process_guid付与
  ├─ category/action/object抽出
  ├─ summary生成
  └─ severity付与

[Storage]
  ├─ SQLite
  └─ JSONL

[UI]
  ├─ Process Tree
  ├─ Unified Timeline
  ├─ Details Pane
  ├─ Artifact View
  ├─ Network View
  ├─ Snapshot Diff View
  └─ Report View
```

## 8. 主要UX

### 8.1 起動画面

起動直後はCase一覧とNew Analysisを表示する。

```text
New Analysis
- Open EXE
- Open DLL
- Open Script/Command
- Open existing case
```

### 8.2 検体選択

ファイル選択時に表層解析を実施する。

表示項目：

```text
- File name
- Full path
- File size
- MD5
- SHA1
- SHA256
- File type
- Architecture
- PE timestamp
- Entry point
- Imports
- Exports
- Sections
- Entropy
- Digital signature
- PDB path
- TLS callbacks
- Overlay
- .NET判定
```

### 8.3 EXE実行

EXEの場合：

```text
Target:
  C:\samples\sample.exe

Command line:
  "C:\samples\sample.exe"

Working directory:
  C:\samples

Run duration:
  30 sec / 60 sec / 180 sec / manual

Network mode:
  observe only / disabled placeholder
```

初期実装ではネットワーク遮断機能は必須ではない。
ただしUI上に将来追加できるよう項目だけ残してよい。

### 8.4 DLL実行

DLLの場合：

PE export tableを読み取り、候補を表示する。

```text
Target:
  C:\samples\sample.dll

Runner:
  rundll32.exe

Export:
  - DllRegisterServer
  - Start
  - Run
  - 任意入力

Command line preview:
  rundll32.exe "C:\samples\sample.dll",Start
```

最低限以下を実装する。

```text
- rundll32.exe <dll>,<export>
- export名手動入力
- ordinal指定はP1でよい
- regsvr32実行はP1でよい
```

### 8.5 実行中UI

実行中は以下を表示。

```text
- elapsed time
- observed process count
- observed network count
- file event count
- registry event count
- stop button
- kill process tree button
```

### 8.6 実行後UI

中央に統合タイムラインを表示する。

基本レイアウト：

```text
┌─────────────────────────────────────────────────────────────┐
│ Target: sample.exe  Start Stop Export  Duration: 60s         │
├───────────────┬───────────────────────────────┬─────────────┤
│ Process Tree  │ Unified Timeline              │ Details     │
│               │                               │             │
│ sample.exe    │ 10:00:01 Process start         │ Summary     │
│ ├ powershell  │ 10:00:02 File write            │ API args    │
│ └ updater     │ 10:00:03 Registry set          │ Process     │
│               │ 10:00:04 DNS query            │ Related     │
│ Filters       │ 10:00:05 TCP connect           │ Raw JSON    │
├───────────────┴───────────────────────────────┴─────────────┤
│ Artifacts | Network | Files | Registry | API Raw | Report     │
└─────────────────────────────────────────────────────────────┘
```

## 9. UI詳細仕様

### 9.1 左ペイン：Process Tree

表示項目：

```text
- process name
- PID
- short command line
- start time
- end time
- event count
- network count
- file count
- registry count
```

プロセスが終了してもツリーから消さない。
終了済みプロセスは淡色表示。

クリック動作：

```text
- そのprocess_guidに紐づくイベントへタイムラインを絞り込む
- Shift/Ctrlで複数プロセス選択可能にするのはP1
```

### 9.2 中央：Unified Timeline

初期表示ではRaw APIの大量ログを直接出さない。
NormalizedEventのsummaryを表示する。

表示列：

```text
- Time
- Process
- Category
- Action
- Object
- Summary
- Severity
- Source
```

Category例：

```text
- Process
- API
- File
- Registry
- DNS
- Network
- Module
- Credential
- Service
- Task
- Snapshot
```

Action例：

```text
- Start
- Exit
- Create
- Read
- Write
- Delete
- SetValue
- Query
- Connect
- Send
- Receive
- Load
- Call
```

Severity：

```text
- High
- Medium
- Low
- Hidden
```

Severityは検知ではなく表示優先度。
初期表示はHigh/Medium中心。

### 9.3 タイムライン表示モード

最低限以下を実装する。

```text
Analyst View:
  High/Mediumイベントを中心表示

Verbose View:
  全イベントを表示

Network View:
  DNS/Network/WinHTTP/WinINet中心

File/Registry View:
  File/Registry中心

API Raw View:
  Hook由来のRaw APIイベント中心
```

### 9.4 イベント圧縮

同一PID、同一category、同一action、同一objectに対する短時間連続イベントは圧縮する。

例：

```text
WriteFile x 382
Target: C:\Users\user\AppData\Roaming\updater.exe
Total: 243 KB
Duration: 1.2 sec
```

圧縮対象：

```text
- ReadFile
- WriteFile
- send
- recv
- RegOpenKey
- RegQueryValue
- DLL load
```

初期実装では簡易圧縮でよい。

条件：

```text
same process_guid
same category
same action
same object_value
within 2 seconds
```

### 9.5 右ペイン：Details

タイムラインイベントをクリックすると右側に詳細を表示する。

表示項目：

```text
Selected Event:
- summary
- timestamp
- source
- category
- action
- severity

Process:
- process name
- pid
- ppid
- process_guid
- image path
- command line
- parent process

Object:
- object_type
- object_value

API:
- api_name
- module
- arguments
- return_value
- last_error

Related:
- previous 5 seconds events
- next 5 seconds events
- same process recent events
- same artifact events

Raw:
- raw JSON
```

「previous/next 5 seconds」はルールではなく、timestampとprocess_guid/object_valueによる近傍表示。

### 9.6 下部：Artifacts

Artifact一覧をタブ表示する。

タブ：

```text
- Files
- Registry
- Processes
- Commands
- Network
- DNS
- Modules
- Credential APIs
```

Artifact項目：

```text
- type
- value
- first_seen
- last_seen
- event_count
- related_processes
- severity
```

クリック動作：

```text
- タイムラインをそのartifact関連イベントに絞り込む
- Detailsにartifact履歴を出す
```

## 10. 表層解析機能

### 10.1 ハッシュ

以下を計算する。

```text
- MD5
- SHA1
- SHA256
```

### 10.2 PE解析

C#で実装する。
PE解析ライブラリを使ってもよいが、最小限は独自実装でもよい。

取得項目：

```text
- machine architecture
- PE type
- subsystem
- timestamp
- entry point
- image base
- sections
- imports
- exports
- resources
- TLS callbacks
- digital signature presence
- overlay size
- PDB path
```

### 10.3 Entropy

sectionごとにShannon entropyを計算する。

表示：

```text
.text    6.2
.rdata   4.1
.data    3.7
UPX0     7.8
```

### 10.4 Strings抽出

ASCII/UTF-16LE文字列を抽出する。

最小長：

```text
default: 5
```

分類：

```text
- URLs
- Domains
- IPs
- Registry paths
- File paths
- Commands
- General strings
```

初期表示ではGeneral stringsは折りたたむ。

### 10.5 DLL export支援

DLLの場合、export一覧をUIに表示し、rundll32実行プロファイルで選択できるようにする。

## 11. 実行プロファイル

### 11.1 Profile Model

```text
ExecutionProfile
- profile_id
- target_path
- target_type
- runner
- command_line
- working_directory
- environment_variables
- duration_seconds
- inject_hook
- enable_etw
- snapshot_before
- snapshot_after
```

target_type：

```text
- Exe
- DllRundll32
- Command
```

P1以降：

```text
- ScriptWscript
- ScriptCscript
- PowerShell
- Msi
- Regsvr32
```

### 11.2 実行制御

必須機能：

```text
- start analysis
- stop analysis
- kill process tree
- timeout stop
- collect final snapshot
```

kill process treeは、監視対象case内のprocess_guidに紐づく全PIDを終了する。

## 12. イベントモデル

### 12.1 RawEvent

```text
RawEvent
- event_id
- case_id
- ts_utc
- source
- pid
- ppid
- tid
- process_image
- process_command_line
- api_name
- provider_name
- event_name
- raw_json
```

source例：

```text
- ETW
- Hook
- Snapshot
- Static
```

### 12.2 NormalizedEvent

```text
NormalizedEvent
- event_id
- case_id
- ts_utc
- process_guid
- pid
- tid
- source
- category
- action
- object_type
- object_value
- summary
- severity
- raw_event_id
```

### 12.3 ProcessInfo

```text
ProcessInfo
- process_guid
- case_id
- pid
- ppid
- parent_process_guid
- image_path
- image_name
- command_line
- working_directory
- user
- integrity_level
- start_time_utc
- end_time_utc
- exit_code
- sha256
- signer
```

### 12.4 process_guid

PIDは再利用されるため、内部ではprocess_guidを使う。

生成式：

```text
process_guid = case_id + ":" + pid + ":" + process_start_time_utc_ticks
```

process_start_timeが取れない場合：

```text
process_guid = case_id + ":" + pid + ":" + first_seen_timestamp_utc_ticks
```

### 12.5 Artifact

```text
Artifact
- artifact_id
- case_id
- type
- value
- first_seen_utc
- last_seen_utc
- event_count
- severity
```

type例：

```text
- file
- registry
- process
- command
- domain
- ip
- url
- module
- api
```

## 13. SQLiteスキーマ

初期スキーマ：

```sql
CREATE TABLE cases (
  case_id TEXT PRIMARY KEY,
  sample_path TEXT,
  sample_name TEXT,
  sample_sha256 TEXT,
  target_type TEXT,
  command_line TEXT,
  working_directory TEXT,
  started_at_utc TEXT,
  ended_at_utc TEXT,
  status TEXT
);

CREATE TABLE sample_metadata (
  case_id TEXT,
  key TEXT,
  value TEXT,
  PRIMARY KEY (case_id, key)
);

CREATE TABLE processes (
  process_guid TEXT PRIMARY KEY,
  case_id TEXT,
  pid INTEGER,
  ppid INTEGER,
  parent_process_guid TEXT,
  image_path TEXT,
  image_name TEXT,
  command_line TEXT,
  working_directory TEXT,
  user TEXT,
  integrity_level TEXT,
  start_time_utc TEXT,
  end_time_utc TEXT,
  exit_code INTEGER,
  sha256 TEXT,
  signer TEXT
);

CREATE TABLE raw_events (
  raw_event_id TEXT PRIMARY KEY,
  case_id TEXT,
  ts_utc TEXT,
  source TEXT,
  pid INTEGER,
  tid INTEGER,
  api_name TEXT,
  provider_name TEXT,
  event_name TEXT,
  raw_json TEXT
);

CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  case_id TEXT,
  ts_utc TEXT,
  process_guid TEXT,
  pid INTEGER,
  tid INTEGER,
  source TEXT,
  category TEXT,
  action TEXT,
  object_type TEXT,
  object_value TEXT,
  summary TEXT,
  severity TEXT,
  raw_event_id TEXT
);

CREATE TABLE artifacts (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT,
  type TEXT,
  value TEXT,
  first_seen_utc TEXT,
  last_seen_utc TEXT,
  event_count INTEGER,
  severity TEXT
);

CREATE TABLE event_artifacts (
  event_id TEXT,
  artifact_id TEXT,
  PRIMARY KEY (event_id, artifact_id)
);

CREATE TABLE notes (
  note_id TEXT PRIMARY KEY,
  case_id TEXT,
  target_type TEXT,
  target_id TEXT,
  note TEXT,
  created_at_utc TEXT
);

CREATE INDEX idx_events_case_ts ON events(case_id, ts_utc);
CREATE INDEX idx_events_process ON events(process_guid);
CREATE INDEX idx_events_object ON events(object_type, object_value);
CREATE INDEX idx_artifacts_case_type ON artifacts(case_id, type);
```

## 14. ETW Collector

### 14.1 必須イベント

取得対象：

```text
- Process Start
- Process Stop
- DNS Query
- TCP Connect
- TCP Disconnect
- Image Load
```

初期実装では以下を優先。

```text
1. Process Start/Stop
2. DNS
3. TCP
```

### 14.2 ETWイベントの正規化

Process Start：

```text
category: Process
action: Start
object_type: process
object_value: image_path
summary: Process started: <image_name>
```

DNS Query：

```text
category: DNS
action: Query
object_type: domain
object_value: query_name
summary: DNS query: <domain>
```

TCP Connect：

```text
category: Network
action: Connect
object_type: endpoint
object_value: <remote_ip>:<remote_port>
summary: TCP connect: <remote_ip>:<remote_port>
```

## 15. Native Hook

### 15.1 Hook方針

Hookは完全性を求めない。
ETWで取れないAPI引数やユーザー視点で重要な操作を補完する。

初期Hook対象：

Process：

```text
- CreateProcessW
- ShellExecuteExW
```

File：

```text
- CreateFileW
- WriteFile
- DeleteFileW
- MoveFileExW
```

Registry：

```text
- RegCreateKeyExW
- RegSetValueExW
- RegDeleteValueW
```

Network：

```text
- connect
- WinHttpSendRequest
- HttpSendRequestW
- InternetOpenUrlW
- DnsQuery_W
```

Credential：

```text
- CryptUnprotectData
```

P1以降：

```text
- NtCreateFile
- NtWriteFile
- NtCreateUserProcess
- NtSetValueKey
- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- CreateRemoteThread
- QueueUserAPC
```

### 15.2 Hook DLLの制約

Hook内で重い処理をしない。

Hook内の処理：

```text
1. 引数を安全にコピー
2. 最小限のJSONイベントを作成
3. Named Pipeに送信
4. original APIを呼び出す
```

禁止：

```text
- Hook内でSQLiteへ書く
- Hook内で複雑な文字列解析をする
- Hook内でUI連携する
- Hook内でネットワーク通信する
```

### 15.3 再帰対策

Thread Local Storageでin_hook guardを実装する。

擬似仕様：

```text
if in_hook:
  call original API directly

else:
  in_hook = true
  collect minimal event
  send to pipe
  call original API
  in_hook = false
```

### 15.4 Hookイベント形式

Named Pipeへ1行1JSONで送信する。

例：

```json
{
  "source": "Hook",
  "ts_utc": "2026-07-01T12:00:00.123Z",
  "pid": 4321,
  "tid": 123,
  "api_name": "RegSetValueExW",
  "category_hint": "Registry",
  "action_hint": "SetValue",
  "object_type": "registry",
  "object_value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
  "arguments": {
    "value_name": "Updater",
    "data": "C:\\Users\\user\\AppData\\Roaming\\updater.exe"
  },
  "return_value": 0
}
```

## 16. Snapshot Collector

### 16.1 目的

Hook/ETWで拾えない実行前後の変更を検出する。

### 16.2 対象

P0：

```text
- Startup folder
- Temp
- AppData Roaming
- AppData Local
- ProgramData
- Run / RunOnce registry keys
- Services registry keys
- Scheduled Tasks basic enumeration
```

P1：

```text
- Defender settings
- Firewall rules
- Hosts file
- WMI event subscription
- IFEO
- Winlogon
- AppInit_DLLs
```

### 16.3 差分イベント

差分はSnapshotイベントとしてタイムラインに出す。

例：

```text
category: Snapshot
action: FileCreated
object_type: file
object_value: C:\Users\...\AppData\Roaming\updater.exe
summary: Snapshot diff: file created
```

## 17. Normalizer

NormalizerはRawEvent/Hook JSON/ETWイベントをNormalizedEventに変換する。

責務：

```text
- process_guid付与
- category統一
- action統一
- object抽出
- summary生成
- severity付与
- artifact抽出
```

### 17.1 Severity付与

これは検知ではなく表示優先度。

High：

```text
- Process start
- Network connect
- DNS query
- Registry set/delete
- File create/write/delete outside common noise
- CryptUnprotectData
- PowerShell/cmd/rundll32/regsvr32/mshta/schtasks/sc/vssadmin/bcdedit起動
```

Medium：

```text
- AppData/Temp/ProgramDataへの書き込み
- DLL load from non-system path
- WinHTTP/WinINet request
- command line with encoded/base64-like string
```

Low：

```text
- normal file read
- normal registry query
- image load from System32
```

Hidden：

```text
- CloseHandle
- GetProcAddress
- LoadLibrary from known system path
- repeated reads/queries
```

## 18. Artifact抽出

各イベントからartifactを抽出する。

対応：

```text
File:
- file path

Registry:
- registry key/value

Network:
- ip
- port
- endpoint

DNS:
- domain

Process:
- image path
- command line

API:
- api name

Static strings:
- url
- domain
- ip
- registry path
- file path
```

Artifactはタイムラインから逆引きできるようにする。

## 19. Network Session View

DNS、TCP、Hook由来HTTP情報をまとめて表示する。

Network session項目：

```text
- process_guid
- process_name
- domain
- resolved_ip
- remote_ip
- remote_port
- protocol
- first_seen
- last_seen
- bytes_sent
- bytes_received
- related_api
```

初期実装ではbytesは取得できる範囲でよい。
取れない場合はnullでよい。

## 20. Command Line Decode Helper

右ペインでコマンドラインを選択した場合、デコード候補を表示する。

対応：

```text
- PowerShell -EncodedCommand UTF-16LE Base64 decode
- Base64 decode
- URL decode
- Hex decode
```

自動実行はしない。
文字列変換のみ。

## 21. Notes / Bookmark

分析中にイベント、artifact、processへメモを残せるようにする。

機能：

```text
- Add note to event
- Add note to artifact
- Add note to process
- Mark important
- Show bookmarked items
```

Exportに含める。

## 22. Export機能

### 22.1 HTML Report

HTML reportには以下を含める。

```text
- Sample summary
- Static analysis summary
- Execution profile
- Process tree
- Timeline summary
- Network activity
- File activity
- Registry activity
- Commands
- Artifacts
- Snapshot diff
- Analyst notes
```

CSSは1ファイル内に埋め込みでよい。
外部CDNは使わない。

### 22.2 CSV

出力：

```text
timeline.csv
artifacts.csv
processes.csv
network.csv
```

### 22.3 JSON

出力：

```text
case.json
```

case.jsonには以下を含める。

```text
- case
- sample_metadata
- processes
- events
- artifacts
- notes
```

### 22.4 JSONL

出力：

```text
events.jsonl
raw_events.jsonl
```

### 22.5 ZIP Export

ZIP形式：

```text
case_<sha256_prefix>_<timestamp>.zip
  report.html
  case.json
  timeline.csv
  artifacts.csv
  processes.csv
  network.csv
  events.jsonl
  raw_events.jsonl
  case.sqlite
  sample_metadata.json
```

検体本体はデフォルトではZIPに含めない。
UIで明示的に選択した場合のみ含める。
含める場合は危険表示を出す。

## 23. フィルタ・検索

必須フィルタ：

```text
- category
- severity
- process
- pid
- source
- time range
- object substring
- API name
```

検索：

```text
- free text search over summary/object/process/api
```

プリセット：

```text
- Analyst View
- Verbose View
- Network Only
- File/Registry Only
- Process/API Only
- High Severity Only
```

## 24. 安全制御

最低限以下を実装する。

```text
- 実行前の警告表示
- 分析用VM推奨表示
- timeout停止
- stop analysis
- kill process tree
- 検体をexport ZIPへ含める場合の警告
```

P1以降：

```text
- network disabled mode
- INetSim連携
- snapshot restore連携
```

## 25. 実装フェーズ

### Phase 0: 土台

目的：UI、DB、case管理、表層解析の土台を作る。

実装：

```text
- WPFプロジェクト作成
- SQLite初期化
- Case作成
- ファイル選択
- SHA256/MD5/SHA1計算
- PE基本情報表示
- Process Tree枠
- Timeline枠
- Details枠
- Artifact枠
```

完了条件：

```text
- EXE/DLLを開くと表層解析が表示される
- case.sqliteが作成される
- 空のタイムラインUIが表示される
```

### Phase 1: ETW Collector

目的：Hookなしでプロセス/DNS/TCPをタイムラインに出す。

実装：

```text
- ETW Process Start/Stop収集
- ETW DNS収集
- ETW TCP収集
- NormalizedEvent変換
- process_guid作成
- SQLite保存
- Timeline表示
- Process Tree表示
```

完了条件：

```text
- notepad.exe等を起動してProcess Start/Stopが見える
- DNS queryが見える
- TCP connectが見える
- process treeからtimelineを絞り込める
```

### Phase 2: 実行プロファイル

目的：EXE/DLL実行をUIから制御する。

実装：

```text
- EXE実行
- DLL rundll32実行
- export一覧表示
- command line preview
- duration指定
- stop
- kill process tree
```

完了条件：

```text
- EXEを選択して実行できる
- DLLをrundll32でexport指定実行できる
- 実行中のプロセスがProcess Treeに出る
```

### Phase 3: Native Hook MVP

目的：主要APIイベントをタイムラインに統合する。

実装：

```text
- injector.exe
- hook.dll x64
- Named Pipe JSONL
- CreateProcessW Hook
- CreateFileW Hook
- WriteFile Hook
- RegSetValueExW Hook
- WinHttpSendRequest Hook
- CryptUnprotectData Hook
- HookイベントのNormalizer
```

完了条件：

```text
- File create/writeがタイムラインに出る
- Registry setがタイムラインに出る
- WinHTTPイベントがタイムラインに出る
- APIイベントが同一process_guidに紐づく
```

### Phase 4: Snapshot Diff

目的：実行前後差分を表示する。

実装：

```text
- file snapshot
- registry snapshot
- startup folder diff
- Run/RunOnce diff
- services basic diff
- scheduled tasks basic diff
- Snapshotイベント生成
```

完了条件：

```text
- 実行前後で作成されたファイルがSnapshot Diffに出る
- Run key変更がSnapshot Diffに出る
- Snapshotイベントがtimelineに出る
```

### Phase 5: UI改善

目的：分析しやすいUIにする。

実装：

```text
- Severity filter
- Category filter
- Search
- Event compression
- Details related events
- Artifact reverse lookup
- Network session view
- Command line decode helper
```

完了条件：

```text
- 高重要イベントだけ表示できる
- Artifactクリックで関連イベントに絞れる
- NetworkイベントクリックでDNS/TCP/API文脈が見える
- 連続WriteFileが圧縮表示される
```

### Phase 6: Export

目的：分析結果を共有可能にする。

実装：

```text
- HTML report
- CSV timeline/artifacts/processes/network
- JSON case
- JSONL raw events
- ZIP export
```

完了条件：

```text
- report.htmlが単体で開ける
- CSVをExcel等で開ける
- JSONでcase全体を復元できる
- ZIPに必要ファイルが入る
```

### Phase 7: P1拡張

P1で追加する候補：

```text
- x86 Hook DLL
- regsvr32実行
- wscript/cscript実行
- PowerShell実行プロファイル
- Process Injection API Hook
- Service creation view
- Persistence view
- Credential access view
- Bookmark/Notes
- Case comparison
```

## 26. 受け入れテスト

### 26.1 表層解析

テスト：

```text
- 任意のEXEを開く
- hashが表示される
- PE情報が表示される
- DLLの場合export一覧が表示される
```

### 26.2 EXE実行

テスト：

```text
- calc.exeまたはnotepad.exeを起動
- Process Startがtimelineに出る
- Process Treeに表示される
- Stop/Killが動作する
```

### 26.3 DLL実行

テスト：

```text
- exportを持つテストDLLを選択
- rundll32 command line previewが生成される
- 実行イベントがtimelineに出る
```

### 26.4 ファイルイベント

テスト用プログラムで以下を実行：

```text
- temp file create
- write
- delete
```

期待：

```text
- TimelineにFile Create/Write/Deleteが出る
- Artifact Filesに対象パスが出る
```

### 26.5 レジストリイベント

テスト用プログラムで以下を実行：

```text
- HKCU\Software\MRTWTest に値を書き込む
```

期待：

```text
- TimelineにRegistry SetValueが出る
- Artifacts Registryにキーが出る
```

### 26.6 ネットワークイベント

テスト用プログラムで以下を実行：

```text
- DNS query
- HTTP request
```

期待：

```text
- DNSイベントが出る
- TCP connectが出る
- Network artifactが出る
```

### 26.7 Export

期待：

```text
- HTMLが生成される
- CSVが生成される
- JSONが生成される
- JSONLが生成される
- ZIPが生成される
```

## 27. コーディング規約

### 27.1 C#

```text
- .NET 8
- Nullable reference types enabled
- async/awaitを適切に使う
- UI threadをブロックしない
- ViewModel分離
- Repository層を分離
- 例外はログに残す
```

### 27.2 C++

```text
- C++20
- RAIIを使う
- Hook内で例外を投げない
- Hook内で重い処理をしない
- Unicode優先
- x64を先に実装
```

## 28. ログ

アプリケーションログを保存する。

```text
logs/
  app.log
  etw.log
  hook.log
  export.log
```

ログには検体の中身や機微情報を不用意に出しすぎない。
ただしデバッグに必要なエラーは残す。

## 29. セキュリティ上の注意

```text
- このツールは検体実行を伴うため分析VMで使うこと
- 外部IOC照会は初期実装では行わない
- 検体ファイルをexportに含める場合は明示確認する
- ネットワーク遮断は初期実装の保証対象外
- ツール自体がマルウェアの影響を受ける可能性を考慮する
```

## 30. 最終完成条件

v1完成条件：

```text
1. EXE/DLLを選択できる
2. 表層解析が表示される
3. EXEを実行できる
4. DLLをrundll32で実行できる
5. 実行中/実行後のプロセスツリーが見える
6. ETW由来のProcess/DNS/TCPイベントが見える
7. Hook由来の主要APIイベントが見える
8. File/Registry/Network/APIイベントが1つのタイムラインに統合表示される
9. タイムラインイベントをクリックすると右側に詳細が出る
10. Artifact一覧から関連イベントへ逆引きできる
11. イベント圧縮がある
12. フィルタ/検索がある
13. 実行前後Snapshot Diffが見える
14. HTML/CSV/JSON/JSONL/ZIP exportができる
15. case.sqliteに保存される
```

## 31. Codexへの実装指示

この設計書に従って、Windows向けローカルマルウェア分析ツールを実装してください。

優先順位は以下です。

```text
1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
```

実装時の注意：

```text
- まず動くMVPを作る
- Hook完全性よりUIとイベント統合を優先する
- Raw APIログを大量に中央表示しない
- process_guidとtimestampを最重要キーにする
- すべてのイベントはSQLiteに保存する
- すべてのRawイベントはJSONLにも残す
- UIはWPFで実装する
- C++ Hookはx64を先に実装する
- x86対応はP1以降でよい
- 自動検知ルールエンジンは不要
- ただしseverityによる表示優先度は実装する
```

成果物：

```text
- Visual Studioでビルド可能なソリューション
- README
- build手順
- 実行手順
- テスト用 benign sample
- HTML export例
- SQLite schema
- docs配下の設計補足
```

最初のPull Requestまたは初回実装では、以下を最低限満たしてください。

```text
- WPF UIが起動する
- EXE/DLLファイルを選択できる
- hash/PE metadataが表示される
- EXEを実行できる
- ETW Process Start/Stopがtimelineに出る
- SQLiteにcaseとeventsが保存される
```

その後、段階的にETW DNS/TCP、Hook DLL、Snapshot Diff、Exportを追加してください。

# 32. CUIモード設計

## 32.1 目的

GUIを起動せず、コマンドラインから検体の表層解析、実行時解析、Export、既存caseの再出力を行えるようにする。

CUIモードの主な用途は以下。

```text id="fuvz7u"
- 分析VM内での自動実行
- 複数検体のバッチ処理
- GUIを使わない軽量実行
- CI/検証環境でのself-test
- Headless環境での実行
- 解析結果の再Export
- GUIで開く前の事前triage
```

CUIモードはGUIとは別実装にしない。
GUIと同じCore、Collector、Storage、Export、StaticAnalysisを利用する。

```text id="7ye2kg"
MRTW.App       GUI
MRTW.Cli       CUI

共通利用:
- MRTW.Core
- MRTW.Collectors.Etw
- MRTW.Collectors.Snapshot
- MRTW.Storage
- MRTW.Export
- MRTW.StaticAnalysis
- MRTW.Native
```

## 32.2 実行ファイル

CUI用の実行ファイル名は以下とする。

```text id="35pcnp"
mrtw.exe
```

GUI起動用の実行ファイルは以下。

```text id="bb2q6h"
MRTW.App.exe
```

ただし、配布時に `mrtw.exe gui` でGUIを起動できるようにしてもよい。

## 32.3 サブコマンド

CUIは以下のサブコマンドを持つ。

```text id="28rc9n"
mrtw run        検体を実行して動的解析する
mrtw static     表層解析のみ実行する
mrtw export     既存case.sqliteから再Exportする
mrtw batch      複数検体を順次解析する
mrtw list       既存case一覧を表示する
mrtw open       既存caseをGUIで開く
mrtw doctor     実行環境の診断を行う
mrtw selftest   安全なテストサンプルで動作確認する
mrtw version    バージョンを表示する
mrtw help       ヘルプを表示する
```

P0で必須のサブコマンド。

```text id="5cekyf"
- run
- static
- export
- doctor
- version
```

P1以降で追加。

```text id="s8epqz"
- batch
- list
- open
- selftest
```

## 32.4 共通オプション

全サブコマンドで利用可能な共通オプション。

```text id="ehtv6d"
--config <path>          設定ファイルを指定
--workspace <dir>        workspaceディレクトリを指定
--log-format text|json   標準出力ログ形式
--quiet                  標準出力を最小化
--verbose                詳細ログを出力
--no-color               ANSIカラーを無効化
--help                   ヘルプ表示
```

デフォルト値。

```text id="80g7pm"
--log-format text
--workspace C:\MRTW\Workspace
```

## 32.5 `mrtw run`

### 32.5.1 目的

検体を実行し、ETW、API Hook、Snapshot Diff、表層解析を用いてcaseを作成する。

基本例。

```powershell id="dy0nff"
mrtw run --target C:\samples\sample.exe --duration 60 --out C:\MRTW\Cases --format all
```

DLL実行例。

```powershell id="i3bxj1"
mrtw run --target C:\samples\update.dll --type dll --runner rundll32 --export-func DllRegisterServer --duration 120 --out C:\MRTW\Cases --format html,jsonl,sqlite
```

任意コマンド実行例。

```powershell id="b8utvp"
mrtw run --cmd "powershell.exe -ExecutionPolicy Bypass -File C:\samples\test.ps1" --duration 60 --out C:\MRTW\Cases --format html,jsonl
```

### 32.5.2 `run` 必須オプション

以下のいずれかを必須とする。

```text id="1u72gv"
--target <path>          解析対象ファイル
--cmd <commandline>      任意コマンドライン
```

`--target` と `--cmd` は排他。

### 32.5.3 `run` 主要オプション

```text id="mnz94t"
--type exe|dll|command
--runner rundll32|regsvr32|none
--export-func <name>
--ordinal <number>
--duration <seconds>
--out <dir>
--case-name <name>
--working-dir <dir>
--env KEY=VALUE
--profile <name>
--format html,csv,json,jsonl,sqlite,zip,all
--etw on|off
--hook on|off
--snapshot-before on|off
--snapshot-after on|off
--static on|off
--kill-tree
--timeout-action stop|kill
--network observe|disabled
```

### 32.5.4 `run` デフォルト値

```text id="kfr6st"
--duration 60
--type 自動判定
--runner none
--format html,json,jsonl,sqlite
--etw on
--hook on
--snapshot-before on
--snapshot-after on
--static on
--timeout-action kill
--kill-tree true
--network observe
```

`--type` の自動判定。

```text id="l9yawt"
.exe → exe
.dll → dll
それ以外 → command指定必須
```

### 32.5.5 DLL実行仕様

DLLの場合、初期実装では `rundll32` のみ必須対応とする。

```powershell id="v2igsa"
mrtw run --target C:\samples\a.dll --type dll --runner rundll32 --export-func Start --duration 60 --out C:\cases
```

実行コマンド生成。

```text id="z539d7"
rundll32.exe "<target_path>",<export_func>
```

`--export-func` が未指定の場合。

```text id="6ntd57"
- DLLのexport一覧を取得
- DllRegisterServer が存在すればそれを候補にする
- 候補が一意に決まらない場合はエラー終了
```

エラー例。

```text id="7g30ap"
ERROR: DLL target requires --export-func because no default export could be selected.
```

P1以降で対応するもの。

```text id="3n3y26"
- --runner regsvr32
- --ordinal
- export一覧表示のみ
```

### 32.5.6 出力ディレクトリ仕様

`--out` には親ディレクトリを指定する。

デフォルトcaseディレクトリ名。

```text id="sskb7g"
<sample_name>_<sha256_8>_<yyyyMMdd_HHmmss>
```

例。

```text id="qggxol"
C:\MRTW\Cases\sample.exe_a6d0c0c7_20260701_213012\
```

`--case-name` が指定された場合。

```powershell id="agpe7y"
mrtw run --target C:\samples\sample.exe --case-name stealer_test_01 --out C:\MRTW\Cases
```

出力先。

```text id="b9hgc2"
C:\MRTW\Cases\stealer_test_01\
```

同名ディレクトリが存在する場合は、デフォルトではエラーにする。
P1以降で以下を追加してもよい。

```text id="w5rvai"
--overwrite
--auto-suffix
```

### 32.5.7 出力ファイル

`run` 実行後、指定formatに応じて以下を生成する。

```text id="flk394"
case.sqlite
sample_metadata.json
events.jsonl
raw_events.jsonl
case.json
timeline.csv
artifacts.csv
processes.csv
network.csv
report.html
case_export.zip
manifest.json
tool_version.txt
```

`--format all` の対象。

```text id="7q1o2l"
html
csv
json
jsonl
sqlite
zip
```

### 32.5.8 実行完了条件

`run` は以下のいずれかで終了する。

```text id="xgpl72"
- duration到達
- target process tree終了
- ユーザー中断
- collector異常終了
- timeout-actionによるkill完了
```

正常終了時は以下を保証する。

```text id="zij57z"
- case.sqliteが存在する
- eventsテーブルが作成されている
- raw_events.jsonlが存在する
- 指定formatのexportが生成されている
```

## 32.6 `mrtw static`

### 32.6.1 目的

検体を実行せず、表層解析だけを実施する。

基本例。

```powershell id="6zg51v"
mrtw static --target C:\samples\sample.exe --out C:\MRTW\Static --format html,json
```

### 32.6.2 オプション

```text id="mn6ryu"
--target <path>
--out <dir>
--case-name <name>
--format html,json,csv,all
--strings on|off
--strings-min-length <number>
--entropy on|off
--imports on|off
--exports on|off
--resources on|off
```

デフォルト。

```text id="4gxsyd"
--strings on
--strings-min-length 5
--entropy on
--imports on
--exports on
--resources on
--format html,json
```

### 32.6.3 出力

```text id="f658we"
static_report.html
sample_metadata.json
strings.json
imports.csv
exports.csv
sections.csv
```

## 32.7 `mrtw export`

### 32.7.1 目的

既存case.sqliteからHTML、CSV、JSON、JSONL、ZIPを再生成する。

基本例。

```powershell id="ig90lr"
mrtw export --case C:\MRTW\Cases\sample\case.sqlite --format html,csv,json --out C:\MRTW\Exports\sample
```

ZIPだけ生成。

```powershell id="flcq6a"
mrtw export --case C:\MRTW\Cases\sample\case.sqlite --format zip --out C:\MRTW\Exports
```

### 32.7.2 オプション

```text id="ysl6sh"
--case <path>
--out <dir>
--format html,csv,json,jsonl,sqlite,zip,all
--privacy-mode on|off
--include-sample on|off
--include-raw on|off
--compress on|off
```

デフォルト。

```text id="2kxx9j"
--privacy-mode off
--include-sample off
--include-raw on
--compress on
```

検体本体はデフォルトでExportに含めない。
`--include-sample on` を指定した場合は警告を出す。

## 32.8 `mrtw batch`

### 32.8.1 目的

指定ディレクトリ内の複数検体を順次解析する。

基本例。

```powershell id="6gkqj6"
mrtw batch --input C:\samples --out C:\MRTW\Cases --duration 60 --format html,jsonl,sqlite
```

### 32.8.2 オプション

```text id="710txn"
--input <dir>
--out <dir>
--duration <seconds>
--format html,csv,json,jsonl,sqlite,zip,all
--recursive
--max-samples <number>
--skip-existing
--continue-on-error
--profile <name>
--parallel <number>
```

デフォルト。

```text id="yjgpkk"
--recursive off
--continue-on-error on
--parallel 1
```

マルウェア実行を伴うため、初期実装では `--parallel` は1のみ許可する。
2以上が指定された場合はエラーまたは警告にする。

### 32.8.3 batch対象ファイル

初期対象。

```text id="6hoavl"
.exe
.dll
```

P1以降。

```text id="6i4p0n"
.ps1
.vbs
.js
.msi
.scr
.com
```

## 32.9 `mrtw doctor`

### 32.9.1 目的

MRTWが正しく動作可能な環境か診断する。

実行例。

```powershell id="fvx0rm"
mrtw doctor
```

### 32.9.2 診断項目

```text id="9rdc0o"
- OS version
- process architecture
- .NET runtime
- 管理者権限
- ETW利用可否
- Hook DLL存在確認
- injector.exe存在確認
- workspace書き込み権限
- export先書き込み権限
- SQLite作成可否
- Visual C++ runtime確認
- Npcap有無
- config.yaml読み込み可否
```

出力例。

```text id="a3wzb9"
MRTW Doctor
[OK] OS: Windows 11 x64
[OK] .NET Runtime: 8.0
[OK] ETW access
[OK] hook_x64.dll found
[OK] injector.exe found
[OK] Workspace writable
[WARN] Not running as Administrator
[INFO] Npcap not installed
```

`doctor` は検体を実行しない。

## 32.10 `mrtw selftest`

### 32.10.1 目的

安全なテストサンプルを使って、ETW、Hook、Storage、Exportが動くか検査する。

実行例。

```powershell id="tt2u74"
mrtw selftest --out C:\MRTW\SelfTest
```

### 32.10.2 テスト内容

同梱の安全なテストEXEを実行し、以下を発生させる。

```text id="zx1fb9"
- 子プロセス起動
- 一時ファイル作成
- 一時ファイル書き込み
- HKCU\Software\MRTWTest へのレジストリ書き込み
- DNS query
- HTTP request to safe test endpoint or localhost
```

外部通信が不要なselftestも用意する。

```text id="3uop6h"
--network off
```

### 32.10.3 期待結果

```text id="zs0xlv"
- Process Startが記録される
- File Writeが記録される
- Registry SetValueが記録される
- DNSまたはNetworkイベントが記録される
- report.htmlが生成される
```

## 32.11 `mrtw list`

### 32.11.1 目的

workspace内のcase一覧を表示する。

```powershell id="jgwyrq"
mrtw list --workspace C:\MRTW\Cases
```

表示項目。

```text id="zqh7bo"
- case name
- sample name
- sha256
- status
- started_at
- duration
- event count
- process count
```

## 32.12 `mrtw open`

### 32.12.1 目的

既存caseをGUIで開く。

```powershell id="3ga2ti"
mrtw open --case C:\MRTW\Cases\sample\case.sqlite
```

動作。

```text id="btbhyc"
- MRTW.App.exeを起動
- 指定case.sqliteを開く
```

## 32.13 `mrtw version`

### 32.13.1 目的

ツール、DBスキーマ、Hook DLL、Collectorのバージョンを表示する。

```powershell id="t93zfq"
mrtw version
```

出力例。

```text id="6n2c8v"
MRTW CLI: 1.0.0
MRTW Core: 1.0.0
Schema: 1
Hook x64: 1.0.0
ETW Collector: 1.0.0
```

## 32.14 標準出力ログ

### 32.14.1 text形式

デフォルトは人間が読めるtext形式。

例。

```text id="2jzs8a"
[+] Case created: C:\MRTW\Cases\sample_a6d0c0c7_20260701_213012
[+] Static analysis completed
[+] ETW collector started
[+] Hook enabled
[+] Process started: sample.exe PID=3260
[+] Analysis completed
[+] Exported: report.html, case.json, events.jsonl, case.sqlite
```

### 32.14.2 json形式

自動化向けにJSON Linesで出力する。

指定。

```powershell id="cppbpm"
mrtw run --target C:\samples\sample.exe --duration 60 --out C:\MRTW\Cases --format all --log-format json
```

出力例。

```json id="7qu82b"
{"level":"info","event":"case_created","case_id":"...","path":"C:\\MRTW\\Cases\\sample_a6d0c0c7_20260701_213012"}
{"level":"info","event":"static_completed","sha256":"a6d0c0c7..."}
{"level":"info","event":"collector_started","collector":"etw"}
{"level":"info","event":"process_started","pid":3260,"image":"sample.exe"}
{"level":"info","event":"analysis_completed","duration_seconds":60}
{"level":"info","event":"export_completed","files":["report.html","case.json","events.jsonl","case.sqlite"]}
```

## 32.15 終了コード

CUIモードでは終了コードを明確に定義する。

```text id="sbkcg2"
0   success
1   invalid arguments
2   target not found
3   analysis failed
4   timeout
5   collector failed
6   hook injection failed
7   export failed
8   permission error
9   unsupported target type
10  case not found
11  config error
12  selftest failed
```

重要：

```text id="2fq1zd"
マルウェアらしい挙動を観測したことは非0終了にしない。
非0終了はツールの実行失敗のみを表す。
```

## 32.16 設定ファイル

CUIは設定ファイルを読み込めるようにする。

デフォルトパス。

```text id="qfoa4t"
.\config.yaml
%APPDATA%\MRTW\config.yaml
```

設定例。

```yaml id="c7ty76"
workspace: "C:\\MRTW\\Workspace"
exports: "C:\\MRTW\\Exports"

default_profile: "full-capture"

profiles:
  quick:
    duration: 30
    etw: true
    hook: false
    snapshot_before: true
    snapshot_after: true
    static: true
    format: "html,jsonl,sqlite"

  full-capture:
    duration: 120
    etw: true
    hook: true
    snapshot_before: true
    snapshot_after: true
    static: true
    format: "all"

cli:
  log_format: "text"
  quiet: false
  verbose: false
```

CLI引数はconfigより優先する。

優先順位。

```text id="tnjslt"
1. CLI引数
2. 指定profile
3. config.yaml
4. アプリ内デフォルト
```

## 32.17 Profile利用

profileを指定して実行できるようにする。

```powershell id="6xm7x7"
mrtw run --target C:\samples\sample.exe --profile full-capture --out C:\MRTW\Cases
```

profileに含める項目。

```text id="5mc9yd"
- duration
- etw
- hook
- snapshot_before
- snapshot_after
- static
- format
- network
- timeout_action
- kill_tree
```

## 32.18 Privacy Mode

CUI exportではprivacy modeを指定できるようにする。

```powershell id="nh3a6g"
mrtw export --case C:\cases\sample\case.sqlite --format html,json --privacy-mode on --out C:\exports\safe
```

マスク対象。

```text id="zggzob"
- username
- hostname
- private IP
- local path username部分
- internal domain
```

変換例。

```text id="5cuxsf"
C:\Users\suzuki\AppData\Roaming\a.exe
↓
C:\Users\<USER>\AppData\Roaming\a.exe
```

## 32.19 Manifest生成

Export時にはmanifest.jsonを生成する。

```json id="ssbjdj"
{
  "case_id": "case-...",
  "tool_version": "1.0.0",
  "schema_version": 1,
  "created_at_utc": "2026-07-01T12:00:00Z",
  "files": [
    {
      "path": "report.html",
      "sha256": "..."
    },
    {
      "path": "events.jsonl",
      "sha256": "..."
    },
    {
      "path": "case.sqlite",
      "sha256": "..."
    }
  ]
}
```

## 32.20 CUI実装構成

CUIプロジェクトを追加する。

```text id="gmldwh"
src/
  MRTW.Cli/
    Program.cs
    Commands/
      RunCommand.cs
      StaticCommand.cs
      ExportCommand.cs
      BatchCommand.cs
      DoctorCommand.cs
      VersionCommand.cs
    Options/
      RunOptions.cs
      StaticOptions.cs
      ExportOptions.cs
    Logging/
      CliLogger.cs
      JsonLineLogger.cs
```

CUIは以下のサービスをDIで利用する。

```text id="1khutm"
- IStaticAnalysisService
- IExecutionManager
- IEtwCollector
- IHookManager
- ISnapshotService
- IStorageService
- IExportService
- ICaseService
```

GUIとCUIで同じサービスを利用する。
CUI専用の解析ロジックを作らない。

## 32.21 CUI受け入れ条件

P0完了条件。

```text id="czwuf2"
1. mrtw version が動作する
2. mrtw doctor が動作する
3. mrtw static --target <exe> が動作する
4. mrtw run --target <exe> --duration 30 が動作する
5. case.sqliteが生成される
6. events.jsonlが生成される
7. report.htmlが生成される
8. mrtw export --case <case.sqlite> が動作する
9. 異常系で適切な終了コードを返す
10. --log-format json がJSON Linesを出力する
```

P1完了条件。

```text id="0d89bk"
1. mrtw batch が動作する
2. mrtw selftest が動作する
3. mrtw list が動作する
4. mrtw open がGUIを起動する
5. --profile が動作する
6. --privacy-mode on が動作する
```

## 32.22 Codexへの追加実装指示

CUIモードを実装すること。

実装優先度。

```text id="2gr42n"
1. MRTW.Cliプロジェクト追加
2. version
3. doctor
4. static
5. run
6. export
7. batch
8. selftest
9. list
10. open
```

重要制約。

```text id="ag25z8"
- GUIに依存しないこと
- Core/Collector/Storage/ExportはGUIと共通利用すること
- CUI専用の解析処理を重複実装しないこと
- 終了コードを定義通り返すこと
- 標準出力はtext/jsonを切り替え可能にすること
- --quietでは必要最小限のみ出力すること
- --verboseではcollector開始/停止、export詳細、例外詳細を出すこと
- マルウェアらしい挙動の有無で終了コードを変えないこと
```
