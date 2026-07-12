# Backlog

## 概要

- 最終更新日: 2026-07-12
- 調査対象: `README.md`、`docs/`、`src/MRTW.Core/`、`src/MRTW.Collectors.Etw/`、`src/MRTW.Cli/`、`src/MRTW.App/`、`src/MRTW.Native/`、`test/`
- 主要な懸念: 高頻度イベント時の収集メモリ上限、短命プロセスのETW開始タイミング、Windows永続化面の観測不足、スクリプト／非PE形式の分析不足、Windows実環境での統合試験不足、Privacy Modeとバッチ実行の検証不足
- 次に着手すべきタスク: TASK-001

このバックログは、現在の実装・文書・テストから確認できた未対応事項だけを記録する。完了済みのP0/P1 GUI停止・ライブ表示・SQLite入力上限の修正は、重複して登録しない。

## 現在実装済みの主要機能

| 分類 | 実装済みの内容 | 主な根拠・対象 |
|---|---|---|
| 静的解析 | MD5/SHA-1/SHA-256、PEヘッダー、Import/Export、Section、Resource、TLS Callback、PDB、.NETメタデータ、Authenticode、文字列・パッカー指標、HTML/JSON/CSV出力 | `README.md`「静的解析」、`src/MRTW.Core/StaticAnalysisService.cs` |
| 実行・動的収集 | EXE/DLL/コマンド実行、前後スナップショット、レジストリ差分、TCPスナップショット、プロセスツリー、ETW、x64 Native Hook、行動相関、Collection Quality | `README.md`「動的解析」、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Collectors.Etw/` |
| 安全制御 | `observe`/`block`/`isolated`のネットワークモード、管理者権限がない場合のfail-closed、起動直前の検体SHA-256再照合、Privacy Mode | `docs/safety.md`、`src/MRTW.Core/NetworkContainmentService.cs`、`RuntimeCaseCollector.cs`、`PrivacyRedactor.cs` |
| GUI・CLI | WPFでのターゲット選択、静的解析結果、ライブタイムライン、フィルター、Artifacts、ケース読込、エクスポート。CLIのstatic/run/export/batch/selftest/doctor/etw-smoke | `README.md`「WPF GUI」「CLIの使い方」、`src/MRTW.App/`、`src/MRTW.Cli/Program.cs` |
| ケース管理・出力 | JSON/JSONL/CSV/HTML/SQLite/ZIP、manifest、raw evidence・保存ファイルの整合性確認、JSON/SQLiteの再読込 | `src/MRTW.Core/CaseService.cs`、`CaseExportService.cs`、`EvidencePathPolicy.cs` |
| 回帰テスト | ネットワークモード、SQLite入出力上限、行動ルール、証拠パス・ハッシュ、Privacy Mode、静的解析上限、ライブバッファの境界 | `test/MRTW.RegressionTests/Program.cs` |

## 完了済みの主な修正・実装

以下は現在のソースに反映済みであり、未着手タスクとして重複登録しない。将来の回帰を防ぐため、関連する残課題だけをP1以降へ登録する。

- 静的解析の詳細結果をWPF GUIへ表示するタブを追加した（Import/Export、Section、Strings、Resources/TLS、Metadata、Indicators）。
- ケースschema v3、`process_guid`の保存、静的解析結果とCollection QualityのJSON/SQLite往復を実装した。
- SQLite／case JSON／raw evidence／証拠パスに入力サイズ、ハッシュ、reparse point、信頼済みrootの検証を追加した。
- 外部行動ルールの検証、評価予算、文字列長上限を実装し、無効ルールは安全にbuiltin ruleへフォールバックするようにした。
- GUIのStart/Stop/Restart、スナップショットのキャンセル、世代分離したライブ更新、履歴上限、終了時の最終ケース反映を実装した。
- Hook pipe、GUIライブキュー、静的文字列抽出に上限を設け、超過をCollection Qualityまたは画面へ記録するようにした。
- 検体の静的解析後から起動までの差替えを検出し、原子的な検証を保証できないUAC直接昇格起動を拒否するようにした。

## 未実装・修正予定の機能

以下のP1〜P3は、上記の実装済み機能を置き換える一覧ではなく、今後実装または調査する残課題である。タスクは13件に限定し、メモリ解析・YARA/YARA-X・capa統合は現方針に従って含めない。

## 優先順位の定義

| 優先度 | 定義 |
|---|---|
| P0 | 重大障害、データ破損、重大なセキュリティ問題 |
| P1 | 主要機能、信頼性、運用に大きく影響する問題 |
| P2 | 保守性、性能、観測性、使い勝手の改善 |
| P3 | 任意改善、将来的な候補 |

## P0

現時点の調査では該当なし。`MRTW.sln` のReleaseビルドと既存の回帰テストは成功している。

## P1

### TASK-001: ETW・ランタイム収集結果に永続化用の上限と欠落品質情報を追加する

- 状態: 未着手
- 規模: M
- 概要: 現在はGUI入力キューには上限がある一方、`TraceEventEtwCollector` のイベント／ネットワークセッションキューと `RuntimeCaseCollector` の永続ケース用リストは収集終了まで増加し続ける。高頻度の検体でメモリ消費が増大し、ケース確定またはエクスポートまで到達できない可能性がある。
- 根拠: `src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs` は `ConcurrentQueue<TimelineEvent>` と `ConcurrentQueue<NetworkSession>` に無制限に追加する。`src/MRTW.Core/RuntimeCaseCollector.cs` もイベントとネットワークセッションをリストに蓄積する。READMEはGUIライブ表示だけを10,000件に制限すると明記している。
- 対象: `src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Collectors.Etw/AnalysisOrchestrator.cs`、`src/MRTW.Core/Models.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 収集器ごとにイベント数・ネットワークセッション数・raw evidenceサイズの上限を設定可能にする。上限到達後は定義済み方針（停止または後続イベントの破棄）で動作し、破棄数・理由・開始／終了時刻を`CollectionQuality`へ保存する。GUI、JSON、SQLite、HTMLの品質表示が同じ欠落情報を示すようにする。
- 完了条件:
  - [ ] 高頻度イベントを発生させるテストで、メモリ上限相当の件数を超えても収集が完了する
  - [ ] 破棄または打切り件数と理由が`CaseData.Quality`、JSON、SQLiteに保存される
  - [ ] 上限未到達ケースのイベント順序と既存の出力互換性を維持する
  - [ ] 関連テストが成功する
- 依存関係: なし
- リスク・注意点: 上限を設けると証拠が欠落するため、無言で切り捨ててはならない。ケース品質を低下として明示すること。

### TASK-002: 対象起動前にETWを準備し、短命プロセスの初期イベント欠落を減らす

- 状態: 未着手
- 規模: L
- 概要: 現在のオーケストレーターはランタイム収集器が`Process Start`等でroot PIDを通知した後にETWを開始する。この順序では、短時間で終了する検体の開始直後のProcess・ImageLoad・TCP・DNSイベントを取得できない。
- 根拠: `docs/architecture.md` は「root PIDが判明してからETWを開始する」と記載している。`src/MRTW.Collectors.Etw/AnalysisOrchestrator.cs` も`rootPid.Task`完了後に`TraceEventEtwCollector.Collect`を開始している。
- 対象: `src/MRTW.Collectors.Etw/AnalysisOrchestrator.cs`、`src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Collectors.Etw/EtwCollectorOptions.cs`、`test/NativeSafeRuntimeProbe/`、`test/SafeRuntimeProbe/`
- 実装内容: ETWセッションを対象起動前に準備し、root PID確定後に対象PIDツリーへ確実に絞り込む設計へ変更する。PID確定前に取得したイベントの扱い、raw ETLの範囲、子プロセス追跡、キャンセル時のセッション停止を明文化する。
- 完了条件:
  - [ ] 100ms未満で終了する安全な検体で、root process start／exitの少なくとも一方と初期ImageLoadを取得できる
  - [ ] 対象外プロセスの構造化イベントがケースへ混入しない
  - [ ] Stop、タイムアウト、起動失敗の各経路でETWセッションが確実に停止する
  - [ ] 関連テストが成功する
- 依存関係: TASK-003
- リスク・注意点: 事前開始したカーネルETWはシステム全体を観測し得る。PID確定前のデータを保存・UI表示・Privacy Modeでどう扱うかを設計で固定すること。

### TASK-003: Windows隔離環境で実行するETW・Native Hook・containmentの統合試験を自動化する

  - 状態: ブロック中
- 規模: L
- 概要: 現在の回帰スイートは.NETの依存なし実行ファイルであり、実際のETWプロバイダー、Native Hook DLL／injector、Windows Firewall containmentを通した検証を行わない。実機依存機能の回帰を継続的に検出できない。
- 根拠: `test/MRTW.RegressionTests/MRTW.RegressionTests.csproj` はCoreとETWプロジェクトのみを参照し、`Program.cs`の21件は主にモデル・保存・境界テストである。`docs/safety.md` はETWとNative Hookの正確性検証には制御されたWindows環境が必要と明記し、`test/README.md` は`SafeRuntimeProbe`をhook/ETW smoke test用と定義している。
- 対象: `test/SafeRuntimeProbe/`、`test/NativeSafeRuntimeProbe/`、`test/NativeExportProbe/`、`src/MRTW.Native/`、`test/`の統合試験用スクリプト、CIまたは隔離VM実行手順
  - 実装内容: 管理者権限を持つ隔離Windows VM向けの統合試験ランナーを作る。SafeRuntimeProbeとNativeSafeRuntimeProbeで、ETWイベント、Hook pipeイベント、子プロセス追跡、`observe`／`block`／`isolated`の許可・失敗時fail-closed、Stop、エクスポート内容を検証する。通常のクロスプラットフォーム回帰とは分離する。`test/Run-IsolatedVmIntegration.ps1` にゲート付きの初期ランナーを実装済みだが、実際の隔離VM・管理者・Native成果物での実行証跡が未取得のため完了扱いにしない。
- 完了条件:
  - [ ] ネイティブhook/injectorをCMakeでビルドし、試験用出力へ配置できる
  - [ ] 隔離VMでETW・Hookそれぞれの取得結果とCollection Qualityを機械判定できる
  - [ ] Firewall ruleが試験後に削除されたことを確認する
  - [ ] 非管理者・プロバイダー利用不可時は期待したfail-closedまたはskipとして判定する
- 依存関係: なし
- リスク・注意点: 実検体を使わず、`test/`配下の安全なプローブのみを対象にする。`isolated`は専用VMでのみ実行すること。

### TASK-004: Privacy Modeの全エクスポート形式に対する漏えい回帰試験を追加する

  - 状態: 完了
- 規模: M
- 概要: Privacy Modeはパス、ユーザー名、ホスト名、プライベートIP、raw evidence、保存ファイルをマスクまたは除外する仕様だが、既存の回帰はプロファイル設定とraw ETLパスの無効化だけを確認している。HTML、CSV、JSON、JSONL、SQLite、ZIPでの実データ漏えいを検出する試験が必要である。
- 根拠: `README.md` はPrivacy Modeがユーザープロファイル名等をマスクすると説明する。`src/MRTW.Core/PrivacyRedactor.cs` は複数フィールドを変換し、`CaseExportService`は複数形式へ出力する。一方、`test/MRTW.RegressionTests/Program.cs`のPrivacyテストは`ExecutionProfile.PrivacyMode`を確認するのみで、各ファイル内容を検証していない。
- 対象: `src/MRTW.Core/PrivacyRedactor.cs`、`src/MRTW.Core/CaseExportService.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 固定のユーザー名・ホスト名・プライベートIP・ユーザープロファイルパス・raw/preserved evidenceを含むケースフィクスチャを用意し、全形式をPrivacy Modeでエクスポートする。アーカイブを展開して機密文字列が残らないこと、必要な分析メタデータは残ることを検証する。
- 完了条件:
    - [x] HTML、CSV、JSON、JSONL、SQLite、ZIPの全出力を検査する
    - [x] 固定した機密フィクスチャ文字列が出力に存在しない
    - [x] `RawEvidence`と`PreservedFiles`がPrivacy Mode出力に含まれない
    - [x] 関連テストが成功する
- 依存関係: なし
- リスク・注意点: 正規表現だけに依存せず、URL、JSON値、CSV引用、SQLite TEXT、ZIP内ファイルを個別に確認すること。マスキングし過ぎてIOCや時刻を失わないこと。

### TASK-005: CLI batchを検体単位で失敗隔離し、結果サマリーを出力する

- 状態: 未着手
- 規模: S
- 概要: `batch`は各ファイルに対して`Run`を直接呼ぶため、1件の例外でループ全体が中断する。大量検体の静的／動的処理では、失敗検体を記録して残りの検体を継続する必要がある。
- 根拠: `src/MRTW.Cli/Program.cs`の`Batch`は列挙ループ内で`Run(batchOptions, json)`を呼び、検体単位の`try/catch`や失敗一覧を持たない。例外処理は`RunAsync`の最外層にあり、バッチ全体を終了する。
- 対象: `src/MRTW.Cli/Program.cs`、`test/MRTW.RegressionTests/Program.cs`またはCLI統合テスト
- 実装内容: 検体ごとに例外と終了コードを捕捉し、成功・失敗・スキップの件数とファイル名、理由、出力先をJSONとテキストでサマリー化する。完了後のCLI終了コードを、部分失敗を呼出元が判定できる規約にする。
- 完了条件:
  - [ ] 存在しない／破損した検体が混在しても後続検体を処理する
  - [ ] 成功・失敗・スキップの件数と各理由を出力する
  - [ ] 部分失敗時の終了コードを文書化し、テストで固定する
- 依存関係: なし
- リスク・注意点: `--network block`／`isolated`の失敗を隠蔽してはならない。検体ごとのfail-closed理由をそのまま記録すること。

### TASK-010: Windows永続化面（Startup・Task・Service・WMI）を状態差分として収集する

- 状態: 未着手
- 規模: L
- 概要: 現在のランタイム収集はHKCU Run/RunOnceを中心としたレジストリ差分であり、Startup Folder、Task Scheduler、Windows Service、WMI permanent event subscriptionの新規・変更・削除をケースの状態差分として確認できない。これらは実際のマルウェアで用いられる代表的な永続化経路である。
- 根拠: `docs/architecture.md`はruntime collectionのレジストリ取得をHKCU Run/RunOnceと説明し、`src/MRTW.Core/SnapshotService.cs`もその範囲を取得する。MITRE ATT&CKは、[Boot or Logon Autostart Execution (T1547)](https://attack.mitre.org/techniques/T1547/)にRegistry Run Keys / Startup Folder・Active Setup等を、[Scheduled Task (T1053.005)](https://attack.mitre.org/techniques/T1053/005/)にスケジュールタスクを、[Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)にサービス永続化を定義している。
- 対象: `src/MRTW.Core/SnapshotService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.Core/Models.cs`、`src/MRTW.Core/CaseExportService.cs`、`test/SafeRuntimeProbe/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 各永続化面をbefore/afterで正規化して取得し、作成・変更・削除と実行先（コマンド、DLL、service binary、WMI consumer）をタイムラインとArtifactsへ出力する。アクセス拒否・未対応OS・収集上限はCollection Qualityへ残す。管理者権限が必要な面は読み取り不可を明示し、推測結果を生成しない。
- 完了条件:
  - [ ] Startup Folder、Task Scheduler、Windows Service、WMI permanent subscriptionの差分を個別に識別できる
  - [ ] 各差分に根拠となる元データと取得時刻が保存される
  - [ ] 読み取り権限不足時に「存在しない」と誤表示せず、品質情報へ理由を記録する
  - [ ] 安全なテストフィクスチャで作成・変更・削除の回帰テストが成功する
- 依存関係: TASK-003
- リスク・注意点: ServiceやWMIの列挙は権限・環境差が大きい。収集器が永続化を作成・変更してはならず、読み取り専用に限定すること。

## P2

### TASK-006: CLI versionのスキーマ表示を単一の定義へ統一する

- 状態: 未着手
- 規模: XS
- 概要: CLI versionのJSON出力ではschemaが`1`、人間向け表示では`3`となっており、ケース形式の利用者が互換性を誤判断する。
- 根拠: `src/MRTW.Cli/Program.cs`の`Version`は辞書に`["schema"] = 1`を設定する一方、同じメソッドの表示文字列には`Schema: 3`を埋め込んでいる。`CaseExportService`と回帰テストはschema v3を使用している。
- 対象: `src/MRTW.Cli/Program.cs`、必要に応じて`src/MRTW.Core/Models.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: スキーマバージョンをCoreの単一定数へ移し、JSONログ、通常出力、manifest、SQLite exportが同じ値を参照するようにする。
- 完了条件:
  - [ ] `mrtw version`のJSONと通常出力が同じschema値を返す
  - [ ] export manifestのschemaと一致する
  - [ ] 関連テストが成功する
- 依存関係: なし
- リスク・注意点: 既存ケースの読込互換性と、表示上のschemaバージョンを混同しないこと。

### TASK-007: config.yamlの厳格な検証と診断を追加する

- 状態: 未着手
- 規模: S
- 概要: 現在の設定パーサーは不正行・未知キー・不正なboolean値を無言で無視または既定値化する。運用者は設定ミスに気付かないまま既定のworkspace、profile、ログ形式で実行する可能性がある。
- 根拠: `src/MRTW.Core/MrtwConfigService.cs`は`:`のない行を無視し、`switch`にないキーを無視し、`ParseBool`失敗時にfalseを返す。READMEはconfig.yamlを正式な設定方法として文書化している。
- 対象: `src/MRTW.Core/MrtwConfigService.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`の設定読込箇所、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 設定読込結果にwarning/errorを持たせる。未知キー、重複キー、不正boolean、未展開または相対パス、未対応profile／log formatを検出し、CLIでは明確に失敗または警告、GUIではユーザーへ表示する。`doctor`にも有効な設定ファイルと診断結果を出す。
- 完了条件:
  - [ ] 不正な設定ごとにファイル名・行番号・原因が表示される
  - [ ] 誤った設定で静かに既定値へ戻らない
  - [ ] 正しい既存config.yamlとの後方互換性をテストする
- 依存関係: なし
- リスク・注意点: コメント、引用符、環境変数展開という現在対応している簡易YAMLの範囲を超えて、暗黙に完全なYAMLパーサーを名乗らないこと。

### TASK-008: 管理者権限が必要な検体の安全な実行方式を設計・実装する

- 状態: 未着手
- 規模: M
- 概要: 検体整合性を守るため、現在はSHA-256検証後にUAC ShellExecuteでの直接昇格起動を拒否する。この安全側の挙動により、管理者権限を必要とする検体は非管理者で分析できない。
- 根拠: `src/MRTW.Core/RuntimeCaseCollector.cs`は、整合性検証後の`ErrorElevationRequired`に対して「atomic verified path launchを保証できない」として例外を送出する。READMEも同じ制約を記載する。
- 対象: `src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/HookPipeServer.cs`、`src/MRTW.App/`、`src/MRTW.Cli/Program.cs`、`docs/safety.md`
- 実装内容: (a) MRTW自体を管理者で起動する事前チェックと明確な案内、または (b) 検証済みの一時コピーを信頼済み領域へ作成して起動する方式を比較し、選択した方式を実装する。起動した実体のハッシュ・パス・コピー時刻をケースへ記録する。
- 完了条件:
  - [ ] 非管理者で権限要求された場合に、安全な次の操作が明示される
  - [ ] 採用方式で検証対象と実行対象のSHA-256一致をケースへ記録する
  - [ ] 安全性を保証できない直接昇格起動は拒否される
  - [ ] 関連テストが成功する
- 依存関係: TASK-003
- リスク・注意点: 検体コピーは証拠保全・AV検知・パス依存挙動に影響する。既定では専用VMでMRTWを管理者起動する案内を維持すること。

### TASK-011: エンコード済みスクリプトとLOLBin連鎖を正規化して分析する

- 状態: 未着手
- 規模: M
- 概要: 現在はPowerShell文字列やコマンド候補を抽出・表示するが、Base64等で符号化されたPowerShell、`certutil`・`rundll32`・`regsvr32`・`mshta`等を経由した復号／実行連鎖を、元のコマンド、親子関係、復号後のIOCとして一貫して表示・相関しない。
- 根拠: `README.md`はPowerShell文字列とCommands Artifactを実装済みとしている。`src/MRTW.App/ViewModels.cs`のCommands Artifactはプロセス名・文字列の一致で候補を作る。MITRE ATT&CKは、[Obfuscated Files or Information (T1027)](https://attack.mitre.org/techniques/T1027/)および[Deobfuscate/Decode Files or Information (T1140)](https://attack.mitre.org/techniques/T1140/)で、Base64・XOR・圧縮・標準ユーティリティを使う復号／実行を代表的な分析対象として示している。
- 対象: `src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/HookPipeServer.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.App/ViewModels.cs`、`src/MRTW.Core/CaseExportService.cs`、`test/SyntheticBehaviorCase/`
- 実装内容: コマンドラインを構文単位で保存し、PowerShellの`-EncodedCommand`、`FromBase64String`、安全に復元できるBase64表現をサイズ上限付きでデコードする。復元に失敗した場合は原文・失敗理由を残す。LOLBin、親子プロセス、直前のファイル書込み／ダウンロードを根拠イベントとして結び、T1027/T1140または実行手法を提示する。
- 完了条件:
  - [ ] 安全なBase64 PowerShell・certutil・rundll32・regsvr32・mshtaのフィクスチャで、原文・復元結果・親子関係を確認できる
  - [ ] デコード対象のサイズ、ネスト深さ、文字コード、失敗を上限付きで記録する
  - [ ] 復元した内容がraw evidenceを改変せず、JSON/SQLite/HTMLに再現可能な形で保存される
  - [ ] 関連テストが成功する
- 依存関係: TASK-001
- リスク・注意点: 復元処理はコードを実行してはならない。圧縮爆弾、深い再帰、巨大文字列を防ぐ上限を必須とする。

### TASK-012: ホスト設定・セキュリティ設定改ざんの観測範囲を追加する

- 状態: 未着手
- 規模: M
- 概要: Run/RunOnce以外のレジストリ値、hostsファイル、WinHTTP/WinINet proxy、Defender除外、Firewall rule等の改ざんは、感染後のC2中継、検知回避、通信妨害を分析する重要な根拠になるが、現在のスナップショット差分では網羅されない。
- 根拠: `src/MRTW.Core/SnapshotService.cs`は限定されたレジストリ永続化面を収集する。`src/MRTW.Core/BehaviorCorrelator.cs`はWinINet/WinHTTP API観測からProxyを示すが、設定値のbefore/after証拠を取得しない。MITRE ATT&CKの[Modify Registry (T1112)](https://attack.mitre.org/techniques/T1112/)は設定・永続化・防御回避目的のレジストリ改変を、[Hide Artifacts (T1564)](https://attack.mitre.org/techniques/T1564/)は隠し属性・パス除外等の痕跡隠蔽を扱う。
- 対象: `src/MRTW.Core/SnapshotService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.Core/Models.cs`、`test/SafeRuntimeProbe/`
- 実装内容: hosts、proxy設定、ユーザー／マシンの主要なExplorer・Defender・Firewall・Security Center関連設定を、読み取り可能な範囲でbefore/after比較する。変更はキー／値またはファイルdiff、権限状態、収集対象バージョンを添えてタイムライン化する。危険な設定を変更するテストは使わず、事前作成した安全な一時キーとモック可能な抽象化で検証する。
- 完了条件:
  - [ ] hosts・proxy・選定した設定面ごとに、変更／未変更／読み取り不能を区別して出力する
  - [ ] 設定変更のタイムラインには根拠パス・値名・旧値／新値（Privacy Mode適用後）がある
  - [ ] 収集器自身がFirewall・Defender・hosts設定を変更しないことをテストで確認する
  - [ ] 関連テストが成功する
- 依存関係: TASK-003
- リスク・注意点: セキュリティ製品設定やhostsの実値は機微情報を含む。Privacy Mode、管理者権限、製品差分、OSバージョン差を明示すること。

### TASK-013: 非PE初期侵入形式を安全に静的トリアージする

- 状態: 未着手
- 規模: M
- 概要: GUIとCLIの主な対象はEXE/DLLであり、LNK、PowerShell、JavaScript/VBScript、MSI、Office由来のコマンド、ZIP内の一次ファイルなど、マルウェア配布で頻出する非PE形式を実行せずに統一表示する機能がない。
- 根拠: READMEのGUI操作とCLI `run`はEXE/DLLを対象とし、`src/MRTW.Cli/Program.cs`の`batch`も`.exe`と`.dll`だけを列挙する。MITRE ATT&CKの[T1027](https://attack.mitre.org/techniques/T1027/)は圧縮・暗号化・エンコードされたファイルを、[T1140](https://attack.mitre.org/techniques/T1140/)は復号後の実行を分析対象として挙げている。
- 対象: `src/MRTW.Core/StaticAnalysisService.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`src/MRTW.Core/Models.cs`、`test/StaticAnalysisProbe/`、追加する安全なフィクスチャ
- 実装内容: ファイル種別判定をPE前提から分離し、LNK、PowerShell、JS/VBS、MSI、ZIPを検出して、メタデータ、埋込コマンド、URL、親ファイル、ハッシュ、展開候補を静的結果として出す。アーカイブ展開はファイル数・深さ・合計サイズ・パス走査の上限を持たせ、既定では実行しない。
- 完了条件:
  - [ ] 各対応形式を実行せずに種別・主要IOC・抽出コマンドを表示できる
  - [ ] ZIPのパストラバーサル、暗号化、深い入れ子、過大展開を安全に拒否または警告する
  - [ ] EXE/DLLの既存静的解析出力との互換性を維持する
  - [ ] 安全な各形式のフィクスチャで回帰テストが成功する
- 依存関係: TASK-011
- リスク・注意点: 非PE解析は「実行可能性」を判定してはならない。Officeやスクリプトの内容は機微情報を含み得るため、エクスポートとPrivacy Modeの扱いを同時に定義すること。

## P3

### TASK-009: ネットワーク証拠のペイロード／TLS指標を取得する拡張方式を評価する

- 状態: 未着手
- 規模: L
- 概要: 現在のETWとHookのNetworkSessionは接続、DNS、HTTPメタデータを中心とし、パケット本文、TLS復号、JA3等は取得しない。追加のネットワーク証拠が必要な案件向けに、外部キャプチャまたは専用センサー連携の設計判断が必要である。
- 根拠: `src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`はUDP coverageを`payload/TLS/JA3 unsupported`と明示する。`src/MRTW.Core/RuntimeCaseCollector.cs`もHookのcoverageを`no packet/TLS payload`と記録する。
- 対象: `src/MRTW.Collectors.Etw/`、`src/MRTW.Core/Models.cs`、`docs/safety.md`、将来追加する外部センサー連携層
- 実装内容: ETWの範囲を超える情報を、MRTW本体で取得するか、PCAP／プロキシ／TLSセンサーの外部成果物として関連付けるかを評価する。採用時は保存容量、Privacy Mode、暗号化通信、権限、ケースハッシュ、エクスポート形式を設計する。
- 完了条件:
  - [ ] 収集方式ごとの取得可能データ、権限、プライバシー影響、保存容量を比較した設計決定がある
  - [ ] 採用しない場合も、現在のcoverage表示が誤解を招かないことを確認する
  - [ ] 採用する場合は安全なプローブを用いた統合試験がある
- 依存関係: TASK-003
- リスク・注意点: パケット本文や復号情報は機微情報を含み得る。既存のPrivacy Modeと同等以上のデータ最小化・アクセス制御を設計すること。

## 保留事項

- メモリ解析、YARA/YARA-X、capa統合は、現在は不要という方針が明示されているため、本バックログの実装タスクには登録しない。
- GUIの実ユーザー操作を通す自動テストは `test/Run-GuiSmoke.ps1` とAutomationIdを追加したが、CI環境と利用可能なWindows対話セッションの情報が不足しており、実行証跡は未取得である。通常実行には含めない。
- ネットワークのパケット本文・TLS指標は現実装で未対応だが、取得・保管の権限とプライバシー要件が未確定のためP3の評価タスクに留める。

## 調査メモ

- GUIとCLIは`AnalysisOrchestrator`を共有し、ETWはroot PIDの通知後に開始する。これは対象外イベントの混入を防ぐ一方、短命プロセスの初期イベント欠落につながる。
- GUIのライブ表示には上限と欠落表示があるが、収集器の永続データ側には同等の上限が確認できない。
- `CaseService`はJSON 64 MiB、SQLite 512 MiB、行数・TEXT長の入力上限を持ち、回帰テストもSQLite巨大TEXT、raw evidence整合性、Privacy Mode、静的解析上限を対象にしている。
- `NativeSafeRuntimeProbe`、`SafeRuntimeProbe`、`NativeExportProbe`は存在するが、.NET回帰スイートから実環境のETW／Hook／Firewallを通して実行する統合試験は確認できない。
- `MRTW.sln`は.NETプロジェクトをビルドする。Native Hook／injectorはCMakeで別途ビルド・配置する運用である。
