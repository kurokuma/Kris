# Backlog

> 2026-07-18 update: README、既存バックログ、ケース保存・読込、静的トリアージ、行動相関、GUI/CLIの実装を再調査し、派生ファイル分析、portable case検証、IOC台帳、判定根拠、基準ケース比較、分析者注釈、横断検索、STIX出力、外部脅威インテリジェンス評価をTASK-014〜022として追加した。新規P0はない。
>
> 2026-07-20 update: 各コンポーネント（`MRTW.Core`／`MRTW.Collectors.Etw`／`MRTW.Native`／`MRTW.Cli`／`MRTW.App`）のReleaseビルド（警告0・エラー0）、回帰テスト70/70、プローブテストの成功を確認し、実コードを精読した。収集網羅性・相関精度・報告性・出所証明の観点でマルウェア分析に有効な未対応機能を洗い出し、ETW観測面拡張、プロセス横断注入相関、ATT&CKカバレッジ出力、プロセスツリーグラフ、ホストベースIOC拡張、ケースmanifest署名、分析環境透明性をTASK-023〜029として追加した。新規P0はない。除外方針（メモリ解析・YARA/YARA-X・capa）は維持する。

## 概要

- 最終更新日: 2026-07-20
- 調査対象: `README.md`、`docs/`、`src/MRTW.Core/`、`src/MRTW.Collectors.Etw/`、`src/MRTW.Cli/`、`src/MRTW.App/`、`src/MRTW.Native/`、`test/`
- 主要な懸念: 保存された派生ファイルを元イベントへ遡れないこと、portable caseの内部整合性を一括検証できないこと、IOCと行動判定根拠が型付き・再現可能な分析データになっていないこと、基準ケース比較・注釈・workspace横断pivot・標準形式共有が不足していること、ETW観測面がProcess/Network/ImageLoad/DNSに限られスクリプト・レジストリ・ファイルの逐次観測が弱いこと、行動相関がPID単位でプロセス横断注入を結べないこと、観測技術のATT&CK集計・グラフ・ケース出所証明が未整備であること
- 次に着手すべきタスク: 分析価値の高いTASK-014を先行し、その後はTASK-006（schema単一定義化）→TASK-015（portable case内部整合性検証）の依存順で着手する。収集網羅性を底上げするTASK-023（ETW観測面拡張）・TASK-024（横断注入相関）は独立トラックとして並行着手できる

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

以下のP1〜P3は、上記の実装済み機能を置き換える一覧ではなく、今後実装または調査する残課題である。TASK-003は利用者要求により削除済みで、現在記載するタスクは28件である。TASK-023〜029は2026-07-20のコンポーネント確認で追加した、収集網羅性・相関精度・報告性・出所証明を強化する分析価値の高いタスクである。メモリ解析・YARA/YARA-X・capa統合は現方針に従って含めない。

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

P1内は、未着手項目についてTASK-014、TASK-006、TASK-015、TASK-016、TASK-017の順に着手することを推奨する。収集網羅性・相関精度を高めるTASK-023、TASK-024はschema系タスクと依存が無く、別トラックとして並行着手できる。既存の完了項目は実装履歴として後続に残す。

### TASK-014: 保存された派生ファイルを系譜付きで再帰静的トリアージする

- 状態: 未着手
- 規模: L
- 概要: 実行中にドロップまたは変更され、ケースへ保存されたファイルを、元の収集証拠を変更せず、bounded・read-onlyで静的解析する。親process GUIDと作成／変更イベントIDを各派生結果へ付与し、検体から二次・多段ペイロードまでを追跡可能にする。
- 根拠: `src/MRTW.Core/SnapshotService.cs`の`PreserveChangedFiles`と`src/MRTW.Core/RuntimeCaseCollector.cs`は変更ファイルを保存し、File Create／Write／Deleteイベントを生成するが、`PreservedFile`は`OriginalPath`、`StoredPath`、サイズ、SHA-256、理由だけで親process GUID／作成イベントID／静的解析結果を持たない。また、before snapshotからprestagingされる実行可能ファイルには既に静的解析済みのroot targetも含まれ得て、削除されたprestaged fileは`deleted-high-risk-prestage`としてafter保存分へ合流するため、root target、root self-modification、prestaged deleted、真の派生ファイルを区別しない再解析は誤った系譜を作る。`StaticAnalysisService`と`NonPeTriageService`は一次ターゲットを安全に解析できるため、その境界を保存ファイルへ再利用できる。削除前の高リスクファイル保全は[MITRE ATT&CK T1070.004](https://attack.mitre.org/techniques/T1070/004/)のFile Deletion分析にも有効である。
- 対象: `src/MRTW.Core/SnapshotService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/StaticAnalysisService.cs`、`src/MRTW.Core/NonPeTriageService.cs`、`src/MRTW.Core/Models.cs`、`src/MRTW.Core/CaseExportService.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 保存時に同一正規化パス・時刻近傍・process GUIDを使ってFile Create／Write／Rename／Delete証拠を対応付ける。各保存物を`root-original`、`root-self-modified`、`prestaged-deleted`、`derived-created/modified`等の由来に分類する。静的解析時のroot pathとSHA-256に一致する`root-original`は既解析のため派生再帰対象から除外し、一次検体を二次payloadとして親子付けしない。root pathのafter版が起動前検証hashと異なり、自己書換えの根拠イベントがある場合だけ`root-self-modified`の別versionとして明示解析する。保存コピーのSHA-256を再検証後、PEと対応済み非PE形式を同じ非実行分析器へ渡し、子ファイル数、深さ、個別／合計バイト、文字列、時間、検出件数をケース全体の共有予算で制限する。コンテナはメモリ内のbounded inspectionだけとし、ディスクへ展開せず、シェル、COM、Office、MSI、スクリプト、デコーダーを起動しない。予算超過、対応不能、ハッシュ不一致、削除済み、読み取り失敗はCollection Qualityへ残し、原証拠を削除・上書きしない。結果と系譜をGUI、JSON/JSONL/CSV/HTML/SQLite/ZIPへ往復させ、Privacy Modeでは元パス等を共有ポリシーでマスクする。
- 完了条件:
  - [ ] PEと対応済み非PEの保存ファイルを実行・ディスク展開せず、共有予算内で再帰トリアージできる
  - [ ] 各派生結果に親process GUID、根拠となる作成／変更イベントID、保存ファイルSHA-256、解析深さが保存される
  - [ ] root-original、root-self-modified、prestaged-deleted、true derivedを区別し、既解析rootを派生再帰対象から除外する。自己改変rootは根拠イベントと異なるSHA-256がある場合だけ別versionとして解析する
  - [ ] 同名・rename・delete・PID再利用・対応不能を誤結合せず、曖昧さと欠落をCollection Qualityへ記録する
  - [ ] 全形式の往復、Privacy Mode、予算超過、ハッシュ不一致、悪性コンテナの回帰テストが成功する
- 依存関係: TASK-001、TASK-011、TASK-013
- リスク・注意点: 再帰解析は圧縮爆弾、解析時間増大、誤った親子付けを招く。既存の非実行・非展開境界を弱めず、派生結果と保存原証拠を明確に分離すること。

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

### TASK-015: portable caseの内部整合性を検証するCLIとGUI状態表示を追加する

- 状態: 未着手
- 規模: L
- 概要: case directoryまたはportable ZIPを開く前に、manifest、raw evidence、preserved evidence、ケースschemaをread-onlyで検証し、整合／不整合／不完全／未対応／出所未検証をGUIと機械可読CLI結果で区別する。署名または検証可能な信頼鎖がない限り、内部整合性が確認できても出所は未検証とする。
- 根拠: `src/MRTW.Core/CaseExportService.cs`の`WriteManifest`はcase directory直下のファイルへSHA-256を付けるが、`evidence/`や`raw/`の再帰検証器ではなく、CLIにも`verify`コマンドがない。`CaseService`はJSON 64 MiB、SQLite 512 MiB、行数・TEXT長等をboundedに読込む一方、portable ZIP全体のentry path、重複名、展開後合計サイズ、manifestとschemaの整合性を開く前に診断しない。
- 対象: `src/MRTW.Core/CaseExportService.cs`、`src/MRTW.Core/CaseService.cs`、`src/MRTW.Core/EvidencePathPolicy.cs`、`src/MRTW.Core/Models.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: `mrtw verify --case <dir|zip>`を追加し、ZIPをディスク展開せずストリームで走査する。entry数、個別／合計サイズ、圧縮率、manifestサイズ、ハッシュ計算量を共有予算で制限し、absolute／drive／UNC／`..` traversal、separator正規化後の重複、大小文字差の重複、file-directory衝突、symlink/reparse相当を拒否する。manifest未記載／欠落／余剰、raw/preserved metadataと実体、SHA-256不一致、schema未対応、構文不正、読取上限超過を別コードで報告する。検証は一切修復せず、GUIは開いたケースに検証時刻、内部整合性状態、出所未検証状態を分離して表示する。署名／信頼鎖がないportable caseを「信頼済み」と表示しない。Privacy Modeケースでは意図的に除外されたraw/preservedを欠損扱いせず、portable exportのポリシーと照合する。
- 完了条件:
  - [ ] 正常なdirectory／ZIPでmanifest、schema、raw／preserved evidenceをread-only検証し、CLI JSONとGUIに内部整合性状態を表示できる
  - [ ] traversal、重複entry、サイズ／圧縮率／件数超過、hash不一致、schema不一致、欠落／余剰を別の安定した診断コードで区別できる
  - [ ] 検証失敗時もケースやZIPを変更・展開せず、GUIの強制読込は不整合／不完全／未対応を明示する
  - [ ] 署名または検証可能な信頼鎖がないケースは、内部整合性の成否と別に「出所未検証」と表示する
  - [ ] 通常／Privacy Modeのportable exportと悪性ZIPフィクスチャの回帰テストが成功する
- 依存関係: TASK-001、TASK-004、TASK-006
- リスク・注意点: manifest自体を信頼の起点とみなしてはならない。署名のないケースでは「内部整合性」と「作成者真正性」を区別し、検証が成功しても安全な検体だとは表示しないこと。

### TASK-016: 型付きIOC台帳をケースの中核分析データとして追加する

- 状態: 未着手
- 規模: L
- 概要: hash、domain、IP、URL、path、registryを型付きIOCとして正規化・重複排除し、first/last seen、source、process GUID、evidence event IDsを保持する。静的・動的・派生ファイルの指標を一つのoffline台帳でpivotできるようにする。
- 根拠: `src/MRTW.Core/Models.cs`の`ArtifactItem`はtype/valueと集計値を持つが、根拠イベントIDやsource別来歴を表現しない。`NonPeTriageResult.Indicators`は文字列配列で、`NetworkSession`、Timeline、`NormalizedCommand`にもIOC候補が分散しており、`CaseExportService`は型付きIOCの全形式往復を提供していない。
- 対象: `src/MRTW.Core/Models.cs`、`src/MRTW.Core/StaticAnalysisService.cs`、`src/MRTW.Core/NonPeTriageService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/CaseExportService.cs`、`src/MRTW.Core/CaseService.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 種別ごとに決定的な正規化規則を定義し、原表記と正規化値を分離する。domainはIDN／末尾dot、IPはIPv4/IPv6、URLはscheme/host/port、hashはalgorithm/hex、pathとregistryはWindows表記を扱い、曖昧な値を別種別へ推測変換しない。重複IOCでは複数source、process GUID、evidence event IDsとfirst/last seenを和集合化し、件数・文字列長・正規化処理をケース共有予算で制限して超過をCollection Qualityへ記録する。外部通信なしで動作し、JSON/JSONL/CSV/HTML/SQLite/ZIPの保存・再読込・再exportを等価にする。Privacy Modeは共有redactor適用後も分析可能な型を残し、機微なpath/URL等を現行方針どおりマスクする。
- 完了条件:
  - [ ] 6種別を決定的に正規化・重複排除し、原表記、first/last seen、全source/process/evidence IDsを保持する
  - [ ] 静的、Timeline、Network、コマンド、TASK-014派生結果から同じ規則でIOCを生成する
  - [ ] 全export形式、SQLite／JSON再読込、再export、Privacy Modeで台帳が欠落・意味変化なく往復する
  - [ ] malformed IDN/URL/IP、上限超過、同値異表記、PID再利用を含むoffline回帰テストが成功する
- 依存関係: TASK-001、TASK-011、TASK-013、TASK-014
- リスク・注意点: 正規化し過ぎると異なる証拠を同一視する。原値と出典を失わず、IOC抽出のためにDNS、URL、ファイル、レジストリへアクセスしたり外部照会したりしないこと。

### TASK-017: 行動判定の説明可能性とruleset再現性を強化する

- 状態: 未着手
- 規模: M
- 概要: すべてのbuiltin／外部行動判定へstable rule ID、ruleset hash/version、confidence、matched evidence IDsを付け、同じ証拠とrulesetから判定を再現できるようにする。外部rulesetのfallbackや評価予算超過もCollection Qualityへ明示する。
- 根拠: `src/MRTW.Core/BehaviorCorrelator.cs`はbehaviorの`RawJson`へ`evidence_event_ids`を保存し、外部ルールではsummaryへ`rule_version`と`rule_hash`を埋め込むが、builtin判定にstable rule ID／ruleset hashがなく、説明情報が型付きではない。`BehaviorRuleLoader`は無効・過大・読取失敗時にbuiltin fallbackを返すが理由を公開せず、`RuleEvaluationBudget`の超過もCase Qualityへ伝播しない。
- 対象: `src/MRTW.Core/BehaviorRuleLoader.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.Core/Models.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/CaseExportService.cs`、`src/MRTW.Core/CaseService.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: rule identityとruleset metadataを型付きモデルにし、builtinにも変更管理されたstable ID/versionを割り当てる。ruleset hashはcanonicalな有効ルール集合から計算し、各判定にconfidence、matched evidence IDs、必要条件、除外条件、評価結果をboundedに保存する。外部rule fileの不在／不正／一部不正／上限／I/O失敗、builtin fallback、ordered comparison／finding等の共有予算超過を面別Collection Qualityへ記録する。ルール評価は既存どおり証拠を読むだけで、コマンド・検体・スクリプトを実行しない。GUIと全portable形式で説明を表示・往復し、Privacy Mode適用後のevidence参照を壊さない。
- 完了条件:
  - [ ] builtin／外部の全behaviorにstable rule ID、rule/ruleset versionとhash、confidence、matched evidence IDsがある
  - [ ] 同一schema・ruleset・入力イベントから同一判定メタデータを再生成できる
  - [ ] fallback理由と評価予算超過がCollection Qualityに残り、判定なしと評価不能を区別できる
  - [ ] GUI、JSON/JSONL/CSV/HTML/SQLite/ZIP、Privacy Mode、旧ケース読込の回帰テストが成功する
- 依存関係: TASK-001、TASK-011
- リスク・注意点: rule IDは表示名から暗黙生成せず、版管理する。confidenceは確率と断定せず、証拠削除やrule更新後の再評価結果を元の収集結果へ上書きしないこと。

### TASK-023: 実行時ETW観測面をAMSI・PowerShell・レジストリ・ファイルI/Oへ拡張する

- 状態: 完了 (2026-07-20)
- 規模: L
- 概要: 現在のETWはkernelのProcess/NetworkTCPIP/ImageLoadとuser-modeのDNS-Clientに限られ、スクリプト系・ファイルレス実行、実行中のレジストリ/ファイル改変を対象PIDツリーで逐次観測できない。AMSI、PowerShell ScriptBlock、kernel Registry/FileIOのETWプロバイダーを、既存のarm→PID bind→bounded保持の枠組みを保ったまま追加し、rootと子孫プロセスに限定して収集する。
- 根拠: `src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`は`KernelTraceEventParser.Keywords`の`Process`／`NetworkTCPIP`／`ImageLoad`だけを`EnableKernelProvider`で有効化し、user-modeは`Microsoft-Windows-DNS-Client`のみを`EnableProvider`する。Native Hookが利用不可・非対応・注入失敗の場合、スクリプト内容やレジストリ/ファイル改変の逐次証拠は`SnapshotService`の前後差分に依存し、実行中の順序と過渡的変更が欠落する。MITRE ATT&CKは[Command and Scripting Interpreter: PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)、[Impair Defenses: Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)、[Modify Registry (T1112)](https://attack.mitre.org/techniques/T1112/)を主要分析対象とする。
- 対象: `src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`、`src/MRTW.Collectors.Etw/AnalysisOrchestrator.cs`（`EtwCollectorOptions`）、`src/MRTW.Core/Models.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`test/SafeRuntimeProbe/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: `EtwCollectorOptions`へ末尾互換のオプション（`ScriptEvents`／`RegistryEvents`／`FileEvents`）を追加する。AMSIは`Microsoft-Antimalware-Scan-Interface`、PowerShellは`Microsoft-Windows-PowerShell`（ScriptBlock logging: EventId 4104相当）、レジストリ/ファイルはkernel `Registry`／`FileIOInit`キーワードを`EnableKernelProvider`へ加える。ScriptBlock/AMSI bufferは候補長・件数の上限付きで正規化テキストとして保持し、超過は既存の`BoundedCaptureBuffer`／Collection Qualityへ理由付きで記録する。すべて既存の`PidTreeFilter`でroot/子孫PIDに限定し、PID bind前の構造化データ・raw ETLは従来どおり保持しない。`BehaviorCorrelator`へ復号済みScriptBlock内容、AMSI無効化、実行時レジストリ永続化のルールを追加し、既存の技術マッピングと重複しないようにする。
- 完了条件:
  - [x] AMSI/PowerShell ScriptBlock/レジストリ/ファイルI/OのETWをroot/子孫PIDに限定して収集し、面別の上限・欠落・非対応をCollection Qualityへ記録する
  - [x] ScriptBlock/AMSIの実行時内容を候補長・件数上限付きで保持し、PID bind前は保持しないraw ETL境界と既存イベント順序・出力互換性を維持する
  - [x] Hook無効・非対応時でもスクリプト・レジストリ・ファイルの逐次証拠が得られ、Runtime/Snapshot経路と二重計上しない
  - [x] Regression tests cover option limits, correlation deduplication, pre-bind discard, Privacy Mode/export round trips, and unavailable-versus-no-observation quality states.
- 依存関係: TASK-001、TASK-002
- リスク・注意点: AMSI/PowerShellプロバイダーは環境・権限差が大きく、非管理者では取得不可を`unavailable`として明示し「変更なし」と誤表示しない。本タスクはETWイベント取得であり、プロセスメモリのダンプ・スキャンやシグネチャ照合（YARA/capa）は行わない現方針を維持する。ScriptBlockは機微情報を含み得るため、Privacy Modeの共有変換を必須とする。
- 検証: `test/MRTW.RegressionTests` の focused regression executable（options、ETW start failure時の面別`unavailable`、provider別/Registry/File品質、Snapshotまたは同一PID Hook/RuntimeとETW Registry永続化の根拠統合、behavior重複抑制、既存のPrivacy/export/pre-bind境界）を実行する。実際のAMSI/PowerShell provider取得はホスト設定に依存するため、回帰は注入済み結果による品質状態を検証する。

### TASK-024: プロセス横断の注入・生成連鎖を相関する

- 状態: 未着手
- 規模: M
- 概要: 現在の行動相関はPID単位でグルーピングするため、あるプロセスが別プロセスへ行うリモート注入（注入元PID→注入先PID）や、親子をまたぐ生成トリガを一つの振る舞いとして相関できない。注入元・注入先・実行APIを対象process GUIDで結び、プロセス横断のProcess Injection/Hollowingを根拠付きで提示する。
- 根拠: `src/MRTW.Core/BehaviorCorrelator.cs`の`Correlate`は`output...GroupBy(e => e.Pid)`で各PIDを独立評価し、`AddProcessInjection`／`AddProcessHollowing`は同一PID内のAPI列だけを判定する。`src/MRTW.Core/HookPipeServer.cs`の`MapTechnique`は`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`をT1055へ写像するが、これらが持ち得る注入先PID/handleを注入元PID単位でしか集計しない。MITRE ATT&CK [Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)は別プロセスへのコード注入を定義する。
- 対象: `src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.Core/HookPipeServer.cs`、`src/MRTW.Core/Models.cs`、`test/SyntheticBehaviorCase/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: HookイベントのRawJsonから注入先PID（`target_pid`）またはprocess handleを正規化し、PID単位相関の後に注入元PIDのAPI列（alloc/write/execute）と注入先PIDを対応付ける第二パスを追加する。target PIDが判明しないhandleベース注入は`target=unknown`として別扱いし、時刻近傍とprocess GUIDで裏取りする。突合対象数・比較回数を共有予算で制限し、超過をCollection Qualityへ記録する。横断findingは注入元/先両方のprocess GUIDと根拠event IDsを保持し、既存のPID内findingと識別可能にする。
- 完了条件:
  - [ ] 別PIDを対象とするalloc/write/execute連鎖を横断注入として相関し、注入元/先のprocess GUIDと根拠event IDsを保持する
  - [ ] target PIDが不明なhandleベース注入を`unknown`として区別し、無関係PIDへ誤結合しない
  - [ ] 既存のPID内注入/ホロウィング検知と重複せず、突合予算超過をCollection Qualityへ記録する
  - [ ] 合成ケースで横断注入、PID再利用、target不明を含む回帰テストが成功する
- 依存関係: なし
- リスク・注意点: PID再利用と短命プロセスにより注入先の同定は誤りやすい。時刻近傍とprocess GUIDで裏取りし、不確実な突合を`unknown`として断定しないこと。

### TASK-001: ETW・ランタイム収集結果に永続化用の上限と欠落品質情報を追加する

- 状態: 完了
- 規模: M
- 概要: RuntimeとETWの永続イベントを既定50,000件、ネットワークセッションを10,000件に先着保持で制限し、上限超過分の受信数・破棄数・理由をCollection Qualityへ保存する。raw ETLは512 MiBでrawと構造化ETWの双方を停止し、未完了rawを証拠として採用しない。
- 根拠: 実装前は`TraceEventEtwCollector`と`RuntimeCaseCollector`の永続収集が無制限だった。`BoundedCaptureBuffer<T>`を共有し、Runtime/ETW双方で同じ先着保持方針を実装した。
- 対象: `src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Collectors.Etw/AnalysisOrchestrator.cs`、`src/MRTW.Core/Models.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: `ExecutionProfile`／`EtwCollectorOptions`の末尾互換オプションで上限を指定できる。上限は中央検証で安全な範囲外を明示拒否する。`CollectorHealth.Message`に上限・受信数・破棄数・理由を記録し、ETWネットワーク品質も独立してGUI、JSON、SQLite、HTMLへ出力する。raw出力先は信頼済みケースscratch配下・reparse pointなしを入口でfail-closed検証し、既存ancestorを確認後に段階作成・再検証する。raw上限時はそのETLだけをbest-effortで削除する。非管理者回帰で先着順、破棄品質、JSON／SQLite／HTMLの出力、無効上限、未信頼rawパス、canonical traversal、利用可能な環境でのreparse pathの拒否を検証した。
- 完了条件:
  - [x] 高頻度イベントを発生させるテストで、メモリ上限相当の件数を超えても収集が完了する
  - [x] 破棄または打切り件数と理由が`CaseData.Quality`、JSON、SQLiteに保存される
  - [x] 上限未到達ケースのイベント順序と既存の出力互換性を維持する
  - [x] 関連テストが成功する
- 依存関係: なし
- リスク・注意点: 上限を設けると証拠が欠落するため、無言で切り捨ててはならない。ケース品質を低下として明示すること。

### TASK-002: 対象起動前にETWを準備し、短命プロセスの初期イベント欠落を減らす

- 状態: 完了
- 規模: L
- 概要: ETWを対象起動前にarmし、Ready barrierの成功後にRuntime収集を開始する。RuntimeがPIDを取得した時点で一度だけbindし、rootと子孫PIDだけを構造化保持する。
- 根拠: `AnalysisOrchestrator`、`TraceEventEtwCollector`、`RuntimeCaseCollector`を更新し、PID bind前にイベント・ネットワーク・ライブcallbackを保持しないことを実装した。
- 対象: `src/MRTW.Collectors.Etw/AnalysisOrchestrator.cs`、`src/MRTW.Collectors.Etw/TraceEventEtwCollector.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: `EtwArmedCapture`のReady/BindTarget/Stopを追加し、既存の`Collect` APIは維持した。ETW arm失敗、pre-launch cancel、integrity failureでもRuntimeは安全に継続または終了し、Stop/Disposeは冪等にした。ETW durationはPID bind後に開始する。
- 完了条件:
  - [x] PID bind前の構造化イベント、ネットワーク、callbackを保持しない
  - [x] root/child PIDに限定した構造化保持を実装する
  - [x] Stop、起動失敗、キャンセル時にcaptureを一回だけ停止する
  - [x] 関連テストとDebug/Releaseビルドが成功する
- 依存関係: なし（TASK-003は利用者要求により削除）
- リスク・注意点: arm中のraw kernel ETLはシステム全体を観測し得る。PID bind前のrawは保存対象外の構造化データと区別し、品質情報とREADMEで注意を明示する。

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

- 状態: 完了
- 規模: S
- 概要: `batch`は各ファイルに対して`Run`を直接呼ぶため、1件の例外でループ全体が中断する。大量検体の静的／動的処理では、失敗検体を記録して残りの検体を継続する必要がある。
- 根拠: 実装前の`src/MRTW.Cli/Program.cs`の`Batch`は列挙ループ内で`Run(batchOptions, json)`を呼び、検体単位の`try/catch`や失敗一覧を持たなかった。例外処理は`RunAsync`の最外層にあり、バッチ全体を終了していた。
- 対象: `src/MRTW.Cli/Program.cs`、`test/MRTW.RegressionTests/Program.cs`またはCLI統合テスト
- 実装内容: 検体ごとに例外と終了コードを捕捉し、成功・失敗・スキップの件数とファイル名、理由、出力先をJSONとテキストでサマリー化する。完了後のCLI終了コードを、部分失敗を呼出元が判定できる規約にする。
- 完了条件:
  - [x] 存在しない／破損した検体が混在しても後続検体を処理する
  - [x] 成功・失敗・スキップの件数と各理由を出力する
  - [x] 部分失敗時の終了コードを文書化し、テストで固定する
- 依存関係: なし
- リスク・注意点: `--network block`／`isolated`の失敗を隠蔽してはならない。検体ごとのfail-closed理由をそのまま記録すること。

### TASK-010: Windows永続化面（Startup・Task・Service・WMI）を状態差分として収集する

- 状態: 完了
- 規模: L
- 概要: 現在のランタイム収集はHKCU Run/RunOnceを中心としたレジストリ差分であり、Startup Folder、Task Scheduler、Windows Service、WMI permanent event subscriptionの新規・変更・削除をケースの状態差分として確認できない。これらは実際のマルウェアで用いられる代表的な永続化経路である。
- 根拠: `docs/architecture.md`はruntime collectionのレジストリ取得をHKCU Run/RunOnceと説明し、`src/MRTW.Core/SnapshotService.cs`もその範囲を取得する。MITRE ATT&CKは、[Boot or Logon Autostart Execution (T1547)](https://attack.mitre.org/techniques/T1547/)にRegistry Run Keys / Startup Folder・Active Setup等を、[Scheduled Task (T1053.005)](https://attack.mitre.org/techniques/T1053/005/)にスケジュールタスクを、[Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)にサービス永続化を定義している。
- 対象: `src/MRTW.Core/SnapshotService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.Core/Models.cs`、`src/MRTW.Core/CaseExportService.cs`、`test/SafeRuntimeProbe/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 各永続化面をbefore/afterで正規化して取得し、作成・変更・削除と実行先（コマンド、DLL、service binary、WMI consumer）をタイムラインとArtifactsへ出力する。WMIは`__FilterToConsumerBinding`を根拠にFilter／Consumerを正規化して対応付け、孤立した片側を永続化成立として出力しない。アクセス拒否・未対応OS・収集上限はCollection Qualityへ残す。管理者権限が必要な面は読み取り不可を明示し、推測結果を生成しない。
- 完了条件:
  - [x] Startup Folder、Task Scheduler、Windows Service、WMI permanent subscriptionの差分を個別に識別できる
  - [x] 各差分に根拠となる正規化データと取得時刻がTimeline／ケース出力に保存される
  - [x] 読み取り権限不足時に「存在しない」と誤表示せず、面別品質情報へ理由を記録する。512件上限では破棄数と`entry-limit`理由を記録する
  - [x] 安全なテストフィクスチャで作成・変更・削除、Privacy Modeを含む回帰テストが成功する
- 依存関係: なし（隔離VM統合試験は利用者要求によりバックログ対象外）
- リスク・注意点: ServiceやWMIの列挙は権限・環境差が大きい。収集器はCOM／レジストリ読み取りだけに限定し、Task XMLやWMIスクリプト本文を保存・実行しない。

## P2

P2内は、未着手項目についてTASK-018、TASK-019、TASK-020、TASK-021、TASK-007、TASK-008の順に着手することを推奨する。報告性を高めるTASK-025・TASK-026は依存が少なく独立して着手でき、ホストIOC拡張のTASK-027はTASK-016、ケース署名のTASK-028はTASK-015の後続とする。P1へ移したTASK-006のschema単一定義化を前提とする。

### TASK-018: 基準ケースとの差分表示と可逆なノイズ抑制を追加する

- 状態: 未着手
- 規模: L
- 概要: 同一環境・同一profileで取得した基準ケースと分析ケースを比較し、共通するOS／常駐ソフト由来イベントを可逆に抑制しながら、追加・欠落・変更されたprocess、file、registry、network、behavior、IOCを提示する。原証拠は削除しない。
- 根拠: `src/MRTW.Core/CaseService.cs`は単一ケースを読込み、`src/MRTW.App/ViewModels.cs`はそのTimeline、Process Tree、Artifactsをフィルター表示するが、別ケースとの比較モデルを持たない。既存の`SnapshotService.Diff`は一回の実行前後を比較するもので、反復実行時の環境ノイズと検体固有挙動を区別しない。
- 対象: `src/MRTW.Core/Models.cs`、`src/MRTW.Core/CaseService.cs`、追加するcase comparison service、`src/MRTW.App/`、`src/MRTW.Cli/Program.cs`、`src/MRTW.Core/CaseExportService.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: OS/build、MRTW/schema、profile、network mode、collector coverage、開始条件、対象architecture等の比較適格性を検査し、同一性を満たさない比較は品質低下として明示する。process GUIDやevent IDそのものではなく、型別の説明可能な正規化キーでexact／changed／only-baseline／only-analysis／ambiguousを算出する。抑制はGUI viewまたは派生比較結果だけに適用し、トグルで全原証拠へ戻せるようにする。比較件数・時間・文字列を共有予算で制限し、打切りとcoverage差をComparison Quality／Collection Qualityへ記録する。Privacy Modeが異なるケース間では安全な共通表現だけを比較し、portable exportへ比較元case ID/hashと規則versionを保存する。
- 完了条件:
  - [ ] 同一環境・同一profileの合成ケースで型別差分と共通ノイズを決定的に識別できる
  - [ ] 抑制前後を切替でき、元ケースのイベント、raw/preserved evidence、IOC、behaviorを削除・変更しない
  - [ ] 環境／profile／coverage／Privacy不一致、曖昧な対応、予算超過を比較品質として表示する
  - [ ] GUI／CLI、portable export、SQLite／JSON往復の回帰テストが成功する
- 依存関係: TASK-006、TASK-015、TASK-016、TASK-017
- リスク・注意点: baselineに存在する悪性挙動を自動で安全扱いしてはならない。「抑制」は非表示候補であり除外や削除ではなく、比較条件と規則を常に追跡可能にすること。

### TASK-019: event単位のbookmark・tag・commentを分析者ワークプロダクトとして追加する

- 状態: 未着手
- 規模: M
- 概要: Timeline eventへbookmark、複数tag、commentを付け、重要証拠の選別と分析メモをケースとともに持ち運べるようにする。収集証拠と分析者ワークプロダクトを別モデル・別保存領域として扱う。
- 根拠: `src/MRTW.App/ViewModels.cs`は`SelectedEvent`とbehaviorの`RelatedEvidenceEvents`を表示できるが注釈モデルがなく、`Models.cs`の`TimelineEvent`と`CaseData`、`CaseExportService`のSQLite／JSONにもanalyst annotationを表す領域がない。現在eventを直接変更するとraw evidence由来の収集結果と人手判断の境界が失われる。
- 対象: `src/MRTW.Core/Models.cs`、`src/MRTW.Core/CaseService.cs`、`src/MRTW.Core/CaseExportService.cs`、`src/MRTW.Core/PrivacyRedactor.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: event IDと補助的なstable event fingerprintを参照するannotation recordを設け、作成／更新時刻、bookmark、正規化tag、comment、任意のanalyst identifierを収集eventとは別に保存する。旧ケース、event再採番、欠落eventではorphanを黙って捨てず表示する。件数・tag/comment長をboundedに検証し、HTML/JSON/JSONL/CSV/SQLite/ZIPへ往復する。manifestにワークプロダクトの有無とhashを含め、元証拠hashとは分離する。Privacy Modeではcomment等にも共有redactorを適用し、匿名化できないanalyst identifierは既定でportable exportから除外する。
- 完了条件:
  - [ ] event単位でbookmark、複数tag、commentを作成・編集・削除し、収集event自体のhash／内容を変更しない
  - [ ] 通常／Privacy Modeの全形式で注釈を往復し、manifestで証拠とワークプロダクトを区別できる
  - [ ] 旧ケース、event再採番、参照先欠落、上限超過を安全に扱い、orphanを確認できる
  - [ ] GUIの選択・フィルターと保存／再読込の回帰テストが成功する
- 依存関係: TASK-015
- リスク・注意点: commentには個人情報や未検証の主張が入り得る。収集事実と分析者判断をUI・schema・exportで混同せず、自動的にbehavior confidenceやIOC真偽へ反映しないこと。

### TASK-020: workspace横断の類似検索と再生成可能な索引を追加する

- 状態: 未着手
- 規模: L
- 概要: workspace内のケースを横断し、hash、型付きIOC、behavior、normalized commandの同一・類似候補から関連ケースへpivotできるようにする。索引は元ケースから再生成可能なbounded・read-only派生データとする。
- 根拠: `src/MRTW.Cli/Program.cs`の`list --workspace`と`src/MRTW.App/ViewModels.cs`のRecent Casesはケース一覧を作るが、内容横断検索を行わない。hashはStatic Analysis、IOC候補はArtifacts／Network、behaviorはTimeline、コマンドは`NormalizedCommands`へ分散しており、workspace単位の関連付けがない。
- 対象: `src/MRTW.Core/CaseService.cs`、追加するworkspace index/search service、`src/MRTW.Core/Models.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: `CaseService`のbounded readerとTASK-015の検証結果を使い、case ID、case hash、schema、index versionと検索用の正規化値だけをローカル索引へ取り込む。完全hash／IOC一致、stable rule ID、正規化command token等の説明可能な尺度を優先し、類似スコアと一致根拠を表示する。走査ケース数、caseサイズ、値数、文字列、索引サイズ、処理時間を共有予算で制限し、破損・改変・未対応ケースを個別隔離して残りを継続する。索引は削除して再構築可能とし、ケースを変更せず外部送信もしない。Privacy Modeケースと通常ケースは機微値が一致しても自動joinせず、明示操作と警告なしに関連付けない。
- 完了条件:
  - [ ] hash／IOC／behavior／normalized-commandごとに一致根拠付きで関連ケースを検索できる
  - [ ] 索引を削除・再生成して同じ入力ケースから決定的な結果を得られ、原ケースを変更しない
  - [ ] 破損／未信頼／未対応schema／予算超過ケースを隔離し、他ケースの索引作成と検索を継続する
  - [ ] Privacy Modeと通常ケースを自動joinせず、offline動作、上限、索引更新の回帰テストが成功する
- 依存関係: TASK-006、TASK-015、TASK-016、TASK-017
- リスク・注意点: 横断相関自体が機微な関係情報になる。索引へraw evidenceやcomment全文を複製せず、workspace境界、Privacy区分、古い索引、case改変を明示すること。

### TASK-021: 分析根拠を保つSTIX 2.1 portable exportを追加する

- 状態: 未着手
- 規模: L
- 概要: 型付きIOC、観測、検体分析、行動判定と相互関係をSTIX 2.1 bundleとしてportable exportし、source、evidence、confidence、時刻を失わずに他ツールへ受け渡せるようにする。
- 根拠: `src/MRTW.Core/CaseExportService.cs`はMRTW固有のJSON/JSONL/CSV/HTML/SQLite/ZIPを出力するが、標準CTI形式はない。[OASIS STIX 2.1 Introduction](https://oasis-open.github.io/cti-documentation/stix/intro.html)はIndicator、Observed Data、Malware Analysis、Relationship等を使ってサイバー脅威情報と関係を交換する形式を定義している。
- 対象: `src/MRTW.Core/Models.cs`、`src/MRTW.Core/CaseExportService.cs`、追加するSTIX mapper/validator、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: TASK-016のIOCをIndicator／observed dataへ、検体hash・静的／動的結果をMalware Analysisへ、TASK-017の判定とsource/process/evidence参照をRelationshipまたはMRTW extensionへ決定的に写像する。STIX ID、timestamp、confidence、object marking、MRTW schema/ruleset情報を安定生成し、根拠を表現できない値を捏造しない。object数、文字列、bundleサイズ、変換時間を共有予算で制限し、除外／変換不能をCollection Qualityまたはexport warningへ残す。外部送信は行わずローカルファイルだけを作り、必ずPrivacy Modeの共有変換を先に適用したデータから出力する。
- 完了条件:
  - [ ] hash/domain/IP/URL等とObserved Data、Malware Analysis、RelationshipがSTIX 2.1準拠bundleとして出力される
  - [ ] source、first/last seen、process/evidence IDs、confidence、ruleset情報の対応を文書化し、検証器でschemaを確認する
  - [ ] Privacy適用前の値、raw/preserved evidence、ローカルpath等がportable STIXへ漏れず、外部通信が発生しない
  - [ ] 決定的ID、上限超過、変換不能、通常／Privacy Modeの回帰テストが成功する
- 依存関係: TASK-006、TASK-016、TASK-017
- リスク・注意点: STIXのIndicatorは単なる観測値と同義ではない。観測事実と検知patternを区別し、MRTW固有情報は標準objectの意味を曲げずextensionまたは外部参照として表すこと。

### TASK-025: 観測技術のATT&CKカバレッジ集計とNavigatorレイヤー出力を追加する

- 状態: 未着手
- 規模: M
- 概要: イベントとbehaviorにはMITRE ATT&CK技術IDが付与されるが、ケース全体でどの戦術・技術が観測されたかを集計・可視化・共有する手段がない。観測技術を戦術別に集計し、根拠event数・最大severity・confidence・根拠event IDsを保持したカバレッジ表と、ATT&CK Navigator互換のlayer JSONをオフラインで出力する。
- 根拠: `src/MRTW.Core/HookPipeServer.cs`の`MapTechnique`と`src/MRTW.Core/BehaviorCorrelator.cs`はTimelineEvent/behaviorへ`TechniqueId`／`TechniqueName`／`Confidence`を付与するが、`src/MRTW.Core/CaseExportService.cs`は技術を集計・レイヤー化せず、`src/MRTW.App/ViewModels.cs`にも戦術別カバレッジ表示がない。ATT&CK Navigatorはlayer JSON（`versions`、`techniques[].techniqueID/score/comment`）で技術を可視化する。
- 対象: `src/MRTW.Core/Models.cs`、追加するATT&CK集計/レイヤー生成サービス、`src/MRTW.Core/CaseExportService.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: TechniqueIdを持つ全イベント/behaviorから、technique→戦術（版管理された内蔵の静的マッピング表）・観測回数・最大severity・confidence・根拠event IDsを決定的に集計する。sub-technique（`T1055.012`等）は親技術へも巻き上げる。集計をcase.json／SQLite／HTMLへ往復させ、ATT&CK Navigator互換のlayer JSONを生成する。件数・文字列を共有予算で制限し、内蔵表に無い技術IDはレイヤーから除外して警告へ残す。外部通信は行わずローカルファイルのみを生成し、Privacy Mode適用後のデータから出力する。
- 完了条件:
  - [ ] 観測技術を戦術別に集計し、回数・severity・confidence・根拠event IDsを保持してGUI/HTML/JSON/SQLiteへ往復する
  - [ ] ATT&CK Navigator互換のlayer JSONを決定的に生成し、スキーマ検証で妥当性を確認する
  - [ ] sub-technique巻き上げ、未知ID、上限超過、Privacy Modeの回帰テストが成功する
  - [ ] 集計を観測事実として扱い、悪性判定やスコアを断定的な検知結論として表示しない
- 依存関係: なし（TASK-017の技術・ruleset metadata型付けと併せると整合が高い）
- リスク・注意点: カバレッジは観測有無であり検知網羅性ではない。内蔵マッピング表は版管理し、Navigator layerが悪性判定と誤解されない注記を付すこと。

### TASK-026: プロセスツリーとタイムラインのグラフ表現を出力する

- 状態: 完了（`ProcessTreeGraphBuilder`、process GUID優先のプロセスツリー／主要イベント連鎖、`process_tree.mmd`／`process_tree.dot`、HTML内のオフラインMermaidソース、および回帰テスト）
- 規模: S
- 概要: 現在のプロセス関係とイベント連鎖はCSV/HTMLの表でしか確認できず、親子関係・注入・生成の全体像を視覚的に把握できない。プロセスツリーと主要イベント連鎖を、外部レンダラを要求しないテキストグラフ（Mermaid／Graphviz DOT）としてオフライン出力し、HTMLレポートへ埋め込む。
- 根拠: `src/MRTW.Core/CaseExportService.cs`は`processes.csv`とHTMLの表を出力するが、`ProcessNode.ParentPid`が表す木構造をグラフ化しない。`src/MRTW.App/ViewModels.cs`はProcess Treeを画面表示するが、可搬な図として出力する経路がない。
- 対象: `src/MRTW.Core/CaseExportService.cs`、追加するグラフ生成ヘルパー、`src/MRTW.Cli/Program.cs`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: `ProcessNode`のPID/ParentPID/process GUIDから決定的にノード・エッジを構築し、Mermaid `flowchart`とGraphviz DOTを生成する。ノード数・エッジ数・ラベル長を上限付きで制限し、超過は省略して件数を注記する。ラベルはHTML/DOTエスケープし、severityで色分けする。生成した図をreport.htmlのMermaidブロックとして埋め込みつつ、単体ファイル（`process_tree.mmd`／`process_tree.dot`）としても出力する。
- 完了条件:
  - [x] PID/ParentPIDから決定的にMermaid/DOTのプロセスツリーを生成し、上限超過を注記する
  - [x] ラベルを安全にエスケープし、report.htmlへ埋め込みつつ単体ファイルも出力する
  - [x] 循環参照・PID再利用・孤立ノード・空ケースを安全に扱う回帰テストが成功する
- 依存関係: なし
- リスク・注意点: 大規模ケースで図が肥大化する。ノード上限と省略注記を必須とし、ラベルへコマンドライン全文を出さずPrivacy Mode規則を適用すること。

### TASK-027: ホストベースIOC種別（mutex/named pipe/service/task/imphash等）を追加する

- 状態: 未着手
- 規模: M
- 概要: TASK-016の型付きIOC台帳はhash/domain/IP/URL/path/registryを対象とするが、実運用のハンティングに有効なmutex名、named pipe名、service名、scheduled task名、imphash、PDBパスなどのホスト成果物IOCを型付けしない。これらを決定的に正規化・重複排除し、first/last seen・source・process GUID・根拠event IDsとともに台帳へ追加する。
- 根拠: `src/MRTW.Core/HookPipeServer.cs`は`mutex_name`／`pipe_name`／`service_name`等を`GetObjectValue`で捕捉し、`src/MRTW.Core/StaticAnalysisService.cs`は`Imphash`／`PdbPath`を算出するが、`src/MRTW.Core/Models.cs`のIOC表現（TASK-016想定）はこれらのホスト成果物型を持たない。MITRE ATT&CK [Create or Modify System Process (T1543)](https://attack.mitre.org/techniques/T1543/)や単一インスタンス制御用mutexは主要なハンティング指標である。
- 対象: `src/MRTW.Core/Models.cs`、`src/MRTW.Core/StaticAnalysisService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/CaseExportService.cs`、`src/MRTW.Core/CaseService.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: 種別ごとの正規化規則（mutex/pipeのセッション接頭辞`Local\`／`Global\`、service/taskの表記、imphashのhex、PDBのWindowsパス）を定義し、原表記と正規化値を分離する。TASK-016と同じ重複排除・source/process/evidence和集合・共有予算・Privacy Mode方針を再利用し、全export形式で往復させる。曖昧値を別種別へ推測変換せず、外部照会も行わない。
- 完了条件:
  - [ ] mutex/pipe/service/task/imphash/PDB等を決定的に正規化・重複排除し、原表記と全source/process/evidence IDsを保持する
  - [ ] 静的・動的・派生結果から同一規則でホストIOCを生成し、全形式・Privacy Modeで往復する
  - [ ] 同値異表記・上限超過・PID再利用を含むoffline回帰テストが成功する
- 依存関係: TASK-016
- リスク・注意点: セッション接頭辞やGUID付きの一時名を過度に正規化すると誤って同一視する。原値と出典を保持し、正規化規則を版管理すること。

### TASK-028: ケースmanifestのローカル署名で内部整合性に出所証明を付与する

- 状態: 未着手
- 規模: M
- 概要: TASK-015はportable caseの内部整合性を検証するが、署名や検証可能な信頼鎖がないため出所は常に未検証となる。manifestと再帰的な証拠ハッシュに対するローカル生成鍵のdetached署名を付与し、`verify`で署名者と改ざん有無を検証できるようにする。鍵管理と失効は運用者の責任とし、外部PKIやネットワークには依存しない。
- 根拠: `src/MRTW.Core/CaseExportService.cs`の`WriteManifest`はcase directory直下のファイルにSHA-256を付けるだけで、`evidence/`・`raw_evidence/`配下を再帰包含せず、署名も持たない。TASK-015のリスクは「manifest自体を信頼の起点とみなしてはならない」「署名のないケースでは内部整合性と作成者真正性を区別する」と明記する。
- 対象: `src/MRTW.Core/CaseExportService.cs`、追加する署名/検証サービスと鍵管理、`src/MRTW.Core/CaseService.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: manifestを`evidence/`・`raw_evidence/`を含む全出力の再帰ハッシュへ拡張し、その正規化バイト列にEd25519またはECDSA P-256のdetached署名（`manifest.sig`）と署名者公開鍵・鍵指紋・生成時刻を付す。鍵はローカルで生成・保管し、秘密鍵はケース・ログ・portable exportへ出力しない。TASK-015の`verify`は署名有無・署名検証結果・公開鍵指紋を内部整合性とは別の状態として報告し、署名がなければ従来どおり「出所未検証」を返す。署名検証は一切修復せず、鍵の信頼判断は運用者に委ねる。
- 完了条件:
  - [ ] manifestが`evidence/`・`raw_evidence/`を含む全証拠を再帰的にハッシュ包含し、detached署名と公開鍵指紋を生成できる
  - [ ] `verify`が署名有無・検証成否・鍵指紋を内部整合性と分離して報告し、無署名は「出所未検証」を維持する
  - [ ] 秘密鍵がケース・ログ・portable exportへ出力されないことをテストで確認する
  - [ ] 改ざん・鍵不一致・無署名・通常/Privacy Modeの回帰テストが成功する
- 依存関係: TASK-015
- リスク・注意点: 署名は「作成者の真正性」であり「検体の安全性」ではない。鍵配布と失効の枠組みがない限り信頼の起点にはならず、署名成功を安全判定と誤表示しないこと。秘密鍵・API鍵を成果物へ残さないこと。

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
- 依存関係: なし（隔離VM統合試験は利用者要求によりバックログ対象外）
- リスク・注意点: 検体コピーは証拠保全・AV検知・パス依存挙動に影響する。既定では専用VMでMRTWを管理者起動する案内を維持すること。

### TASK-011: エンコード済みスクリプトとLOLBin連鎖を正規化して分析する

- 状態: 完了
- 規模: M
- 概要: 現在はPowerShell文字列やコマンド候補を抽出・表示するが、Base64等で符号化されたPowerShell、`certutil`・`rundll32`・`regsvr32`・`mshta`等を経由した復号／実行連鎖を、元のコマンド、親子関係、復号後のIOCとして一貫して表示・相関しない。
- 根拠: `README.md`はPowerShell文字列とCommands Artifactを実装済みとしている。`src/MRTW.App/ViewModels.cs`のCommands Artifactはプロセス名・文字列の一致で候補を作る。MITRE ATT&CKは、[Obfuscated Files or Information (T1027)](https://attack.mitre.org/techniques/T1027/)および[Deobfuscate/Decode Files or Information (T1140)](https://attack.mitre.org/techniques/T1140/)で、Base64・XOR・圧縮・標準ユーティリティを使う復号／実行を代表的な分析対象として示している。
- 対象: `src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/HookPipeServer.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.App/ViewModels.cs`、`src/MRTW.Core/CaseExportService.cs`、`test/SyntheticBehaviorCase/`
- 実装内容: コマンドラインを構文単位で保存し、PowerShellの`-EncodedCommand`、`FromBase64String`、安全に復元できるBase64表現をサイズ上限付きでデコードする。復元に失敗した場合は原文・失敗理由を残す。LOLBin、親子プロセス、直前のファイル書込み／ダウンロードを根拠イベントとして結び、T1027/T1140または実行手法を提示する。
- 完了条件:
  - [x] Bounded Base64 PowerShell・LOLBin chains retain original text, normalized result, status, evidence event IDs, and export/SQLite backward compatibility without execution
  - [x] デコード対象のサイズ、ネスト深さ（0）、文字コード、失敗を上限付きで記録し、全体予算超過をCollection Qualityへ記録する
  - [x] 復元した内容がraw evidenceを改変せず、JSON/SQLite/HTMLに再現可能な形で保存される
  - [x] 関連テストが成功する
- 依存関係: TASK-001
- リスク・注意点: 復元処理はコードを実行してはならない。圧縮爆弾、深い再帰、巨大文字列を防ぐ上限を必須とする。

### TASK-012: ホスト設定・セキュリティ設定改ざんの観測範囲を追加する

- 状態: 完了
- 規模: M
- 概要: Run/RunOnce以外のレジストリ値、hostsファイル、WinHTTP/WinINet proxy、Defender除外、Firewall rule等の改ざんは、感染後のC2中継、検知回避、通信妨害を分析する重要な根拠になるが、現在のスナップショット差分では網羅されない。
- 根拠: `src/MRTW.Core/SnapshotService.cs`は限定されたレジストリ永続化面を収集する。`src/MRTW.Core/BehaviorCorrelator.cs`はWinINet/WinHTTP API観測からProxyを示すが、設定値のbefore/after証拠を取得しない。MITRE ATT&CKの[Modify Registry (T1112)](https://attack.mitre.org/techniques/T1112/)は設定・永続化・防御回避目的のレジストリ改変を、[Hide Artifacts (T1564)](https://attack.mitre.org/techniques/T1564/)は隠し属性・パス除外等の痕跡隠蔽を扱う。
- 対象: `src/MRTW.Core/SnapshotService.cs`、`src/MRTW.Core/RuntimeCaseCollector.cs`、`src/MRTW.Core/BehaviorCorrelator.cs`、`src/MRTW.Core/Models.cs`、`test/SafeRuntimeProbe/`
- 実装内容: hosts、proxy設定、ユーザー／マシンの主要なExplorer・Defender・Firewall・Security Center関連設定を、読み取り可能な範囲でbefore/after比較する。変更はキー／値またはファイルdiff、権限状態、収集対象バージョンを添えてタイムライン化する。危険な設定を変更するテストは使わず、事前作成した安全な一時キーとモック可能な抽象化で検証する。
- 完了条件:
  - [x] hosts・proxy・選定した設定面ごとに、変更／未変更／読み取り不能を区別して出力する
  - [x] 設定変更のタイムラインには根拠パス・値名・旧値／新値（Privacy Mode適用後）がある
  - [x] 収集器自身がFirewall・Defender・hosts設定を変更しないことをテストで確認する
  - [x] レジストリのエントリ・名前・値サイズ上限、および読取り中の再サイズをCollection Qualityへ記録し、部分値を出力しない
  - [x] 関連テストが成功する
- 依存関係: なし（隔離VM統合試験は利用者要求によりバックログ対象外）
- リスク・注意点: セキュリティ製品設定やhostsの実値は機微情報を含む。Privacy Mode、管理者権限、製品差分、OSバージョン差を明示すること。

### TASK-013: 非PE初期侵入形式を安全に静的トリアージする

- 状態: 完了
- 規模: M
- 概要: GUIとCLIの主な対象はEXE/DLLであり、LNK、PowerShell、JavaScript/VBScript、MSI、Office由来のコマンド、ZIP内の一次ファイルなど、マルウェア配布で頻出する非PE形式を実行せずに統一表示する機能がない。
- 根拠: READMEのGUI操作とCLI `run`はEXE/DLLを対象とし、`src/MRTW.Cli/Program.cs`の`batch`も`.exe`と`.dll`だけを列挙する。MITRE ATT&CKの[T1027](https://attack.mitre.org/techniques/T1027/)は圧縮・暗号化・エンコードされたファイルを、[T1140](https://attack.mitre.org/techniques/T1140/)は復号後の実行を分析対象として挙げている。
- 対象: `src/MRTW.Core/StaticAnalysisService.cs`、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`、`src/MRTW.Core/Models.cs`、`test/StaticAnalysisProbe/`、追加する安全なフィクスチャ
- 実装内容: ファイル種別判定をPE前提から分離し、LNK、PowerShell、JS/VBS、MSI、ZIPを検出して、メタデータ、埋込コマンド、URL、親ファイル、ハッシュ、展開候補を静的結果として出す。アーカイブ展開はファイル数・深さ・合計サイズ・パス走査の上限を持たせ、既定では実行しない。
- 完了条件:
  - [x] 各対応形式を実行せずに種別・主要IOC・抽出コマンドを表示できる
  - [x] ZIPのパストラバーサル、暗号化、深い入れ子、過大展開を安全に拒否または警告する
  - [x] EXE/DLLの既存静的解析出力との互換性を維持する
  - [x] 安全な各形式のフィクスチャで回帰テストが成功する
- 依存関係: なし（TASK-011は復号とLOLBin連鎖強化の後続タスク）
- リスク・注意点: 非PE解析は「実行可能性」を判定してはならない。Officeやスクリプトの内容は機微情報を含み得るため、エクスポートとPrivacy Modeの扱いを同時に定義すること。

## P3

P3内は、TASK-022の設計評価を先に行い、TASK-009のネットワークセンサー評価とはデータ取得境界を分離する。TASK-029の分析環境透明性は他のP3と独立で、収集をread-onlyに限定する。

### TASK-022: 外部脅威インテリジェンス照会の導入可否と安全境界を評価する

- 状態: 未着手（設計評価）
- 規模: M
- 概要: hash、domain、IP等のIOCを外部脅威インテリジェンスproviderへ照会する機能について、分析価値、情報漏えい、利用規約、再現性、運用コストを比較し、導入可否と安全要件を決定する。実装を自動的に約束するタスクではない。
- 根拠: 現在の`MRTW.Cli`、`MRTW.App`、`CaseExportService`はローカル解析・portable exportを中心とし、外部IOC照会、provider資格情報、cache、rate limitモデルを持たない。TASK-016の型付きIOCは照会候補を明確化する一方、Privacy Modeや未公開検体の指標を無断送信すると分析環境や案件を漏えいさせる。
- 対象: `docs/safety.md`、`src/MRTW.Core/Models.cs`、将来追加を検討するprovider abstraction/cache層、`src/MRTW.Cli/Program.cs`、`src/MRTW.App/`
- 実装内容: providerごとの送信可能な種別、認証情報管理、規約、データ保持、応答schema、可用性を比較する。採用候補は明示opt-inを必須とし、送信前にprovider名と正規化済みIOCの完全なプレビューを表示して個別／一括承認できる設計にする。実行ファイル、raw evidence、path、registry、comment、process情報は送らず、provider adapterをCore分析から分離する。cacheには取得時刻、provider、出典、TTL、rate-limit状態、失敗／timeoutを保存し、過去結果を現在値と誤表示しない。Privacy Modeでは既定禁止とし、解除も明示操作なしに許可しない。評価後は採用／不採用／保留と理由、脅威モデル、テスト方針を設計記録へ残す。
- 完了条件:
  - [ ] 候補providerごとに送信データ、認証、規約、保持、TTL、rate limit、失敗時挙動を比較した設計決定がある
  - [ ] 明示opt-in、送信プレビュー、provider分離、Privacy Mode既定禁止、外部送信なしのoffline既定動作を脅威モデルで確認する
  - [ ] 採用時の結果モデルが照会時点、出典、cache/TTL、失敗を保存し、portable exportとPrivacy適用範囲を定義している
  - [ ] 不採用または保留でも、offline分析機能を劣化させず、実装を行わない理由が記録される
- 依存関係: TASK-016
- リスク・注意点: IOC送信は機密案件の存在を第三者へ知らせ得る。TASK-009のpacket/TLS取得評価とは別機能であり、ネットワーク収集や外部照会を暗黙に有効化しないこと。API keyをケース、ログ、portable exportへ保存しない。

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
- 依存関係: なし（隔離VM統合試験は利用者要求によりバックログ対象外）
- リスク・注意点: パケット本文や復号情報は機微情報を含み得る。既存のPrivacy Modeと同等以上のデータ最小化・アクセス制御を設計すること。

### TASK-029: 検体休眠を解釈するための分析環境透明性レポートを追加する

- 状態: 未着手（設計評価を含む）
- 規模: S
- 概要: 検体が「何もしなかった」場合に、それが良性なのか環境検知による休眠なのかを分析者が判断できるよう、ホスト上のVM/サンドボックス/分析ツール痕跡と、アンチ分析API観測を突き合わせたread-onlyの環境透明性メモをケースへ付す。
- 根拠: `src/MRTW.Core/BehaviorCorrelator.cs`の`AddAntiAnalysis`／`AddSystemEnvironmentProfiling`はアンチ分析・環境プロファイリングAPIを検知するが、ホスト側にどのサンドボックス痕跡（既知VMベンダー文字列、代表的な分析ツールプロセス、少数CPU・少メモリ等）が存在するかを対応付けず、休眠の原因を説明しない。MITRE ATT&CK [Virtualization/Sandbox Evasion (T1497)](https://attack.mitre.org/techniques/T1497/)は環境検知による回避を扱う。
- 対象: `src/MRTW.Core/Models.cs`、`src/MRTW.Core/HostSecuritySnapshotProvider.cs`または追加する環境プロファイラ、`src/MRTW.Core/BehaviorCorrelator.cs`、`docs/safety.md`、`test/MRTW.RegressionTests/Program.cs`
- 実装内容: read-onlyで観測可能なホスト特性（論理CPU数、物理メモリ量、既知VMベンダー文字列、代表的な分析ツールプロセス名の有無）を上限付きで収集し、同一ケース内のアンチ分析API観測と対応付ける。環境痕跡は事実として記録し、検体の意図を断定しない。Privacy Modeではホスト名等を既存規則でマスクする。設計評価として、収集項目・偽陽性・プライバシー影響・不採用時の扱いを`docs/safety.md`へ記録する。
- 完了条件:
  - [ ] read-onlyの環境痕跡とアンチ分析API観測を同一ケースで対応付けて提示する
  - [ ] 環境痕跡を事実として記録し、休眠原因や悪性/良性を断定しない
  - [ ] Privacy Mode・非対応環境・上限超過の回帰テストが成功する
  - [ ] 収集がホスト設定を変更しないことをテストで確認する
- 依存関係: なし
- リスク・注意点: 環境痕跡の一致は回避の証明ではない。偽陽性を前提に説明的注記へ留め、収集がホスト設定を一切変更しないこと。

## 保留事項

- メモリ解析、YARA/YARA-X、capa統合は、現在は不要という方針が明示されているため、本バックログの実装タスクには登録しない。
- GUIの実ユーザー操作を通す自動テストは `test/Run-GuiSmoke.ps1` とAutomationIdを追加し、対話デスクトップで静的ターゲット選択、Start/Stop、タイムライン、Collection Quality、合成ケース読込、Privacy Modeエクスポートの実行証跡を取得済みである。CI環境への統合は未整備であり、通常実行には含めない。
- ネットワークのパケット本文・TLS指標は現実装で未対応だが、取得・保管の権限とプライバシー要件が未確定のためP3の評価タスクに留める。

## 調査メモ

- GUIとCLIは`AnalysisOrchestrator`を共有し、ETWは対象起動前にarmしてReady barrier後にRuntimeを開始する。root PID bind前の構造化イベント・ネットワーク・callbackは保持せず、bind後にroot/子孫PIDだけを対象にする。
- GUIのライブ表示に加え、収集器の永続データはRuntime／ETWイベント各50,000件、ネットワークセッション10,000件の先着保持上限と、raw ETL 512 MiB上限を持つ。受信数、破棄数、停止理由、欠落はCollection Qualityへ保存される。
- `CaseService`はJSON 64 MiB、SQLite 512 MiB、行数・TEXT長の入力上限を持ち、回帰テストもSQLite巨大TEXT、raw evidence整合性、Privacy Mode、静的解析上限を対象にしている。
- `NativeSafeRuntimeProbe`、`SafeRuntimeProbe`、`NativeExportProbe`は存在する。実環境のETW／Hook／Firewall統合試験は利用者要求によりバックログ対象外とする。
- `MRTW.sln`は.NETプロジェクトをビルドする。Native Hook／injectorはCMakeで別途ビルド・配置する運用である。
