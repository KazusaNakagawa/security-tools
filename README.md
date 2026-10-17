# alertcheck

IPA「不正アクセスによる漏えい等の事案を踏まえ、速やかに実施すべき対策等について」（2026-10-09）の点検・対策項目を、自組織がどこまで満たしているか診断するローカル実行ツール。自動診断・ファイル解析・質問票の結果から IPA の 27 項目それぞれに「達成 / 一部達成 / 未達 / 未確認 / 対象外」を判定し、HTML / JSON のレポートを出力する。

- 仕様書: [docs/spec.md](docs/spec.md)
- 設計書: [docs/design.md](docs/design.md)

> 診断対象は自組織が管理権限を持つ資産に限ってください。`scope.yaml` の `authorization.confirmed` を `true` にするまで、ネットワーク検査は一切実行されません。本ツールは IPA の公式ツールではありません。

## クイックスタート（Docker）

Docker Engine 24 以降と `docker compose` v2 が必要。コマンドはリポジトリのルートで実行する。

```sh
# 1. ワークスペース（scope.yaml・質問票・inputs/・out/）を作る
docker compose -f docker/compose.yaml run --rm alertcheck init

# 2. workspace/scope.yaml に対象と責任者の確認を書き、workspace/questionnaire.yaml に回答する
#    リポジトリやログは workspace/inputs/ 以下に置く（ワークスペースの外は参照できない）

# 3. KEV・EOL データと脆弱性 DB・nuclei テンプレートを取得する（初回と定期的に）
docker compose -f docker/compose.yaml run --rm alertcheck db update

# 4. 設定と入力を検証し、実行計画を確認する
docker compose -f docker/compose.yaml run --rm alertcheck validate

# 5. 診断して、レポートを出力する
docker compose -f docker/compose.yaml run --rm alertcheck scan
docker compose -f docker/compose.yaml run --rm alertcheck report
# → workspace/out/runs/<run_id>/report.html と report.json
```

ネットワークを使わずにファイル検査（依存関係など）だけを行う場合:

```sh
docker compose -f docker/compose.yaml run --rm --network none alertcheck scan --offline
```

ワークスペースの場所は `ALERTCHECK_WORKSPACE` で変えられる（既定は `./workspace`）。コンテナは uid 10001 の非 root ユーザー、読み取り専用のルートファイルシステム、`cap_drop: ALL` で動く。ワークスペースのディレクトリは uid 10001 から書き込めるようにしておくこと。

## 主なコマンド

| コマンド | 内容 |
|---|---|
| `init` | ワークスペースの雛形を作る |
| `validate` | 設定・入力を検証し、実行される検査と未確認になる IPA 項目を表示する |
| `scan [--only ...] [--skip ...] [--offline] [--active]` | 診断し、IPA 項目を判定して保存する |
| `report [--run RUN_ID] [--format html,json] [--redact-ips]` | 保存したランのレポートを出力する |
| `runs [RUN_ID]` | 実行履歴の一覧、または項目別の判定を表示する |
| `questionnaire init / show` | 質問票の雛形を作る / 回答状況を表示する |
| `db update` | KEV・EOL データとツールのデータベースを更新する |

終了コード（`scan` / `report`）: `0` critical・high なし、`1` high あり、`2` critical あり、`3` 実行エラー。

## 開発

```sh
uv sync
uv run pytest                                   # 単体テスト
ALERTCHECK_E2E=1 uv run pytest tests/e2e -q     # Docker を使う E2E テスト
uv run ruff check src tests && uv run ruff format --check src tests
```

E2E テストは、わざと設定不備を入れた標的（nginx・Node・Redis）を外部と通信できない内部 Docker ネットワークに立て、Docker イメージで診断して結果を確認する（`tests/e2e/`）。
