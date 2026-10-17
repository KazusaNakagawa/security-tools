"""Files written by `alertcheck init`."""

SCOPE_TEMPLATE = """\
# alertcheck 診断スコープ（仕様書 6.1 / 設計書 5.1）
# 自組織が管理権限を持つ資産だけを記載してください。第三者の資産を診断すると
# 不正アクセス禁止法等に抵触するおそれがあります。
organization: 組織名を記入

authorization:
  # 責任者が対象を自組織の資産と確認したら true にし、approver と confirmed_at を記入する。
  # false の間はネットワーク検査を一切実行しない。
  confirmed: false
  approver: null        # 例: 情報システム部 山田
  confirmed_at: null    # 例: 2026-10-17
  note: ""

targets:
  domains: []           # 例: [example.co.jp]（サブドメインを含む）
  urls: []              # 例: [https://shop.example.co.jp/]（このパス配下のみ）
  hosts: []             # 例: [203.0.113.10]
  cidrs: []             # 例: [203.0.113.0/28]

exclude: []             # 例: [https://shop.example.co.jp/checkout/, 203.0.113.5]

asset_inventory: null   # 例: inputs/assets.csv
url_allowlist: null     # 例: inputs/url_allowlist.txt
api_endpoints: null     # 例: inputs/api_endpoints.txt

limits:
  rps_per_host: 5
  concurrency: 4
  timeout_sec: 10
  allow_private_targets: false   # 名前解決先がプライベート IP の対象を許可する（検証環境向け）

active:
  enabled: false        # ログイン試行などのアクティブ検査。scan --active も必要

inputs:
  access_logs: []       # 例: [{path: "inputs/logs/*.log*", format: nginx_combined, site: shop}]
  auth_logs: []
  # accounts の例: [{path: inputs/accounts/gws.csv, service: google_workspace, mapping: gws}]
  accounts: []
  roster: null          # 例: inputs/hr/roster.csv
  deps: []              # 例: [{path: inputs/repos/shop}, {image: "registry.example/shop:1"}]
  data_inventory: null

cloud:
  aws:
    enabled: false
    regions: [ap-northeast-1]
"""

INPUT_DIRS = ["inputs/logs", "inputs/accounts", "inputs/hr", "inputs/repos", "out"]
