# alertcheck

IPA「不正アクセスによる漏えい等の事案を踏まえ、速やかに実施すべき対策等について」（2026-10-09）の点検・対策項目を、自組織がどこまで満たしているか診断するローカル実行ツール。

- 仕様書: [docs/spec.md](docs/spec.md)
- 設計書: [docs/design.md](docs/design.md)

## 開発

```
uv sync
uv run pytest
uv run alertcheck init --workspace ./workspace
uv run alertcheck validate --workspace ./workspace
```
