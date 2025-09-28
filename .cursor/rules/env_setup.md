
### 環境変数の設定
- `.devcontainer/.env`ファイルに環境変数を設定
- `examples/config.json`を参考にSysdig APIトークンを設定
- 必要な環境変数:
  - `SYSDIG_API_TOKEN`: Sysdig APIトークン
  - `SYSDIG_API_URL`: Sysdig APIエンドポイント（デフォルト: https://us2.app.sysdig.com）
  - `CACHE_DIR`: キャッシュディレクトリ（デフォルト: /workspace/data）
  - `CACHE_TYPE`: キャッシュタイプ（sqlite/csv）

