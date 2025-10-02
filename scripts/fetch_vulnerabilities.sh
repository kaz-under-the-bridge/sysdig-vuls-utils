#!/bin/bash

# スクリプトの説明
# Sysdig Secure APIから脆弱性データを取得してSQLiteに保存するスクリプト
# パイプライン・ランタイム両方のスキャン結果を並列処理で取得

set -e

# ==================================================
# パフォーマンスレベル計算方法
# ==================================================
# パフォーマンスレベル: 1（最も安全）〜 30（最も高速）
#
# 基準値（元の設定）:
#   - バッチサイズ: 5
#   - API遅延: 0秒
#   - これをレベル30（最高速）とする
#
# 計算式:
#   バッチサイズ = ceil(レベル / 6)  # 1-30を1-5にマッピング
#   API遅延 = max(0, 6 - ceil(レベル / 5))  # レベルが高いほど遅延減少
#
# 例:
#   レベル30: バッチ5, 遅延0秒 (最速だがRate limit高リスク)
#   レベル20: バッチ4, 遅延2秒
#   レベル15: バッチ3, 遅延3秒 (バランス型)
#   レベル10: バッチ2, 遅延4秒
#   レベル5:  バッチ1, 遅延5秒
#   レベル1:  バッチ1, 遅延6秒 (最も安全)
# ==================================================

# デフォルト値
DEFAULT_DAYS=7
DEFAULT_PERF_LEVEL=25  # デフォルトは速度重視（API errorが多い場合は20, 15と減らす）

# Runtime制限のデフォルト値（critical/high絞り込み後の件数制限）
DEFAULT_RUNTIME_WORKLOAD_LIMIT=0  # 0 = 無制限（全件取得）
DEFAULT_RUNTIME_HOST_LIMIT=0      # 0 = 無制限
DEFAULT_RUNTIME_CONTAINER_LIMIT=0 # 0 = 無制限

# 引数処理（互換性維持）
DAYS=${1:-$DEFAULT_DAYS}

# 第2引数の処理: パフォーマンスレベルまたはバッチサイズ
if [ ! -z "$2" ]; then
    if [ "$2" = "perf" ] || [ "$2" = "-p" ]; then
        # パフォーマンスレベルモード
        PERF_LEVEL=${3:-$DEFAULT_PERF_LEVEL}
        if ! [[ "$PERF_LEVEL" =~ ^[0-9]+$ ]] || [ "$PERF_LEVEL" -lt 1 ] || [ "$PERF_LEVEL" -gt 30 ]; then
            echo "エラー: パフォーマンスレベルは1から30の間で指定してください"
            echo "使用法: $0 [日数] perf [レベル1-30]"
            echo "例: $0 7 perf 15  # バランス型"
            echo "    $0 7 perf 5   # 安全重視"
            echo "    $0 7 perf 25  # 速度重視"
            exit 1
        fi
        # パフォーマンスレベルから値を計算
        BATCH_SIZE=$(( ($PERF_LEVEL + 5) / 6 ))  # 1-30 → 1-5
        API_DELAY=$(( 6 - ($PERF_LEVEL + 4) / 5 ))  # レベルが高いほど遅延減少
        API_DELAY=$(( $API_DELAY < 0 ? 0 : $API_DELAY ))  # 負の値を0に
        echo "パフォーマンスレベル ${PERF_LEVEL} → バッチサイズ: ${BATCH_SIZE}, API遅延: ${API_DELAY}秒"
    else
        # 従来の直接指定モード（互換性維持）
        BATCH_SIZE=${2:-2}
        API_DELAY=${3:-3}

        # 引数の検証
        if ! [[ "$BATCH_SIZE" =~ ^[0-9]+$ ]] || [ "$BATCH_SIZE" -lt 1 ] || [ "$BATCH_SIZE" -gt 10 ]; then
            echo "エラー: バッチサイズは1から10の間で指定してください"
            exit 1
        fi

        if ! [[ "$API_DELAY" =~ ^[0-9]+$ ]] || [ "$API_DELAY" -lt 0 ] || [ "$API_DELAY" -gt 30 ]; then
            echo "エラー: API遅延は0から30秒の間で指定してください"
            exit 1
        fi
    fi
else
    # デフォルト値（perf 25相当：速度重視）
    BATCH_SIZE=5
    API_DELAY=1
fi

# Runtime制限値の設定
RUNTIME_WORKLOAD_LIMIT=${DEFAULT_RUNTIME_WORKLOAD_LIMIT}
RUNTIME_HOST_LIMIT=${DEFAULT_RUNTIME_HOST_LIMIT}
RUNTIME_CONTAINER_LIMIT=${DEFAULT_RUNTIME_CONTAINER_LIMIT}

# 日数の検証
if ! [[ "$DAYS" =~ ^[0-9]+$ ]] || [ "$DAYS" -lt 1 ] || [ "$DAYS" -gt 14 ]; then
    echo "エラー: 日数は1から14の間で指定してください"
    echo ""
    echo "使用法:"
    echo "  直接指定: $0 [日数] [バッチサイズ] [API遅延秒数]"
    echo "  レベル指定: $0 [日数] perf [パフォーマンスレベル]"
    echo ""
    echo "Runtime制限（デフォルト値、critical/high絞り込み後）:"
    echo "  - workload: 無制限（全件取得）"
    echo "  - host: 無制限"
    echo "  - container: 無制限"
    echo ""
    echo "例:"
    echo "  $0 7 2 3       # 直接指定"
    echo "  $0 7 perf 15   # レベル15（バランス型）"
    exit 1
fi

# .devcontainer/.envファイルの存在チェック
ENV_FILE=".devcontainer/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "エラー: ${ENV_FILE} が見つかりません"
    echo "Sysdig SecureからAPIトークンを取得して、.envファイルを作成してください"
    echo "cp .devcontainer/.env.example ${ENV_FILE}"
    exit 1
fi

# .envファイルを読み込み
if [ -f "$ENV_FILE" ]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

# 環境変数チェック
if [ -z "$SYSDIG_API_TOKEN" ]; then
    echo "エラー: SYSDIG_API_TOKEN環境変数が設定されていません"
    echo "${ENV_FILE} にトークンを設定してください"
    exit 1
fi

# タイムスタンプ付きディレクトリ作成
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DATA_DIR="data/${TIMESTAMP}"
mkdir -p "${DATA_DIR}"

# データベースファイルパス
PIPELINE_DB="${DATA_DIR}/pipeline_vulnerabilities.db"
RUNTIME_DB="${DATA_DIR}/runtime_vulnerabilities.db"

# ログファイルパス
PIPELINE_LOG="/tmp/pipeline_${TIMESTAMP}.log"
RUNTIME_LOG="/tmp/runtime_${TIMESTAMP}.log"

# OS判定してバイナリパスを決定
OS_TYPE=$(uname -s)
case "$OS_TYPE" in
    Darwin)
        BINARY="./bin/sysdig-vuls-darwin-arm64"
        ;;
    Linux)
        BINARY="./bin/sysdig-vuls"
        ;;
    *)
        echo "エラー: サポートされていないOS: $OS_TYPE"
        exit 1
        ;;
esac

echo "検出されたOS: $OS_TYPE"
echo "使用するバイナリ: $BINARY"

# バイナリの存在確認とビルド
if [ ! -f "$BINARY" ]; then
    echo "バイナリが見つかりません。ビルドを実行します..."
    if command -v task &> /dev/null; then
        # OS別にビルドタスクを実行
        case "$OS_TYPE" in
            Darwin)
                echo "macOS用にビルドします..."
                task build-darwin-arm64
                ;;
            Linux)
                echo "Linux用にビルドします..."
                task build
                ;;
        esac

        if [ ! -f "$BINARY" ]; then
            echo "エラー: ビルドに失敗しました"
            exit 1
        fi
        echo "ビルドが完了しました"
    else
        echo "エラー: taskコマンドが見つかりません"
        echo "go-taskをインストールするか、手動でビルドしてください"
        exit 1
    fi
fi

echo "========================================="
echo "Sysdig脆弱性データ取得スクリプト"
echo "========================================="
echo "日数: ${DAYS}日"
echo "バッチサイズ: ${BATCH_SIZE}"
echo "API遅延: ${API_DELAY}秒"
echo "Runtime制限: workload=${RUNTIME_WORKLOAD_LIMIT}, host=${RUNTIME_HOST_LIMIT}, container=${RUNTIME_CONTAINER_LIMIT}"
echo "データ保存先: ${DATA_DIR}"
echo "開始時刻: $(date)"
echo ""

# パイプラインスキャン結果の取得（バックグラウンド実行）
echo "パイプラインスキャン結果を取得中..."
${BINARY} -command pipeline-cache -days ${DAYS} -batch-size ${BATCH_SIZE} -api-delay ${API_DELAY} -cache "${PIPELINE_DB}" > "${PIPELINE_LOG}" 2>&1 &
PIPELINE_PID=$!
echo "  PID: ${PIPELINE_PID}"
echo "  ログ: ${PIPELINE_LOG}"

# ランタイムスキャン結果の取得（バックグラウンド実行）
echo ""
echo "ランタイムスキャン結果を取得中..."
${BINARY} -command runtime-cache -days ${DAYS} -batch-size ${BATCH_SIZE} -api-delay ${API_DELAY} \
    -runtime-workload-limit ${RUNTIME_WORKLOAD_LIMIT} \
    -runtime-host-limit ${RUNTIME_HOST_LIMIT} \
    -runtime-container-limit ${RUNTIME_CONTAINER_LIMIT} \
    -cache "${RUNTIME_DB}" > "${RUNTIME_LOG}" 2>&1 &
RUNTIME_PID=$!
echo "  PID: ${RUNTIME_PID}"
echo "  ログ: ${RUNTIME_LOG}"

# プロセス監視関数（20秒間隔で進捗表示）
wait_for_completion() {
    local pid=$1
    local name=$2
    local log=$3

    while kill -0 $pid 2>/dev/null; do
        # タイムスタンプ付きで最後の行を表示（進捗確認用）
        if [ -f "$log" ]; then
            last_line=$(tail -n 1 "$log" 2>/dev/null || echo "")
            if [ ! -z "$last_line" ]; then
                echo "$(date '+%H:%M:%S') [${name}] ${last_line}"
            fi
        fi
        sleep 20
    done

    # 終了ステータスチェック
    if wait $pid; then
        echo "✓ ${name}の取得が完了しました"
        return 0
    else
        echo "✗ ${name}の取得でエラーが発生しました"
        echo "  詳細はログファイルを確認してください: ${log}"
        return 1
    fi
}

echo ""
echo "処理実行中..."
echo "（進捗はログファイルで確認できます）"
echo ""

# 両方のプロセスが完了するまで待機
PIPELINE_SUCCESS=false
RUNTIME_SUCCESS=false

# パイプラインプロセスの監視
if wait_for_completion $PIPELINE_PID "パイプライン" "$PIPELINE_LOG"; then
    PIPELINE_SUCCESS=true
fi

# ランタイムプロセスの監視
if wait_for_completion $RUNTIME_PID "ランタイム" "$RUNTIME_LOG"; then
    RUNTIME_SUCCESS=true
fi

echo ""
echo "========================================="
echo "処理完了"
echo "========================================="
echo "終了時刻: $(date)"
echo ""

# 結果サマリー
echo "結果:"
if [ "$PIPELINE_SUCCESS" = true ]; then
    echo "  ✓ パイプラインデータ: ${PIPELINE_DB}"
    if [ -f "$PIPELINE_DB" ]; then
        echo "    サイズ: $(du -h ${PIPELINE_DB} | cut -f1)"
    fi
else
    echo "  ✗ パイプラインデータ: 取得失敗"
fi

if [ "$RUNTIME_SUCCESS" = true ]; then
    echo "  ✓ ランタイムデータ: ${RUNTIME_DB}"
    if [ -f "$RUNTIME_DB" ]; then
        echo "    サイズ: $(du -h ${RUNTIME_DB} | cut -f1)"
    fi
else
    echo "  ✗ ランタイムデータ: 取得失敗"
fi

echo ""
echo "ログファイル:"
echo "  - パイプライン: ${PIPELINE_LOG}"
echo "  - ランタイム: ${RUNTIME_LOG}"

# Claude Code用の指示を出力
echo ""
echo "========================================="
echo "次のステップ (Claude Code用の指示)"
echo "========================================="
echo ""
echo "以下の処理を実行してください:"
echo ""
echo "1. SQLiteデータベースの分析:"
echo "   - パイプラインDB: ${PIPELINE_DB}"
echo "   - ランタイムDB: ${RUNTIME_DB}"
echo ""
echo "2. 検索条件:"
echo "   - Severity: Critical または High"
echo "   - Fixable: true (修正可能な脆弱性)"
echo "   - Exploitable: true (悪用可能な脆弱性)"
echo ""
echo "3. レポート生成:"
echo "   - 出力先: ${DATA_DIR}/report.md"
echo "   - 形式: Markdownフォーマット"
echo "   - 内容:"
echo "     * エグゼクティブサマリー"
echo "     * 重要な脆弱性のリスト（CVE番号、パッケージ、修正バージョン）"
echo "     * 影響を受けるコンテナ/ランタイムの一覧"
echo "     * 推奨される対応アクション"
echo ""
echo "SQLクエリ例:"
echo "SELECT * FROM scan_vulnerabilities "
echo "WHERE LOWER(severity) IN ('critical', 'high') "
echo "  AND fixable = 1 "
echo "  AND exploitable = 1 "
echo "ORDER BY "
echo "  CASE LOWER(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 END, "
echo "  cvss_score DESC;"
echo ""
echo "========================================="

# エラーがあった場合は非ゼロで終了
if [ "$PIPELINE_SUCCESS" = false ] || [ "$RUNTIME_SUCCESS" = false ]; then
    exit 1
fi

exit 0