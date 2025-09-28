# Go開発環境用Dockerfile
# Microsoft Dev Containers Goイメージを使用
FROM mcr.microsoft.com/devcontainers/go:1-1.23-bookworm

# 作業ディレクトリ設定
WORKDIR /workspace

# 追加の開発ツールをインストール（基本ツールは既にベースイメージに含まれている）
RUN apt-get update && apt-get install -y \
    jq \
    vim \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*

# golangci-lintのインストール（最新版）
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.57.2

# 追加のGo開発用ツールのインストール（基本的なツールは既にインストール済み）
RUN go install github.com/cweill/gotests/gotests@latest \
    && go install honnef.co/go/tools/cmd/staticcheck@latest

# GitHub CLIは既にベースイメージに含まれているため、追加インストール不要

# vsodeユーザー用エイリアス設定（Microsoft Dev Containersイメージにはvsocdeユーザーが存在）
USER vscode
RUN echo "alias ll='ls -la'" >> ~/.bashrc \
    && echo "alias gs='git status'" >> ~/.bashrc \
    && echo "alias gd='git diff'" >> ~/.bashrc

# Go環境変数設定
ENV GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct \
    CGO_ENABLED=0

# ワークスペースのGoモジュールキャッシュ用ボリュームマウントポイント
VOLUME ["/go/pkg/mod"]

# デフォルトユーザーに戻す
USER root