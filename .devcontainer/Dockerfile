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
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# golangci-lintのインストール（最新版）
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.57.2

# 追加のGo開発用ツールのインストール（基本的なツールは既にインストール済み）
RUN go install github.com/cweill/gotests/gotests@latest \
    && go install honnef.co/go/tools/cmd/staticcheck@latest

# go-taskのインストール
RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# GitHub CLIは既にベースイメージに含まれているため、追加インストール不要
# ただし最新版にアップデート
RUN (type -p wget >/dev/null || (apt update && apt-get install wget -y)) \
    && mkdir -p -m 755 /etc/apt/keyrings \
    && wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt update \
    && apt install gh -y

# Node.jsとnpmのインストール（Claude Code CLIに必要）
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get install -y nodejs

# Claude Code CLIのインストール
RUN npm install -g @anthropic-ai/claude-code

# vsodeユーザー用エイリアス設定（Microsoft Dev Containersイメージにはvsocdeユーザーが存在）
USER vscode

# Go modulesキャッシュディレクトリの権限設定
RUN sudo mkdir -p /go/pkg/mod && sudo chown -R vscode:vscode /go

RUN echo "alias ll='ls -la'" >> ~/.bashrc \
    && echo "alias gs='git status'" >> ~/.bashrc \
    && echo "alias gd='git diff'" >> ~/.bashrc

# Go環境変数設定
ENV GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct \
    CGO_ENABLED=0 \
    GOPATH=/go \
    GOMODCACHE=/go/pkg/mod

# ワークスペースのGoモジュールキャッシュ用ボリュームマウントポイント
VOLUME ["/go/pkg/mod"]

# デフォルトユーザーに戻す
USER root
