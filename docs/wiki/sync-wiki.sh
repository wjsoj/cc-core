#!/usr/bin/env bash
# 把 docs/wiki/ 同步到 GitHub Wiki（github.com/wjsoj/cc-core.wiki.git）。
#
# 前置条件：Wiki 仓库必须已经初始化过一次。
# GitHub 的 wiki git 仓库在“第一个页面被创建”之前是不存在的（clone 会报
# Repository not found），所以首次使用前需要在网页上
#   https://github.com/wjsoj/cc-core/wiki  →  Create the first page  →  Save
# 随便存一个空页面，之后本脚本就能一直用了。
#
# 用法：bash docs/wiki/sync-wiki.sh ["提交信息"]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO_ROOT/docs/wiki"
WIKI_URL="git@github.com:wjsoj/cc-core.wiki.git"
WORK="${TMPDIR:-/tmp}/cc-core-wiki"
MSG="${1:-docs(wiki): sync from docs/wiki@$(cd "$REPO_ROOT" && git rev-parse --short HEAD)}"

rm -rf "$WORK"
git clone --depth 1 "$WIKI_URL" "$WORK"

# 只同步 .md，脚本本身不进 wiki
find "$WORK" -maxdepth 1 -name '*.md' -delete
cp "$SRC"/*.md "$WORK"/

cd "$WORK"
git add -A
if git diff --cached --quiet; then
  echo "wiki 无变更"
  exit 0
fi
git commit -m "$MSG"
git push origin HEAD
echo "已推送到 $WIKI_URL"
