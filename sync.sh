#!/bin/bash
echo "=== 同步到 GitHub ==="
git push origin --all && git push origin --tags
echo ""
echo "=== 同步到 GitCode ==="
git push gitcode --all && git push gitcode --tags
echo ""
echo "=== 完成 ==="
