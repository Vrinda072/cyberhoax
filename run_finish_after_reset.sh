#!/bin/bash
# Cron wrapper for finish_after_reset.py.
#
# Installed to run hourly across the window after the Groq daily-token-cap reset
# (00:00 UTC). It is idempotent and self-cleaning: once the cross-check has a
# non-primary model row it removes its own crontab line and stops.
#
# Needs GROQ_API_KEY - read from ./.env (git-ignored).
# Logs to runs/finish_after_reset.log. Does NOT git commit - review, then commit.

set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO" || exit 1
LOG="$REPO/runs/finish_after_reset.log"
LOCKDIR="$REPO/runs/.finish.lock.d"

mkdir "$REPO/runs" 2>/dev/null
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "$(date -u) another run holds the lock; skip" >>"$LOG"
  exit 0
fi
trap 'rmdir "$LOCKDIR" 2>/dev/null' EXIT

remove_cron() {
  crontab -l 2>/dev/null | grep -v "run_finish_after_reset.sh" | crontab - 2>/dev/null
  echo "$(date -u) removed crontab entry" >>"$LOG"
}

done_check() {
  ./.venv/bin/python - <<'PY'
import json, sys
from pathlib import Path
p = Path("runs/cross_check.json")
try:
    d = json.loads(p.read_text())
    models = [m["model"] for m in d.get("models", [])]
    sys.exit(0 if any("gpt-oss-20b" != m for m in models) and models else 1)
except Exception:
    sys.exit(1)
PY
}

if done_check; then
  echo "$(date -u) already complete; nothing to do" >>"$LOG"
  remove_cron
  exit 0
fi

[ -f .env ] && set -a && . ./.env && set +a
if [ -z "${GROQ_API_KEY:-}" ]; then
  echo "$(date -u) GROQ_API_KEY not set (no .env?); abort" >>"$LOG"
  exit 1
fi

echo "$(date -u) ===== finish_after_reset.py start =====" >>"$LOG"
./.venv/bin/python finish_after_reset.py >>"$LOG" 2>&1
rc=$?
echo "$(date -u) ===== finish_after_reset.py exit $rc =====" >>"$LOG"

if [ $rc -eq 0 ] || done_check; then
  remove_cron
  echo "$(date -u) done. Review runs/report.md, then: git add runs/ && git commit" >>"$LOG"
fi
