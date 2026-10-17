#!/usr/bin/env bash
# Security review, PR 38 (C-PR-1) pass 2, 2026-10-17.
# probe_changelog_entry_has_an_unclosed_code_span
#
# Each Markdown list item (a "- " line plus its indented continuation lines) must hold an even
# number of backticks. An odd count is an unclosed code span: the rendered entry swallows the
# words after it into code and drops the closing mark of the next one.
# RED (exit 1) when any item is odd, naming its first line. GREEN (exit 0) when all are even.
# Exit 2 when the file is missing or unreadable.
# Usage: cipher-probe-c-pr38-p2-changelog-codespans.sh <module root>
set -euo pipefail
F="${1:?module root}/CHANGELOG.md"
[ -r "$F" ] || { echo "UNVERIFIABLE: no readable $F"; exit 2; }
awk '
  function flush() { if (start && n % 2 == 1) { print "ODD (" n "): line " start ": " first; bad = 1 } start = 0; n = 0 }
  /^```/ { fence = !fence; flush(); next }
  fence { next }
  /^- / { flush(); start = NR; first = $0 }
  /^[^ -]/ || /^$/ { flush(); next }
  start { t = $0; n += gsub(/`/, "", t) }
  END { flush(); exit bad }
' "$F" && { echo "GREEN: every CHANGELOG item closes its code spans"; exit 0; }
echo "RED: a CHANGELOG item has an unclosed code span"; exit 1
