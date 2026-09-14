#!/bin/sh
# Prints the committer date of HEAD in the ISO-8601 form Maven expects for
# project.build.outputTimestamp (e.g. 2026-09-08T12:34:56Z), normalised to UTC.
#
# Used by the release workflow and by verify-reproducible.sh:
#   ./mvnw ... -Dproject.build.outputTimestamp="$(scripts/git-commit-timestamp.sh)"
#
# Why the commit date and not "now": two builds of the same commit must produce the
# same bytes. "now" changes every second; the commit date does not.
set -eu
TZ=UTC0 git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd "$@"
