#!/usr/bin/env bash
# Records the server's identity-switch call sites for one PostgreSQL release (owner-context
# design page Rev 2, section "Closure"; C-RC021-2c, -2g). Writes
#   gdpr-shredding-core/src/test/resources/owner-context/grep-<major>.txt
# from an unpacked source tree of the exact release the pinned image runs. The test
# call_site_list_matches_the_pinned_sources compares it with the map that ships in the jar
# (owner-context-call-sites-<major>.tsv), and call_site_record_is_for_the_pinned_server_version
# compares its first line with the pinned image. Run it at every pin bump.
#
# Usage: tools/owner-context-call-sites.sh <major> <path to postgresql-X.Y source tree>
#   The tree comes from https://ftp.postgresql.org/pub/source/vX.Y/postgresql-X.Y.tar.bz2,
#   checked against the .sha256 file published beside it.
set -euo pipefail

major="${1:-}"
src="${2:-}"
case "$major" in
  16|17) ;;
  *) echo "usage: $0 16|17 <postgresql source tree>" >&2; exit 2 ;;
esac
if [ ! -f "$src/configure" ]; then
  echo "not a PostgreSQL source tree: $src" >&2
  exit 2
fi
version="$(sed -n "s/^PACKAGE_VERSION='\(.*\)'$/\1/p" "$src/configure")"
case "$version" in
  "$major".*) ;;
  *) echo "source tree is PostgreSQL $version, not $major" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/gdpr-shredding-core/src/test/resources/owner-context/grep-$major.txt"
mkdir -p "$(dirname "$out")"

set +e
sites="$(cd "$src" && grep -rlE 'SetUserIdAndSecContext\(|fmgr_security_definer\(|SwitchToUntrustedUser\(' \
  src/backend src/pl contrib | LC_ALL=C sort)"
status=$?
set -e
# grep -l exits 1 when nothing matches: an empty list is not a clean result here.
if [ "$status" -ne 0 ] || [ -z "$sites" ]; then
  echo "grep found no call site (exit $status): refusing to write an empty record" >&2
  exit 1
fi
{
  echo "# postgresql $version"
  echo "$sites"
} > "$out"
echo "wrote $out"
