#!/usr/bin/env bash
#
# Installs one vulnerability scanner at a pinned version, verified byte for byte against a
# checksum recorded in THIS file, into a directory the caller names.
#
#   tools/install-scanner.sh osv-scanner "$RUNNER_TEMP/bin"
#   tools/install-scanner.sh grype       "$RUNNER_TEMP/bin"
#   tools/install-scanner.sh --print-versions
#
# Why a pinned binary and not the vendors' GitHub Actions (the deviation from "pin the
# action SHA", recorded in QUESTIONS):
#
#   1. google/osv-scanner-action is a DOCKER action. Pinning the action's commit sha pins
#      the twenty lines of YAML, not the scanner: the image reference inside it is the
#      mutable tag ghcr.io/google/osv-scanner-action:v2.6.0. The thing that decides whether
#      a release goes out would still be a moving target.
#   2. Upstream says so itself: "We recommend using the reusable workflows instead of
#      directly using the scanner action as the scanner action behavior might change in a
#      minor patch update."
#   3. Both gates need control of the exit code. The scanners exit non-zero on ANY finding;
#      the threshold this project gates on is one definition, in
#      tools/check-vulnerability-report.py, applied to a JSON report by us.
#
# Fail closed, always. A download that fails, a checksum that does not match, an unknown
# platform, a missing tool: all refuse with a non-zero exit and a reason. A scan that could
# not run is never reported as a scan that found nothing.
#
# Upgrading: bump the version and BOTH checksums from the release's own published checksum
# file (osv-scanner_SHA256SUMS, grype_<version>_checksums.txt). The weekly security duty
# includes checking whether a newer scanner exists.
#
set -euo pipefail

OSV_VERSION="2.6.0"
OSV_SHA256_linux_amd64="ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"
OSV_SHA256_linux_arm64="2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4"
OSV_SHA256_darwin_arm64="98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4"

GRYPE_VERSION="0.118.0"
GRYPE_SHA256_linux_amd64="1d444c5e7360471815f7158f71935fcecc68a3c417d85c7344f770854300bba2"
GRYPE_SHA256_linux_arm64="32aceeb8ee837244775fcb522372c8b3a47914986385f3148f4ee2c930482a84"
GRYPE_SHA256_darwin_arm64="938f050bb5076c8aa761867b39843abad2414dfe4cc82b7d36886e634f49c640"

fail() { echo "install-scanner: $1" >&2; exit 1; }

if [ "${1:-}" = "--print-versions" ]; then
  echo "osv-scanner ${OSV_VERSION}"
  echo "grype ${GRYPE_VERSION}"
  exit 0
fi

tool="${1:-}"
dest="${2:-}"
[ -n "$tool" ] && [ -n "$dest" ] || fail "usage: install-scanner.sh <osv-scanner|grype> <directory>"

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported operating system $(uname -s); no pinned checksum exists for it" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m); no pinned checksum exists for it" ;;
esac

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else fail "neither sha256sum nor shasum is available, so the download cannot be verified"
  fi
}

mkdir -p "$dest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "$tool" in
  osv-scanner)
    var="OSV_SHA256_${os}_${arch}"
    want="${!var:-}"
    [ -n "$want" ] || fail "no pinned osv-scanner checksum for ${os}_${arch}"
    url="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${os}_${arch}"
    curl -fsSL --retry 3 --retry-delay 5 -o "$work/osv-scanner" "$url" \
      || fail "could not download $url - a scan that cannot run is a failed check, never a clean one"
    got="$(sha256_of "$work/osv-scanner")"
    [ "$got" = "$want" ] || fail "osv-scanner checksum mismatch: expected $want, got $got"
    install -m 0755 "$work/osv-scanner" "$dest/osv-scanner"
    "$dest/osv-scanner" --version >/dev/null || fail "the installed osv-scanner does not run"
    echo "install-scanner: osv-scanner ${OSV_VERSION} verified and installed in $dest"
    ;;
  grype)
    var="GRYPE_SHA256_${os}_${arch}"
    want="${!var:-}"
    [ -n "$want" ] || fail "no pinned grype checksum for ${os}_${arch}"
    url="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${os}_${arch}.tar.gz"
    curl -fsSL --retry 3 --retry-delay 5 -o "$work/grype.tar.gz" "$url" \
      || fail "could not download $url - a scan that cannot run is a failed check, never a clean one"
    got="$(sha256_of "$work/grype.tar.gz")"
    [ "$got" = "$want" ] || fail "grype checksum mismatch: expected $want, got $got"
    tar -xzf "$work/grype.tar.gz" -C "$work" grype || fail "the grype archive does not contain the binary"
    install -m 0755 "$work/grype" "$dest/grype"
    "$dest/grype" version >/dev/null || fail "the installed grype does not run"
    echo "install-scanner: grype ${GRYPE_VERSION} verified and installed in $dest"
    ;;
  *) fail "unknown scanner '$tool'" ;;
esac
