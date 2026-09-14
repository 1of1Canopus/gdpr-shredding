#!/usr/bin/env bash
#
# Refuses a reference, anywhere a reader of this repository can reach it, to a document that
# was moved out of the public tree or to a machine-local absolute path.
#
#   tools/check-private-references.sh --tree               the working tree (git grep)
#   tools/check-private-references.sh --jars <module-dir>...  every jar in each module's target/
#   tools/check-private-references.sh --self-test          plants each mutation class, asserts red
#
# Exit 0: nothing found. Exit 1: a reference was found, or the caller asked for something the
# script cannot do (fail closed).
#
# History. This guard lived twice, inline, in two jobs of the CI workflow, with the pattern
# written out in both. It is here, once, so the two copies cannot drift; nothing else changed
# about it. The properties it has to keep, each earned by a finding:
#
#   * The pattern appears EXACTLY ONCE, on the definition line below.
#   * The pattern is SELF-NON-MATCHING: every alternative brackets one of its own characters
#     (or escapes a dot), so the definition line is text the pattern does not match. This
#     script is a file in the tree and --tree reads it like any other, with no exemption.
#   * There is NO content-marker exemption, and no file- or path-level exemption for this
#     script. An earlier version let any line claim exemption by carrying a fixed marker
#     string, so a forbidden reference carrying that same string passed unchanged.
#   * `git grep --text` on the tree: whether a file is "binary" is decided by .gitattributes,
#     which the same commit that adds a forbidden reference can also edit, and `git grep -I`
#     never matches a binary file. --text forces every path to be read as text.
#   * The machine-path half covers a developer laptop, a hosted Linux runner, the Linux
#     superuser home and a Windows drive-letter user path, not just one of them.
#   * The jar side loops over EVERY jar in a module's target/, the main jar included, not
#     only the sources and javadoc jars: the main jar is published too.
#   * Fail closed on an unverifiable scan: `git grep`, `grep` and `unzip` each have their own
#     exit code that does not mean "no hits", and an error there must refuse, not pass.
#
set -uo pipefail
# The scan is always rooted at this repository, EXCEPT when the self-test points it at a
# scratch repository it just built. That override exists so the self-test can exercise this
# script end to end (its real scan function, its real exit code) instead of re-implementing
# the scan next to it and proving only that a regex is a regex. With the RP-1 fix below, a
# `CHECK_PRIVATE_REFERENCES_ROOT` that is not itself a git work tree makes `--tree` refuse
# rather than report clean, so this override can only ever redirect the scan to another real
# git work tree - which is what makes it acceptable to leave in production code.
cd "${CHECK_PRIVATE_REFERENCES_ROOT:-$(dirname "$0")/..}"

# The one definition. Self-non-matching, no exemption anywhere. There is no path exemption
# (the former `internal/**` carve-out protected nothing: this repository has no `internal/`
# directory and by design never will, and the exemption had no self-test case covering it -
# see R-3 in the security review).
pattern='QUESTIONS\.md|STATUS\.md|SPEC\.md|LICENSING\.md|SHARED-CONVENTIONS\.md|AGENTS\.md|docs[/]plans|SECURITY[-]REVIEW|RELEASIN[G]|[/]Users[/]|[/]home[/][a-z]|[/]root[/]|[A-Z]:\\Users'

scan_tree() {
  local hits rc
  hits="$(git grep -n --text -E "$pattern")"
  rc=$?
  case "$rc" in
    0)
      echo "::error::found a reference to a moved-private document or a machine-local path:"
      printf '%s\n' "$hits"
      return 1
      ;;
    1)
      echo "check-private-references: tree clean"
      return 0
      ;;
    *)
      echo "::error::check-private-references: git grep exited $rc, refusing to call the tree clean (not a git repository, bad pathspec, or some other error)" >&2
      return 1
      ;;
  esac
}

# Recursive scan of an already-extracted directory (a jar's contents, or a scratch tree in
# the self-test). Plain grep, not git grep: there is no index here.
scan_dir() {
  local dir="$1" hits rc
  hits="$(grep -rnE "$pattern" "$dir" 2>/dev/null)"
  rc=$?
  case "$rc" in
    0) printf '%s\n' "$hits"; return 1 ;;
    1) return 0 ;;
    *) echo "::error::check-private-references: grep exited $rc scanning $dir, refusing to call it clean" >&2; return 1 ;;
  esac
}

scan_jars() {
  local status=0 extract_dir
  extract_dir="${RUNNER_TEMP:-$(mktemp -d)}/private-reference-jar-contents.$$"
  mkdir -p "$extract_dir"
  local module jar dest found_any=0
  for module in "$@"; do
    for jar in "$module"/target/*.jar; do
      [ -f "$jar" ] || continue
      found_any=1
      dest="$extract_dir/$(basename "$jar" .jar)"
      mkdir -p "$dest"
      if ! unzip -q -o "$jar" -d "$dest" 2>/dev/null; then
        echo "::error::check-private-references: cannot read $jar (unzip failed, refusing to call it clean)"
        status=1
        continue
      fi
      if ! scan_dir "$dest" > "$extract_dir/hits.txt"; then
        echo "::error::$jar contains a reference to a moved-private document or a machine-local path:"
        cat "$extract_dir/hits.txt"
        status=1
      fi
    done
  done
  if [ "$found_any" -eq 0 ]; then
    echo "check-private-references: no jar found under $* - build first" >&2
    rm -rf "$extract_dir"
    return 1
  fi
  rm -rf "$extract_dir"
  [ "$status" -eq 0 ] && echo "check-private-references: every built jar is clean"
  return "$status"
}

# ---------------------------------------------------------------------------------------
# --self-test: plants one mutation per class in a scratch git repository and asserts the
# guard goes RED on each, then asserts it is GREEN on the unmutated scratch tree. Every
# planted string is ASSEMBLED at run time from fragments, so this script's own source never
# contains a string its own pattern matches.
# ---------------------------------------------------------------------------------------
run_self_test() {
  local failures=0 work guard
  guard="$(pwd)/tools/check-private-references.sh"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN

  local q s u h r c marker
  q="QUESTION""S.md"                 # a moved-private document name
  s="SECURITY""-REVIEW-feat-x.md"    # another one, hyphen form
  u="/User""s/someone/Documents/Work/notes.txt"
  h="/hom""e/runner/work/gdpr-shredding/out.txt"
  r="/roo""t/build/out.txt"
  c="C:\\User""s\\someone\\build.log"
  marker="pattern-definition-line, exempt from the guard it defines"

  # One scratch repo per case: a mutation must be the only difference from a clean tree.
  _case() { # _case <name> <expected: red|green> <file> <content> [gitattributes line]
    local name="$1" expect="$2" file="$3" content="$4" attrs="${5:-}"
    local dir="$work/$name"
    mkdir -p "$dir"
    ( cd "$dir" && git init -q . && printf 'clean file, nothing to see\n' > ok.txt )
    printf '%s\n' "$content" > "$dir/$file"
    [ -n "$attrs" ] && printf '%s\n' "$attrs" > "$dir/.gitattributes"
    ( cd "$dir" && git add -A >/dev/null 2>&1 )
    # The real script, the real --tree path, the real exit code: 1 == red, 0 == green.
    local rc=0
    CHECK_PRIVATE_REFERENCES_ROOT="$dir" bash "$guard" --tree >/dev/null 2>&1 || rc=1
    if [ "$expect" = "red" ] && [ "$rc" -eq 1 ]; then
      echo "self-test OK    $name caught"
    elif [ "$expect" = "green" ] && [ "$rc" -eq 0 ]; then
      echo "self-test OK    $name not flagged"
    else
      echo "self-test FAIL  $name expected $expect, guard said $([ "$rc" -eq 1 ] && echo red || echo green)"
      failures=$((failures + 1))
    fi
  }

  _case "moved-private-document-name"      red   doc.md   "see $q for the open items"
  _case "moved-private-review-name"        red   doc.md   "see $s"
  _case "old-marker-appended-to-a-hit"     red   doc.md   "see $q   # $marker"
  _case "gitattributes-binary-hides-a-hit" red   doc.md   "see $q" "doc.md binary"
  _case "developer-laptop-path"            red   doc.md   "built from $u"
  _case "hosted-linux-runner-path"         red   doc.md   "built from $h"
  _case "linux-superuser-path"             red   doc.md   "built from $r"
  _case "windows-drive-letter-path"        red   doc.md   "built from $c"
  _case "clean-tree"                       green doc.md   "nothing forbidden in this line"

  # Negative control for the .gitattributes case: prove the mutation is caught BECAUSE of
  # --text. The same scratch tree scanned with `git grep -I` (the form this guard used to
  # have) must MISS it - otherwise the case above would pass for some unrelated reason and
  # the property "a .gitattributes line cannot hide a reference" would be untested.
  if ( cd "$work/gitattributes-binary-hides-a-hit" \
        && git grep -n -I -E "$pattern" >/dev/null 2>&1 ); then
    echo "self-test FAIL  negative control: git grep -I still matched, the case proves nothing"
    failures=$((failures + 1))
  else
    echo "self-test OK    negative control: git grep -I misses it, --text is what catches it"
  fi

  # The guard's own source must not be a hit: it is a tree file and --tree reads it with no
  # exemption, so a pattern that matched its own definition line would make the guard
  # permanently red on an unmutated checkout.
  if grep -nE "$pattern" "$guard" >/dev/null 2>&1; then
    echo "self-test FAIL  the pattern matches this script's own source (it must be self-non-matching)"
    grep -nE "$pattern" "$guard"
    failures=$((failures + 1))
  else
    echo "self-test OK    the pattern does not match this script's own source"
  fi

  # The pattern is defined exactly once: a second copy is how the two inline versions drifted.
  local defs
  defs="$(grep -c "^pattern=" "$guard")"
  if [ "$defs" -eq 1 ]; then
    echo "self-test OK    the pattern is defined exactly once"
  else
    echo "self-test FAIL  the pattern is defined $defs times, expected 1"
    failures=$((failures + 1))
  fi

  # RP-1: `git grep` failing outright (not a git repository) must refuse, not report clean.
  # A directory that is not a git work tree, holding a planted reference, must still go red.
  local nongit rc_nongit
  nongit="$work/non-git-directory-holding-a-reference"
  mkdir -p "$nongit"
  printf 'see %s and %s\n' "$q" "$u" > "$nongit/leak.md"
  rc_nongit=0
  CHECK_PRIVATE_REFERENCES_ROOT="$nongit" bash "$guard" --tree >/dev/null 2>&1 || rc_nongit=$?
  if [ "$rc_nongit" -eq 1 ]; then
    echo "self-test OK    non-git directory refused (git grep error not read as tree clean)"
  else
    echo "self-test FAIL  non-git directory: expected refusal (exit 1), guard exited $rc_nongit"
    failures=$((failures + 1))
  fi

  # RP-2: a jar `unzip` cannot read must refuse, not report every built jar clean.
  local jar_module rc_jar
  jar_module="$work/corrupt-jar-module"
  mkdir -p "$jar_module/target"
  printf 'not a zip file, but mentions %s\n' "$q" > "$jar_module/target/broken.jar"
  rc_jar=0
  bash "$guard" --jars "$jar_module" >/dev/null 2>&1 || rc_jar=$?
  if [ "$rc_jar" -eq 1 ]; then
    echo "self-test OK    corrupt jar refused (failed unzip not read as clean)"
  else
    echo "self-test FAIL  corrupt jar: expected refusal (exit 1), guard exited $rc_jar"
    failures=$((failures + 1))
  fi

  echo
  if [ "$failures" -eq 0 ]; then
    echo "check-private-references --self-test: all cases correct"
    return 0
  fi
  echo "check-private-references --self-test: $failures case(s) FAILED" >&2
  return 1
}

case "${1:-}" in
  --tree)      scan_tree ;;
  --jars)      shift; [ "$#" -gt 0 ] || { echo "usage: check-private-references.sh --jars <module-dir>..." >&2; exit 1; }; scan_jars "$@" ;;
  --self-test) run_self_test ;;
  *)
    echo "usage: check-private-references.sh --tree | --jars <module-dir>... | --self-test" >&2
    exit 1
    ;;
esac
