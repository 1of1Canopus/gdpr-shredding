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
#   * A jar member that is itself an archive (first bytes `PK\x03\x04`) is refused, not
#     read: its compressed bytes would hide any text in it (B-NG-6). Fail closed.
#   * The jar side reads every extracted file as text (`grep -a`), like the tree side. GNU
#     grep, without it, splits a binary file at NUL bytes, so a class-file constant becomes
#     the start of a "line" and `^` matches inside it.
#
# Agent first names (added after register rows B-DC-036, C-DC-1, D-DC-1: review documents in
# all three public repositories named the agents who wrote them; public text uses roles only).
# The second half of the pattern refuses the first names of the studio's agents. It is
# case-sensitive, so the lower-case words `cipher`, `thor`, `ra` never match. A name counts
# only as a whole word: the character before it must be whitespace, or not a letter, digit,
# `_` or control byte; the character after it must not be a letter, digit or `_`.
#   - A non-whitespace control byte before a name: in a class file every string constant
#     follows a two-byte length, and a length of 82 is the byte `R`. Measured on
#     stripe-einvoice-core 0.1.0: an 82-character constant starting with "a " read as the
#     short name, behind a high length byte of 0x00. Text never has such a byte there; tab,
#     form feed, vertical tab and carriage return are text and stay boundaries (B-NG-1).
#     The self-test case `jar-length-byte-before-a-string` holds this rule.
#   - The JDK cipher class: the twelfth name may follow `.` or `/` only when the segment
#     before it is `crypto` (`javax.crypto.C...` in source, `javax/crypto/C...` in a class
#     file). ERE has no look-behind, so it is written out by hand, one alternative per
#     letter of `crypto`. The other eleven names have no JDK or library class and get no
#     dot or slash exemption (B-NG-2).
#   - The security-probe suite: the required status check on `main` is named after the
#     reviewing agent ("C... probes"), and test classes are `C...Probe...Test`. The
#     identifier form fails the word rule by itself. The name followed by the exact word
#     " probes" is not refused, because renaming a required check is a ruleset change on
#     GitHub, not a change in this tree. "probe", "probed", "probe-verified" and every
#     other use of that name are refused (B-NG-3).
#   - The one lower-case form refused is an agent's address, `<name>@housedevinci...`,
#     as in a pasted sign-off trailer (B-NG-5). The project and security addresses pass.
# Names deliberately NOT in the pattern, measured with `git grep -n -w` on the three trees
# and on the published main and sources jars (2026-10-15):
#   - Max: `@Max` is a Bean Validation annotation in stripe-einvoice (9 hits), and "Max" is
#     an ordinary sentence start ("Max 72 chars"). That agent does not work in module repos.
#   - Red: "Red" opens sentences in test prose ("Red on the current text", agent-guard), and
#     red/green is the test vocabulary. That agent does not work in module repos either.
# Included although short or common, because each one was measured at zero hits outside the
# leaks themselves, and two of them did leak in possessive form in C-DC-1: `[R]a`,
# `[D]ollar`, `[B]rain`. (Names in this comment are bracketed like the pattern, so this
# script stays self-non-matching.)
#
# Letter case of the document names (B-NG-12). A private document copied out under a
# lower-case or mixed-case name (`q...s.md`, `Q...s.md`) passed. Each document name, and the
# plans folder, is now matched in any letter case, written one bracket per letter (ERE has
# no case-insensitive flag for one alternative). Two words stay upper case only: the bare
# review word and the bare release word. In lower case both are plain English ("releasing a
# version", "a security-review probe"): measured on the three trees (2026-10-17), they gave
# 11 lines that are not leaks, one of them in a published SQL resource. With the new
# pattern, measured the same day: 0 new hits in tree content, tree names, and the main,
# sources and javadoc jars of the three repositories.
#
# File names (B-NG-7, with B-NG-9, B-NG-10, B-NG-11, B-NG-13 from the design review). The
# content scan reads lines inside files; it never read a file's own name. So a file AT a
# refused path passed while its text was clean: `QUESTIONS[.]md` at the root, a directory
# `docs[/]plans`, a jar entry named after an agent. Both scans now read names as well:
#   N0  `export LC_ALL=C` before any grep, and `grep -a` on name lists. In a UTF-8 locale a
#       byte that is not valid UTF-8 never matches a bracket expression, so such a byte
#       before an agent name hid it from the word rule, in names and in content (B-NG-9).
#       The self-test refuses to run on a grep that is neither GNU nor BSD grep (ugrep
#       behaves differently): run it with /usr/bin/grep or GNU grep first on PATH.
#   N1  Names are checked with the SAME `pattern` as content. There is no second pattern.
#   N2  One tree path shape is admitted, `review_doc_shape` below: a security review
#       document at the root of `docs/`, lower-case slug, `.md`. Anchored at both ends, and
#       the slug is scanned again with `pattern`. The review documents are public by design
#       (each pull request's review ships as evidence). This admits the NAME only: the text
#       of those files is scanned like any other file, with no exemption. Tree paths only;
#       never applied to content, never to jar members.
#   N3  Every refusal prints one fixed reason word: `content`, `name`, `control byte`,
#       `symlink`, `gitlink`, `dot segment`, `duplicate member`, `nested archive`,
#       `cannot list`, `listing mismatch`. The self-test asserts the word, not only the
#       exit code, so a case that is red for a second reason cannot hide a dead check.
#   N4  Every listing (`git ls-files -s -z`, `unzip -Z1`, `unzip -Zt`) is written to a file
#       in the scratch folder by `listing`, and its exit code is checked before the file is
#       read. No listing is read through a pipe. The scratch folder goes on any exit.
#   N5  Tree paths are read NUL-separated (`-z`) and refused on a control byte BEFORE any
#       path becomes a line. Without `-z`, git quotes such a path ("a\nb"), so the raw
#       name is never seen; split into lines first, one path would become two clean ones.
#   N6  A refused name is printed after the refusal, every byte outside printable ASCII as
#       `\xHH` (B-NG-13). A raw newline in a path cannot start an output line that the CI
#       runner reads as a workflow command. Content hits are printed the same way, line by
#       line (`escape_lines`, B-NG-23): a hit line holds no newline, but it can hold a
#       carriage return, and the runner ends a line there too, so `\r::warning::` in a hit
#       would start a command. Every hit line, tree and jar, also starts with the fixed
#       prefix `hit: ` (B-NG-30), so a file path such as `::stop-commands::tok` cannot be the
#       first bytes of a line.
#   N7  Extraction is checked one to one, after unzip and before the content scan (B-NG-19,
#       B-NG-20, B-NG-21). unzip does not write every listed member as one regular file: it
#       folds `./a.txt` onto `a.txt` (the later member overwrites the earlier one), it drops
#       the data of a directory entry, and it makes a symlink whose stored target the
#       recursive grep never reads. So: any symlink in the extraction folder is refused
#       (`symlink`); then the number of regular files must equal the number of listed
#       members that are not directories, and their total size must equal the `bytes
#       uncompressed` figure of `unzip -Zt` (`listing mismatch`). Any rewrite or disk
#       collision loses a file or bytes, so this closes the class, not only the spellings
#       below. A jar that fails N7 is not content-scanned: its extraction proves nothing.
#       Before extraction, empty and `.` segments (`./`, `//`, `/./`, a trailing `/.`) are
#       refused by name (`dot segment`), so the common spellings get a precise reason.
#       Measured on the 12 published jars of the three modules (2026-10-17): files and
#       bytes equal on every one. The "listed, not extracted" refusal stays: Apple's unzip
#       lists a non-ASCII member name as `?`, so the name is not found on disk although
#       the counts agree; the self-test reaches it by calling `check_extracted_members`.
#   Tree: symlinks (mode 120000, the target is a path string) and gitlinks (160000) are
#       refused. Jars, before extraction: `unzip -Z1` prints a control byte as `^J`, `^I`,
#       so any `^` in a member name is refused (B-NG-11), and the -Z1 line count must equal
#       the entry count of `unzip -Zt` (`jar_counts_match`; Info-ZIP escapes every control
#       byte, so on that build the counts always agree, and the check guards against a
#       build that prints raw names); an empty jar is refused. Members with a `..` segment,
#       a leading `/` or a `\` are refused (unzip rewrites them on extraction). Two members
#       with the same name, or names equal after case folding, are refused (B-NG-10):
#       extraction keeps one, and the content of the other was never scanned. The jar's own
#       file name is scanned too. Member names get no shape admission.
#   Measured with the scan's own call, `git ls-files -s -z`, LC_ALL=C (2026-10-16):
#   agent-guard 210 entries, gdpr-shredding 457, stripe-einvoice 311; no control byte, no
#   symlink, no gitlink; 5, 10 and 13 name hits, every one of them a review document of the
#   admitted shape.
#   Not here: gzip members in jars and a nested zip behind a prefix byte (B-NG-14,
#   B-NG-22, own change); look-alike Unicode letters (B-NG-28, design stop).
#
set -uo pipefail
# N0: the C locale for every grep, git grep, sort and case pattern below. Exported before
# the first of them, and set here, not left to the caller.
export LC_ALL=C
# The scan is always rooted at this repository, EXCEPT when the self-test points it at a
# scratch repository it just built. That override exists so the self-test can exercise this
# script end to end (its real scan function, its real exit code) instead of re-implementing
# the scan next to it and proving only that a regex is a regex. With the RP-1 fix below, a
# `CHECK_PRIVATE_REFERENCES_ROOT` that is not itself a git work tree makes `--tree` refuse
# rather than report clean, so this override can only ever redirect the scan to another real
# git work tree - which is what makes it acceptable to leave in production code.
cd "${CHECK_PRIVATE_REFERENCES_ROOT:-$(dirname "$0")/..}" || exit 1

# One scratch folder per run; removed on every exit, failure included (N4).
scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/check-private-references.XXXXXX")" || {
  echo "::error::check-private-references: cannot list: no scratch folder" >&2; exit 1; }
trap 'rm -rf "$scratch"' EXIT

# The one definition. Self-non-matching, no exemption anywhere. There is no path exemption
# (the former `internal/**` carve-out protected nothing: this repository has no `internal/`
# directory and by design never will, and the exemption had no self-test case covering it -
# see R-3 in the security review).
pattern='[Qq][Uu][Ee][Ss][Tt][Ii][Oo][Nn][Ss][.][Mm][Dd]|[Ss][Tt][Aa][Tt][Uu][Ss][.][Mm][Dd]|[Ss][Pp][Ee][Cc][.][Mm][Dd]|[Ll][Ii][Cc][Ee][Nn][Ss][Ii][Nn][Gg][.][Mm][Dd]|[Ss][Hh][Aa][Rr][Ee][Dd]-[Cc][Oo][Nn][Vv][Ee][Nn][Tt][Ii][Oo][Nn][Ss][.][Mm][Dd]|[Aa][Gg][Ee][Nn][Tt][Ss][.][Mm][Dd]|[Dd][Oo][Cc][Ss][/][Pp][Ll][Aa][Nn][Ss]|[Rr][Ee][Ll][Ee][Aa][Ss][Ii][Nn][Gg][.][Mm][Dd]|SECURITY[-]REVIEW|RELEASIN[G]|[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy][-][Rr][Ee][Vv][Ii][Ee][Ww][.-]|[Rr][Ee][Ll][Ee][Aa][Ss][Ii][Nn][Gg][.]|[/]Users[/]|[/]home[/][a-z]|[/]root[/]|[A-Z]:\\Users|(^|[^[:alnum:][:cntrl:]_]|[[:space:]])([T]hor|[I]sis|[R]a|[A]thena|[O]din|[H]ermes|[H]arvey|[D]ollar|[B]rain|[B]rainus|[L]oki)([^[:alnum:]_]|$)|(^|[^[:alnum:][:cntrl:]_./]|[[:space:]]|(^|[^o]|(^|[^t])o|(^|[^p])to|(^|[^y])pto|(^|[^r])ypto|(^|[^c])rypto)[./])[C]ipher($|[^[:alnum:]_ ]| $| [^p]| p$| p[^r]| pr$| pr[^o]| pro$| pro[^b]| prob$| prob[^e]| probe$| probe[^s]| probes[[:alnum:]_])|(^|[^[:alnum:]._+-])([t]hor|[i]sis|[r]a|[a]thena|[o]din|[h]ermes|[h]arvey|[d]ollar|[b]rain|[b]rainus|[l]oki|[c]ipher)@housedevinci'

# Rule N2, defined exactly once: the one tree path shape whose NAME may carry a hit. Tree
# paths only; the slug is scanned again with `pattern` (admitted_review_doc).
review_doc_shape='^docs/SECURITY[-]REVIEW-[a-z0-9]+([.-][a-z0-9]+)*[.]md$'

# N6: every byte outside printable ASCII, and the backslash, printed as \xHH.
escape_bytes() {
  printf '%s' "$1" | od -An -v -tu1 | awk '{
    for (i = 1; i <= NF; i++) {
      b = $i + 0
      if (b >= 32 && b < 127 && b != 92) printf "%c", b; else printf "\\x%02X", b
    }
  }'
}

# N6, B-NG-23, B-NG-30: the same escape for a stream of lines; only the newline stays a
# newline. Every non-empty line starts with the fixed prefix `hit: `, so a hit line can never
# start with the file path it carries: a tracked file named `::stop-commands::tok` would
# otherwise print a line the runner reads as a workflow command.
escape_lines() {
  od -An -v -tu1 | awk 'BEGIN { start = 1 } {
    for (i = 1; i <= NF; i++) {
      b = $i + 0
      if (b == 10) { printf "\n"; start = 1; continue }
      if (start) { printf "hit: "; start = 0 }
      if (b >= 32 && b < 127 && b != 92) printf "%c", b
      else printf "\\x%02X", b
    }
  }'
}

refuse() { # refuse <reason word> <subject>; the subject is printed escaped (N3, N6)
  printf '::error::check-private-references: %s: %s\n' "$1" "$(escape_bytes "$2")"
}

# N4: run one listing command into a file and keep its exit code. Called for every listing,
# so the self-test can call it on a missing jar without a stub of the tool.
listing() { # listing <subject> <out-file> <command...>
  local subject="$1" out="$2"
  shift 2
  if "$@" > "$out" 2>/dev/null; then
    return 0
  fi
  refuse "cannot list" "$subject"
  return 1
}

# Grep a file of names, one per line, with `pattern`. Exit 0 hits (in $2), 1 clean,
# 2 grep failed: never read as clean.
grep_names() { # grep_names <names-file> <hits-file>
  grep -a -E "$pattern" "$1" > "$2" 2>/dev/null
  case "$?" in
    0) return 0 ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
}

# Rule N2. Tree paths only. Exit 0 admits the name, anything else refuses it.
admitted_review_doc() { # admitted_review_doc <path>
  local slug rc
  [[ "$1" =~ $review_doc_shape ]] || return 1
  # The slug is what follows the last `/SECURITY[-]REVIEW-`. The anchors of the shape, not this
  # cut, decide where the document may sit (mutation M2 drops `^` and must go red).
  slug="${1##*/SECURITY[-]REVIEW-}"
  slug="${slug%.md}"
  printf '%s\n' "$slug" | grep -a -q -E "$pattern"
  rc=$?
  [ "$rc" -eq 1 ]
}

scan_tree_names() {
  local lst="$scratch/tree.lst" names="$scratch/tree-names.lst" hits="$scratch/tree-name-hits.lst"
  local status=0 rec meta path rc
  listing "git ls-files -s -z" "$lst" git ls-files -s -z || return 1
  : > "$names"
  # N5: split on NUL only, and refuse a control byte in a path HERE, before the path is
  # written out as a line. The order matters: a newline inside a path, turned into a line
  # first, would make one hit into two clean lines.
  while IFS= read -r -d '' rec || [ -n "$rec" ]; do
    meta="${rec%%$'\t'*}"
    path="${rec#*$'\t'}"
    if [ "$meta" = "$rec" ]; then
      refuse "cannot list" "$rec"; status=1; continue
    fi
    case "$path" in
      *[[:cntrl:]]*) refuse "control byte" "$path"; status=1; continue ;;
    esac
    case "$meta" in
      "120000 "*) refuse "symlink" "$path"; status=1; continue ;;
      "160000 "*) refuse "gitlink" "$path"; status=1; continue ;;
    esac
    printf '%s\n' "$path" >> "$names"
  done < "$lst"
  grep_names "$names" "$hits"
  rc=$?
  case "$rc" in
    0)
      while IFS= read -r path; do
        admitted_review_doc "$path" && continue
        refuse "name" "$path"; status=1
      done < "$hits"
      ;;
    1) ;;
    *) refuse "cannot list" "grep on the tree names"; status=1 ;;
  esac
  return "$status"
}

scan_tree_content() {
  local hits rc
  hits="$(git grep -n --text -E "$pattern")"
  rc=$?
  case "$rc" in
    0)
      echo "::error::check-private-references: content: found a reference to a moved-private document, a machine-local path or an agent first name:"
      printf '%s\n' "$hits" | escape_lines
      return 1
      ;;
    1)
      return 0
      ;;
    *)
      echo "::error::check-private-references: cannot list: git grep exited $rc, refusing to call the tree clean (not a git repository, bad pathspec, or some other error)" >&2
      return 1
      ;;
  esac
}

scan_tree() {
  local status=0
  scan_tree_names || status=1
  scan_tree_content || status=1
  [ "$status" -eq 0 ] && echo "check-private-references: tree clean (file content and file names)"
  return "$status"
}

# Recursive scan of an already-extracted directory (a jar's contents, or a scratch tree in
# the self-test). Plain grep, not git grep: there is no index here.
scan_dir() {
  local dir="$1" hits rc
  hits="$(grep -rnaE "$pattern" "$dir" 2>/dev/null)"
  rc=$?
  case "$rc" in
    0) printf '%s\n' "$hits"; return 1 ;;
    1) return 0 ;;
    *) echo "::error::check-private-references: cannot list: grep exited $rc scanning $dir, refusing to call it clean" >&2; return 1 ;;
  esac
}

# B-NG-11: the -Z1 name list must have exactly as many lines as `unzip -Zt` has entries.
# The -Zt line is parsed strictly: `1 file, ...` or `N files, ...`, nothing else. An empty
# jar ("Empty zipfile.") or a line that does not parse is refused.
# The `unzip -Zt` total line, defined once: entry count, then bytes uncompressed.
zt_line_re='^([0-9]+) files?, ([0-9]+) bytes uncompressed, [0-9]+ bytes compressed: *-?[0-9]+[.][0-9]%$'
jar_counts_match() { # jar_counts_match <list-file> <total-file>
  local re="$zt_line_re"
  local line n lines
  if [ ! -f "$1" ] || [ ! -f "$2" ] || [ "$(wc -l < "$2" | tr -d ' ')" != "1" ]; then
    refuse "cannot list" "entry count of $1"; return 1
  fi
  IFS= read -r line < "$2"
  if ! [[ "$line" =~ $re ]]; then
    refuse "cannot list" "entry count line: $line"; return 1
  fi
  n="${BASH_REMATCH[1]}"
  if [ "$n" -lt 1 ]; then
    refuse "cannot list" "empty archive $1"; return 1
  fi
  lines="$(wc -l < "$1" | tr -d ' ')"
  if [ "$lines" != "$n" ]; then
    refuse "listing mismatch" "$lines names listed, $n entries counted"; return 1
  fi
  return 0
}

# Everything decided from the central directory listing, before extraction. Exit 0: the
# jar may be extracted (name hits were refused but do not stop the content scan). Exit 1:
# the listing itself is refused and the jar must NOT be extracted.
check_jar_listing() { # check_jar_listing <jar> <list-file> <work-dir>
  local jar="$1" lst="$2" w="$3" name base status=0 rc
  # Control bytes, the `^` that -Z1 prints in their place, and paths unzip would rewrite.
  while IFS= read -r name || [ -n "$name" ]; do
    case "$name" in
      *[[:cntrl:]]*|*'^'*) refuse "control byte" "$jar!$name"; status=1; continue ;;
    esac
    case "$name" in
      /*|*'\'*|..|../*|*/..|*/../*|.|./*|*/.|*/./*|*//*|'') refuse "dot segment" "$jar!$name"; status=1; continue ;;
    esac
  done < "$lst"
  # B-NG-10: exact duplicates, then names equal after case folding among the distinct ones
  # (so each check has its own case). Each step writes a file and is checked.
  if ! sort "$lst" > "$w/sorted" || ! uniq -d "$w/sorted" > "$w/dup" \
     || ! sort -u "$lst" > "$w/distinct" || ! sort -f "$w/distinct" > "$w/folded" \
     || ! uniq -di "$w/folded" > "$w/dupf"; then
    refuse "cannot list" "duplicate check of $jar"; return 1
  fi
  while IFS= read -r name; do refuse "duplicate member" "$jar!$name"; status=1; done < "$w/dup"
  while IFS= read -r name; do refuse "duplicate member" "$jar!$name (case-fold)"; status=1; done < "$w/dupf"
  [ "$status" -eq 0 ] || return 1
  # Names: the jar's own file name, then every member, with `pattern`. No shape admission.
  base="$(basename "$jar")"
  printf '%s\n' "$base" > "$w/base"
  case "$base" in *[[:cntrl:]]*) refuse "control byte" "$jar"; return 1 ;; esac
  grep_names "$w/base" "$w/base-hits"
  rc=$?
  case "$rc" in
    0) refuse "name" "$jar" ;;
    1) ;;
    *) refuse "cannot list" "grep on the name of $jar"; return 1 ;;
  esac
  grep_names "$lst" "$w/name-hits"
  rc=$?
  case "$rc" in
    0) while IFS= read -r name; do refuse "name" "$jar!$name"; done < "$w/name-hits" ;;
    1) ;;
    *) refuse "cannot list" "grep on the member names of $jar"; return 1 ;;
  esac
  return 0
}

# N7: after extraction, before the content scan. Exit 0: every listed byte is in a regular
# file the content scan will read. Exit 1: refused, do not trust the extraction.
extracted_matches_listing() { # extracted_matches_listing <jar> <list-file> <total-file> <dest>
  local jar="$1" lst="$2" tot="$3" dest="$4" f name line status=0
  local want_files=0 want_bytes have_files=0 have_bytes
  listing "$jar (symlinks in the extraction)" "$dest.links" find "$dest" -type l -print0 || return 1
  while IFS= read -r -d '' f; do
    refuse "symlink" "$jar!${f#"$dest"/}"; status=1
  done < "$dest.links"
  [ "$status" -eq 0 ] || return 1
  IFS= read -r line < "$tot"
  if ! [[ "$line" =~ $zt_line_re ]]; then
    refuse "cannot list" "entry count line: $line"; return 1
  fi
  want_bytes="${BASH_REMATCH[2]}"
  while IFS= read -r name || [ -n "$name" ]; do
    case "$name" in */) ;; *) want_files=$((want_files + 1)) ;; esac
  done < "$lst"
  listing "$jar (files in the extraction)" "$dest.files" find "$dest" -type f -print0 || return 1
  while IFS= read -r -d '' f; do have_files=$((have_files + 1)); done < "$dest.files"
  listing "$jar (bytes in the extraction)" "$dest.bytes" \
    bash -o pipefail -c 'find "$1" -type f -exec cat {} + | wc -c' _ "$dest" || return 1
  have_bytes="$(tr -d ' \t\n' < "$dest.bytes")"
  if [ "$have_files" != "$want_files" ] || [ "$have_bytes" != "$want_bytes" ]; then
    refuse "listing mismatch" "$jar: $want_files files and $want_bytes bytes listed, $have_files files and $have_bytes bytes extracted"
    return 1
  fi
  return 0
}

# B-NG-6: a member that is itself a zip archive is compressed bytes to grep, so any text
# inside it is unverifiable. Refuse it rather than call it clean. The members come from the
# same -Z1 list as the names, not from a second listing tool.
check_extracted_members() { # check_extracted_members <jar> <list-file> <dest>
  local jar="$1" lst="$2" dest="$3" name magic status=0
  while IFS= read -r name; do
    case "$name" in */) continue ;; esac
    if [ ! -f "$dest/$name" ]; then
      refuse "cannot list" "$jar!$name (listed, not extracted)"; status=1; continue
    fi
    magic="$(od -An -N4 -tx1 "$dest/$name" 2>/dev/null | tr -d ' \n')"
    if [ "$magic" = "504b0304" ]; then
      refuse "nested archive" "$jar!$name (not scanned, refusing to call it clean)"
      status=1
    fi
  done < "$lst"
  return "$status"
}

scan_jars() {
  local status=0 module jar dest w lst tot found_any=0 i=0 out rc
  for module in "$@"; do
    for jar in "$module"/target/*.jar; do
      [ -f "$jar" ] || continue
      found_any=1
      i=$((i + 1))
      w="$scratch/jar-$i"
      dest="$w/contents"
      lst="$w/names.lst"
      tot="$w/total.lst"
      mkdir -p "$dest"
      listing "$jar" "$lst" unzip -Z1 "$jar" || { status=1; continue; }
      listing "$jar" "$tot" unzip -Zt "$jar" || { status=1; continue; }
      jar_counts_match "$lst" "$tot" || { status=1; continue; }
      out="$w/listing-refusals"
      check_jar_listing "$jar" "$lst" "$w" > "$out"
      rc=$?
      cat "$out"
      [ -s "$out" ] && status=1
      [ "$rc" -eq 0 ] || { status=1; continue; }
      if ! unzip -q -o "$jar" -d "$dest" 2>/dev/null; then
        refuse "cannot list" "$jar (unzip could not extract it)"
        status=1
        continue
      fi
      extracted_matches_listing "$jar" "$lst" "$tot" "$dest" || { status=1; continue; }
      check_extracted_members "$jar" "$lst" "$dest" || status=1
      if ! scan_dir "$dest" > "$w/hits.txt"; then
        echo "::error::check-private-references: content: $(escape_bytes "$jar") contains a reference to a moved-private document, a machine-local path or an agent first name:"
        escape_lines < "$w/hits.txt"
        status=1
      fi
    done
  done
  if [ "$found_any" -eq 0 ]; then
    echo "check-private-references: no jar found under $* - build first" >&2
    return 1
  fi
  [ "$status" -eq 0 ] && echo "check-private-references: every built jar is clean (content and names)"
  return "$status"
}

# ---------------------------------------------------------------------------------------
# --self-test: plants one mutation per class in a scratch git repository and asserts the
# guard goes RED on each, with its reason word, then asserts it is GREEN on the clean
# cases. Every planted string is ASSEMBLED at run time from fragments, so this script's own
# source never contains a string its own pattern matches.
# ---------------------------------------------------------------------------------------
run_self_test() {
  local failures=0 work guard utf8 v
  guard="$(pwd)/tools/check-private-references.sh"
  work="$scratch/self-test"
  mkdir -p "$work"

  # N0: ugrep (and any other grep) reads bytes differently; refuse rather than prove nothing.
  v="$(grep --version 2>/dev/null | head -n 1)"
  case "$v" in
    "grep (GNU grep)"*|*"BSD grep"*) ;;
    *)
      echo "check-private-references --self-test: refusing to run: the grep on PATH is not GNU grep or BSD grep ($v); run with /usr/bin/grep or GNU grep first on PATH" >&2
      return 1
      ;;
  esac
  # Every case runs the guard in a UTF-8 locale, so the guard's own `export LC_ALL=C` is
  # what makes the non-UTF-8 byte cases red, not the caller's environment.
  utf8=""
  locale -a > "$work/locales" 2>/dev/null
  for v in C.UTF-8 C.utf8 en_US.UTF-8 en_US.utf8; do
    if grep -qx "$v" "$work/locales"; then utf8="$v"; break; fi
  done
  if [ -z "$utf8" ]; then
    echo "self-test FAIL  no UTF-8 locale on this machine, cannot prove the C locale rule"
    failures=$((failures + 1))
    utf8=C
  fi

  local q s u h r c marker
  q="QUESTION""S.md"                 # a moved-private document name
  s="SECURITY""-REVIEW-feat-x.md"    # another one, hyphen form
  u="/User""s/someone/Documents/Work/notes.txt"
  h="/hom""e/runner/work/gdpr-shredding/out.txt"
  r="/roo""t/build/out.txt"
  c="C:\\User""s\\someone\\build.log"
  marker="pattern-definition-line, exempt from the guard it defines"

  # _verdict <name> <expect: green | red:<reason word>> <exit code> <output file>
  # Red needs exit 1 AND the reason word in the output (N3).
  _verdict() {
    local name="$1" expect="$2" rc="$3" out="$4" reason
    if [ "$expect" = "green" ]; then
      if [ "$rc" -eq 0 ]; then
        echo "self-test OK    $name not flagged"; return 0
      fi
      echo "self-test FAIL  $name expected green, guard said red"
    else
      reason="${expect#red:}"
      if [ "$rc" -eq 1 ] && grep -aqF "check-private-references: $reason:" "$out"; then
        echo "self-test OK    $name caught ($reason)"; return 0
      fi
      if [ "$rc" -eq 1 ]; then
        echo "self-test FAIL  $name red, but not for the reason '$reason'"
      else
        echo "self-test FAIL  $name expected red ($reason), guard said green"
      fi
    fi
    failures=$((failures + 1))
    return 1
  }

  _new_repo() { # _new_repo <dir>: a scratch repository with one clean tracked file
    mkdir -p "$1"
    ( cd "$1" && git init -q . && printf 'clean file, nothing to see\n' > ok.txt && git add ok.txt )
  }

  _run_tree() { # _run_tree <dir> <output file>; prints nothing, returns 1 for red
    local rc=0
    CHECK_PRIVATE_REFERENCES_ROOT="$1" LC_ALL="$utf8" bash "$guard" --tree > "$2" 2>&1 || rc=1
    return "$rc"
  }

  # One scratch repo per case: a mutation must be the only difference from a clean tree.
  _case() { # _case <name> <expect> <file> <content> [gitattributes line]
    local name="$1" expect="$2" file="$3" content="$4" attrs="${5:-}"
    local dir="$work/$name" rc=0
    _new_repo "$dir"
    mkdir -p "$(dirname "$dir/$file")"
    printf '%s\n' "$content" > "$dir/$file"
    [ -n "$attrs" ] && printf '%s\n' "$attrs" > "$dir/.gitattributes"
    ( cd "$dir" && git add -A >/dev/null 2>&1 )
    # The real script, the real --tree path, the real exit code: 1 == red, 0 == green.
    _run_tree "$dir" "$dir.out" || rc=1
    _verdict "$name" "$expect" "$rc" "$dir.out"
  }

  # Name cases. Each path is put straight into the index with a clean blob, never written
  # to disk: macOS refuses some of these bytes, and a newline in a file name is hostile to
  # every tool. So the case runs the same on a laptop and on a Linux runner.
  _name_case() { # _name_case <name> <expect> <mode> <path>...
    local name="$1" expect="$2" mode="$3" dir="$work/$1" rc=0 blob p
    shift 3
    _new_repo "$dir"
    blob="$( cd "$dir" && printf 'clean\n' | git hash-object -w --stdin )"
    for p in "$@"; do
      ( cd "$dir" && git update-index --add --cacheinfo "$mode,$blob,$p" ) || {
        echo "self-test FAIL  $name: git refused the index entry"; failures=$((failures + 1)); return; }
    done
    _run_tree "$dir" "$dir.out" || rc=1
    _verdict "$name" "$expect" "$rc" "$dir.out"
  }

  _case "moved-private-document-name"      red:content   doc.md   "see $q for the open items"
  _case "moved-private-review-name"        red:content   doc.md   "see $s"
  _case "old-marker-appended-to-a-hit"     red:content   doc.md   "see $q   # $marker"
  _case "gitattributes-binary-hides-a-hit" red:content   doc.md   "see $q" "doc.md binary"
  _case "developer-laptop-path"            red:content   doc.md   "built from $u"
  _case "hosted-linux-runner-path"         red:content   doc.md   "built from $h"
  _case "linux-superuser-path"             red:content   doc.md   "built from $r"
  _case "windows-drive-letter-path"        red:content   doc.md   "built from $c"
  _case "clean-tree"                       green         doc.md   "nothing forbidden in this line"

  # Agent first names. Each planted name is assembled from two fragments, like the strings
  # above. Every alternative gets its own red case, so breaking any one of them turns this
  # self-test red; the green cases pin the words the pattern must leave alone.
  # Cases are numbered, not named after the planted name: this output is public CI log text.
  local cr th n i=0
  cr="Ci""pher"
  th="Th""or"
  for n in "$th" "Is""is" "R""a" "Ath""ena" "Od""in" "Her""mes" "Har""vey" "Dol""lar" \
           "Br""ain" "Br""ainus" "Lo""ki" "$cr"; do
    i=$((i + 1))
    _case "agent-name-$i"                  red:content   doc.md   "verified by $n's numbers"
  done
  _case "agent-name-reviewed-by"           red:content   doc.md   "reviewed by $cr"
  _case "agent-name-at-line-start"         red:content   doc.md   "$th writes the design page"
  _case "agent-name-in-parentheses"        red:content   doc.md   "probes ($cr, 2026-10-11)"
  _case "agent-name-end-of-sentence"       red:content   doc.md   "the second pass by $cr."
  _case "agent-name-markdown-bold"         red:content   doc.md   "**$cr**: two findings"
  _case "agent-name-at-end-of-line"        red:content   doc.md   "checks green (Build & test, $cr"
  _case "agent-name-before-findings"       red:content   doc.md   "Module B, $cr findings J1 and K1"
  _case "lower-case-crypto-word"           green         doc.md   "a TLS cipher suite and a cipher mode"
  _case "word-that-starts-with-a-name"     green         doc.md   "Maximum length, ${th}ough review, Rate limit, Brainstorm"
  _case "excluded-annotation"              green         doc.md   "@Max(32) and Red on the current text"
  _case "required-check-name"              green         doc.md   "the $cr probes job and the $cr probes check"
  # B-NG-1: whitespace control bytes are text, so they are boundaries.
  _case "agent-name-after-tab"             red:content   doc.md   "$(printf '\t')$th wrote this"
  _case "agent-name-after-form-feed"       red:content   doc.md   "$(printf '\f')$th wrote this"
  _case "agent-name-after-vertical-tab"    red:content   doc.md   "$(printf '\v')$th wrote this"
  _case "agent-name-after-carriage-return" red:content   doc.md   "x$(printf '\r')$th wrote this"
  # B-NG-9: a byte that is not valid UTF-8 before a name is a boundary (C locale).
  _case "agent-name-after-a-non-utf8-byte" red:content   doc.md   "$(printf '\377')$th wrote this"
  # B-NG-2: only the JDK class (after crypto. or crypto/) may follow a dot or a slash.
  _case "agent-name-after-slash"           red:content   doc.md   "see docs/$th for the design"
  _case "agent-name-after-root-slash"      red:content   doc.md   "see /$th"
  _case "agent-name-after-dot"             red:content   doc.md   "v1.$th wrote it"
  _case "agent-name-in-a-url"              red:content   doc.md   "https://example.org/reviews/$th"
  _case "short-agent-name-after-e-g"       red:content   doc.md   "e.g.R""a"
  _case "check-name-after-slash"           red:content   doc.md   "see docs/$cr"
  _case "check-name-after-other-package"   red:content   doc.md   "javax.krypto.$cr"
  # B-NG-3: the carve-out is the exact word "probes", nothing else.
  _case "check-name-singular-probe"        red:content   doc.md   "the $cr probe found it"
  _case "check-name-probed"                red:content   doc.md   "$cr probed the branch"
  _case "check-name-probe-verified"        red:content   doc.md   "$cr probe-verified, no findings"
  _case "check-name-probes-prefix"         red:content   doc.md   "$cr probesuite ran"
  # B-NG-5: an agent's address in lower case; the project addresses stay clean.
  _case "agent-address-sign-off"           red:content   doc.md   "Signed-off-by: th""or <th""or@housedevinci.com>"
  _case "agent-address-short-name"         red:content   doc.md   "ask r""a@housedevinci.com"
  _case "project-addresses"                green         doc.md   "security@housedevinci.com and hello@housedevinci.com"
  _case "probe-class-identifier"           green         doc.md   "class ${cr}ProbeJdbcTest"
  _case "jdk-class-qualified-in-source"    green         doc.md   "javax.crypto.$cr c = javax.crypto.$cr.getInstance(x);"
  _case "jdk-class-in-a-class-file"        green         doc.md   "(Ljava/lang/String;)Ljavax/crypto/$cr;"
  # B-NG-12: the moved-private document names in any letter case (numbered, assembled).
  local dn j=0
  for dn in "question""s.md" "Question""s.md" "QUESTION""S.MD" "statu""s.md" "spe""c.md" \
            "licensin""g.md" "shared-convention""s.md" "agent""s.md" "doc""s/Plans" \
            "releasin""g.md" "Releasin""g.MD"; do
    j=$((j + 1))
    _case "private-document-any-case-$j"   red:content   doc.md   "see $dn for the details"
  done
  # B-NG-26: the upper-case originals stay refused (a pattern narrowed to lower case must go red).
  j=0
  for dn in "STATU""S.MD" "SPE""C.MD" "LICENSIN""G.MD" "SHARED-CONVENTION""S.MD" "AGENT""S.MD"; do
    j=$((j + 1))
    _case "private-document-upper-case-$j" red:content   doc.md   "see $dn for the details"
  done
  # B-NG-25: the review word and the release word as file names, any case.
  _case "review-word-lower-case-dash-in-content" red:content doc.md "see securit""y-review.md"
  _case "release-word-lower-case-dot-in-content" red:content doc.md "see Releasin""g.txt"
  _case "plain-words-near-document-names"  green         doc.md   "releasing a version, a security-review probe, the status of the spec"

  # B-NG-7: file names in the tree. `sr` is a review document name in the admitted form;
  # each red case moves it out of that one shape by one step.
  local sr pl nl tb
  nl=$'\n'
  tb=$'\t'
  sr="SECURITY""-REVIEW-a"
  pl="docs""/plans"
  _name_case "name-moved-private-document-at-root" red:name       100644 "$q"
  _name_case "name-private-plans-folder"           red:name       100644 "$pl/a.md"
  _name_case "name-agent-in-a-file-name"           red:name       100644 "docs/review-by-$th.md"
  _name_case "name-agent-as-a-folder"              red:name       100644 "$th/notes.md"
  _name_case "name-agent-after-a-non-utf8-byte"    red:name       100644 "x/$(printf '\377')$th.md"
  _name_case "name-review-doc-in-a-sub-folder"     red:name       100644 "sub/docs/$sr.md"
  _name_case "name-review-doc-below-docs"          red:name       100644 "docs/sub/$sr.md"
  _name_case "name-review-doc-at-root"             red:name       100644 "$sr.md"
  _name_case "name-lower-case-private-document"    red:name       100644 "notes/question""s.md"
  _name_case "name-review-doc-slug-rescan"         red:name       100644 "docs/SECURITY""-REVIEW-statu""s.md.md"
  _name_case "name-lower-case-review-word"         red:name       100644 "securit""y-review.md"
  _name_case "name-mixed-case-review-word-dash"    red:name       100644 "docs/Securit""y-Review-pr12.md"
  _name_case "name-mixed-case-release-word"        red:name       100644 "docs/Releasin""g.txt"
  _name_case "name-review-doc-upper-case-slug"     red:name       100644 "docs/SECURITY""-REVIEW-Feat.md"
  _name_case "name-review-doc-not-markdown"        red:name       100644 "docs/$sr.txt"
  _name_case "name-review-doc-trailing-suffix"     red:name       100644 "docs/$sr.md.bak"
  _name_case "name-tab-in-a-path"                  "red:control byte" 100644 "docs/a${tb}b.md"
  _name_case "name-newline-in-a-private-name"      "red:control byte" 100644 "docs/QUEST${nl}IONS.md"
  _name_case "name-newline-workflow-command"       "red:control byte" 100644 "a${nl}::warning::x.md"
  _name_case "name-symlink"                        red:symlink    120000 "ok.md"
  _name_case "name-gitlink"                        red:gitlink    160000 "vendor/sub"
  _name_case "name-review-doc-admitted"            green          100644 "docs/SECURITY""-REVIEW-feat-x.md" "docs/SECURITY""-REVIEW-0.1.3.md"
  _name_case "name-probe-and-cipher-identifiers"   green          100644 "${cr}ProbeXTest.java" "Field${cr}.java" "tools/cipher-probe-x.sh"
  # N6: the refused path is printed escaped, so its second half never starts a line.
  if grep -aq '^::warning::' "$work/name-newline-workflow-command.out"; then
    echo "self-test FAIL  name-newline-workflow-command: a refused path started an output line (N6)"
    failures=$((failures + 1))
  else
    echo "self-test OK    name-newline-workflow-command printed escaped (N6)"
  fi
  # The admitted shape admits the name only: the review document's text is still scanned.
  _case "review-doc-content-still-scanned" red:content   "docs/$s"   "see $q"
  _case "review-doc-clean-content"         green         "docs/$s"   "a clean review"

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
  # permanently red on an unmutated checkout. That covers the review_doc_shape line too.
  if grep -anE "$pattern" "$guard" >/dev/null 2>&1; then
    echo "self-test FAIL  the pattern matches this script's own source (it must be self-non-matching)"
    grep -anE "$pattern" "$guard"
    failures=$((failures + 1))
  else
    echo "self-test OK    the pattern does not match this script's own source"
  fi

  # The pattern and the admitted shape are each defined exactly once: a second copy is how
  # the two inline versions drifted.
  local defs what
  for what in pattern review_doc_shape; do
    defs="$(grep -c "^$what=" "$guard")"
    if [ "$defs" -eq 1 ]; then
      echo "self-test OK    $what is defined exactly once"
    else
      echo "self-test FAIL  $what is defined $defs times, expected 1"
      failures=$((failures + 1))
    fi
  done

  # N0: `export LC_ALL=C` comes before the first line of code that runs a grep.
  local first_export first_grep
  first_export="$(grep -n '^export LC_ALL=C$' "$guard" | head -n 1 | cut -d: -f1)"
  first_grep="$(grep -n 'grep' "$guard" | grep -a '^[0-9]*:[[:space:]]*[^#[:space:]]' | head -n 1 | cut -d: -f1)"
  if [ -n "$first_export" ] && [ -n "$first_grep" ] && [ "$first_export" -lt "$first_grep" ]; then
    echo "self-test OK    LC_ALL=C is exported before the first grep"
  else
    echo "self-test FAIL  LC_ALL=C is not exported before the first grep (line ${first_export:-none} vs ${first_grep:-none})"
    failures=$((failures + 1))
  fi

  # RP-1: `git grep` failing outright (not a git repository) must refuse, not report clean.
  # A directory that is not a git work tree, holding a planted reference, must still go red,
  # and the name scan must say it could not list the tree (N4), not only the content scan.
  local nongit rc_nongit
  nongit="$work/non-git-directory-holding-a-reference"
  mkdir -p "$nongit"
  printf 'see %s and %s\n' "$q" "$u" > "$nongit/leak.md"
  rc_nongit=0
  _run_tree "$nongit" "$nongit.out" || rc_nongit=1
  if [ "$rc_nongit" -eq 1 ] && grep -aqF "cannot list: git ls-files" "$nongit.out" \
     && grep -aqF "cannot list: git grep exited" "$nongit.out"; then
    echo "self-test OK    non-git directory refused by the name scan and the content scan (cannot list)"
  else
    echo "self-test FAIL  non-git directory: expected 'cannot list' from both scans, exit $rc_nongit"
    failures=$((failures + 1))
  fi

  _run_jars() { # _run_jars <module dir> <output file>; returns 1 for red
    local rc=0
    LC_ALL="$utf8" bash "$guard" --jars "$1" > "$2" 2>&1 || rc=1
    return "$rc"
  }

  # Agent first names in a built jar, through the real --jars path. The red jar carries a
  # name in a resource. The green jar carries what a class file really holds: a string
  # constant behind its two-byte length, where a length of 82 is the byte R and the
  # constant starts with "a ". Measured on stripe-einvoice-core 0.1.0 (TaxSubtotal.class).
  # It must stay green on BSD grep and on GNU grep, which needs `grep -a` for that.
  _jar_case() { # _jar_case <name> <expect> <printf format for the entry>
    local name="$1" expect="$2" fmt="$3" mod="$work/jar-$1" rc=0
    mkdir -p "$mod/target" "$mod/entry"
    # shellcheck disable=SC2059
    printf "$fmt" > "$mod/entry/Entry.class"
    if ! python3 -I -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z: z.write(sys.argv[2], "Entry.class")' \
        "$mod/target/case.jar" "$mod/entry/Entry.class"; then
      echo "self-test FAIL  $name: could not build the scratch jar (python3 missing?)"
      failures=$((failures + 1))
      return
    fi
    _run_jars "$mod" "$mod.out" || rc=1
    _verdict "$name" "$expect" "$rc" "$mod.out"
  }
  _jar_case "jar-agent-name-in-a-resource"    red:content          "\001\000\022reviewed by $cr\n"
  _jar_case "jar-length-byte-before-a-string" green                "\001\000\122a VAT breakdown line\000\001"
  # B-NG-6: a member that is itself an archive is refused, not read (fail closed).
  _jar_case "jar-nested-archive"              "red:nested archive" "PK\003\004\024\000compressed bytes"

  # Member names (B-NG-7, B-NG-10, B-NG-11). The jar is built by Python's zipfile from
  # pairs of arguments, member name then member text; a text of `@nested:<name>` stores a
  # zip holding one clean member of that name, `@link:<target>` a symlink member with that
  # stored target. A name ending in `/` is a directory entry (its text is stored as data).
  _zip_case() { # _zip_case <name> <expect> <jar file name> <member> <text> [<member> <text>]...
    local name="$1" expect="$2" mod="$work/zip-$1" rc=0
    mkdir -p "$mod/target"
    if ! python3 -I -W ignore -c 'import io, sys, zipfile
a = sys.argv[2:]
with zipfile.ZipFile(sys.argv[1], "w") as z:
    for m, t in zip(a[0::2], a[1::2]):
        if t.startswith("@nested:"):
            b = io.BytesIO()
            with zipfile.ZipFile(b, "w") as n:
                n.writestr(t[len("@nested:"):], "clean\n")
            z.writestr(m, b.getvalue())
        elif t.startswith("@link:"):
            zi = zipfile.ZipInfo(m)
            zi.create_system = 3
            zi.external_attr = 0o120777 << 16
            z.writestr(zi, t[len("@link:"):])
        else:
            z.writestr(m, t)' "$mod/target/$3" "${@:4}"; then
      echo "self-test FAIL  $name: could not build the scratch jar (python3 missing?)"
      failures=$((failures + 1))
      return
    fi
    _run_jars "$mod" "$mod.out" || rc=1
    _verdict "$name" "$expect" "$rc" "$mod.out"
  }
  _zip_case "jar-member-agent-name"            red:name               case.jar "META-INF/review-by-$th.txt" "clean"
  _zip_case "jar-directory-entry-name"         red:name               case.jar "$pl/" ""
  _zip_case "jar-member-mixed-case-document"   red:name               case.jar "META-INF/Agent""s.md" "clean"
  _zip_case "jar-member-review-doc-name"       red:name               case.jar "docs/$sr.md" "clean"
  _zip_case "jar-member-parent-segment"        "red:dot segment"      case.jar "../x.txt" "clean"
  _zip_case "jar-member-absolute-path"         "red:dot segment"      case.jar "/x.txt" "clean"
  _zip_case "jar-member-newline"               "red:control byte"     case.jar "QUEST${nl}IONS.md" "clean"
  _zip_case "jar-member-tab"                   "red:control byte"     case.jar "t${tb}ab.txt" "clean"
  _zip_case "jar-member-caret"                 "red:control byte"     case.jar "a^b.txt" "clean"
  _zip_case "jar-duplicate-member"             "red:duplicate member" case.jar "a.txt" "see $q" "a.txt" "clean"
  _zip_case "jar-case-fold-duplicate-member"   "red:duplicate member" case.jar "b/X.txt" "see $q" "b/x.txt" "clean"
  _zip_case "jar-file-name"                    red:name               "$th-1.0.jar" "a.txt" "clean"
  _zip_case "jar-nested-member-name"           "red:nested archive"   case.jar "lib/inner.zip" "@nested:$q"
  _zip_case "jar-empty"                        "red:cannot list"      case.jar
  _zip_case "jar-clean-cipher-class"           green                  case.jar "com/housedevinci/x/Field$cr.class" "clean" "META-INF/" ""
  # N7 (B-NG-19, B-NG-20, B-NG-21): unzip folds these pairs onto one file, keeping the clean
  # one; a directory entry's data is dropped; a symlink's stored target is never read.
  local crb lt
  crb=$'\r'
  lt="$work/link-target.txt"
  printf 'clean\n' > "$lt"
  _zip_case "jar-member-dot-slash-folds"       "red:dot segment"      case.jar "./a.txt" "see $q" "a.txt" "clean"
  _zip_case "jar-member-double-slash-folds"    "red:dot segment"      case.jar "b//a.txt" "see $q" "b/a.txt" "clean"
  _zip_case "jar-member-dot-segment-folds"     "red:dot segment"      case.jar "b/./a.txt" "see $q" "b/a.txt" "clean"
  _zip_case "jar-member-backslash"             "red:dot segment"      case.jar 'a\b.txt' "clean"
  _zip_case "jar-directory-entry-data"         "red:listing mismatch" case.jar "a.txt" "clean" "d/" "see $q"
  _zip_case "jar-symlink-member"               red:symlink            case.jar "a.txt" "clean" "link" "@link:$lt"
  _zip_case "jar-file-name-control-byte"       "red:control byte"     "a${nl}b.jar" "a.txt" "clean"
  # N6, B-NG-23: a content hit holding a carriage return is printed escaped, on both sides.
  _case     "content-hit-carriage-return"      red:content   doc.md   "see $q${crb}::warning::spoofed"
  _zip_case "jar-content-hit-carriage-return"  red:content            case.jar "a.txt" "see $q${crb}::warning::spoofed"
  for v in "$work/content-hit-carriage-return.out" "$work/zip-jar-content-hit-carriage-return.out"; do
    if tr '\r' '\n' < "$v" | grep -aq '^::warning::'; then
      echo "self-test FAIL  $(basename "$v" .out): a content hit started a runner command line (N6)"
      failures=$((failures + 1))
    else
      echo "self-test OK    $(basename "$v" .out) printed escaped (N6)"
    fi
  done
  # N6, B-NG-30: a tracked file whose NAME is a runner command, with a hit inside. Every output
  # line, split on CR and LF as the runner splits, must not start with `::` (after blanks)
  # except the guard's own error line; the hit line starts with `hit: `.
  _case "hit-path-starts-a-command" red:content '::stop-commands::tok' "see $q"
  if tr '\r' '\n' < "$work/hit-path-starts-a-command.out" | grep -a -E '^[[:space:]]*::' \
       | grep -aqv '^::error::check-private-references: '; then
    echo "self-test FAIL  hit-path-starts-a-command: a hit line started with its file path (N6)"
    failures=$((failures + 1))
  elif ! grep -aq '^hit: ' "$work/hit-path-starts-a-command.out"; then
    echo "self-test FAIL  hit-path-starts-a-command: no hit line found to check (N6)"
    failures=$((failures + 1))
  else
    echo "self-test OK    hit-path-starts-a-command hit lines start with the fixed prefix (N6)"
  fi
  # N7, B-NG-31: the file-count half of the one-to-one check, alone. Equal bytes, unequal file
  # count: the dirty `./a.txt` listed at size 0 plus a clean `a.txt` (6 bytes, 2 files listed),
  # extracted as one 6-byte file. Only the file-count comparison can refuse this.
  mkdir -p "$work/file-count-half"
  printf 'clean\n' > "$work/file-count-half/a.txt"
  printf './a.txt\na.txt\n' > "$work/file-count-half.lst"
  printf '2 files, 6 bytes uncompressed, 6 bytes compressed:  0.0%%\n' > "$work/file-count-half.tot"
  local frc=0
  ( extracted_matches_listing "$work/x.jar" "$work/file-count-half.lst" "$work/file-count-half.tot" "$work/file-count-half" ) > "$work/file-count-half.out" 2>&1 || frc=1
  _verdict "file-count-half" "red:listing mismatch" "$frc" "$work/file-count-half.out"
  # The "listed, not extracted" refusal, on the real function: Apple's unzip lists a
  # non-ASCII name as `?`, which no portable jar reproduces on both systems.
  mkdir -p "$work/not-extracted"
  printf 'a.txt\n' > "$work/not-extracted.lst"
  local nrc=0
  ( check_extracted_members "$work/x.jar" "$work/not-extracted.lst" "$work/not-extracted" ) > "$work/not-extracted.out" 2>&1 || nrc=1
  _verdict "listed-not-extracted" "red:cannot list" "$nrc" "$work/not-extracted.out"

  # N4: a listing that fails refuses. The real `listing` function on a missing jar, no stub.
  local lrc=0
  ( listing "$work/missing.jar" "$work/missing.lst" unzip -Z1 "$work/missing.jar" ) > "$work/missing.out" 2>&1 || lrc=1
  _verdict "listing-of-a-missing-jar" "red:cannot list" "$lrc" "$work/missing.out"
  # B-NG-11: the count check, on a synthetic pair: two names listed, one entry counted.
  printf 'a.txt\nb.txt\n' > "$work/count.lst"
  printf '1 file, 2 bytes uncompressed, 2 bytes compressed:  0.0%%\n' > "$work/count.tot"
  lrc=0
  ( jar_counts_match "$work/count.lst" "$work/count.tot" ) > "$work/count.out" 2>&1 || lrc=1
  _verdict "listing-count-mismatch" "red:listing mismatch" "$lrc" "$work/count.out"
  printf 'a.txt\n' > "$work/count1.lst"
  lrc=0
  ( jar_counts_match "$work/count1.lst" "$work/count.tot" ) > "$work/count1.out" 2>&1 || lrc=1
  _verdict "listing-count-match" green "$lrc" "$work/count1.out"
  printf 'some other line\n' > "$work/count2.tot"
  lrc=0
  ( jar_counts_match "$work/count1.lst" "$work/count2.tot" ) > "$work/count2.out" 2>&1 || lrc=1
  _verdict "listing-count-unparsed" "red:cannot list" "$lrc" "$work/count2.out"

  # RP-2: a jar `unzip` cannot read must refuse, not report every built jar clean.
  local jar_module rc_jar
  jar_module="$work/corrupt-jar-module"
  mkdir -p "$jar_module/target"
  printf 'not a zip file, but mentions %s\n' "$q" > "$jar_module/target/broken.jar"
  rc_jar=0
  _run_jars "$jar_module" "$jar_module.out" || rc_jar=1
  _verdict "corrupt-jar" "red:cannot list" "$rc_jar" "$jar_module.out"

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
