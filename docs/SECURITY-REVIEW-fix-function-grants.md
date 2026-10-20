# Security review: fix/function-grants (C-PR45-3)

## Pass 1, 2026-10-19

Head reviewed: `b28e891` ("test(core): kill the two mutations the first suite let live"),
with `main` `13b3bf1` merged in. The branch builds the function-grants leg: no role in reach,
and PUBLIC no more than the server default, may hold EXECUTE on a function the server or a
shipped extension withholds, on an alias of one, on native `SECURITY DEFINER` code, on native
code made by hand, or on a shipped extension member no longer as shipped. Native code is judged
against three files pinned in the jar, not against the live record.

Words used here:
- **gate**: the startup schema check.
- **login role / reach**: the role the connection authenticated as, and every role it reaches.
- **W**: the withheld set (initdb functions the server ships without PUBLIC EXECUTE, plus the baseline).
- **pinned files**: the three per-major `.tsv` files generated from the pinned image and byte-compared to it.
- **caller object**: a catalogue row that names a function the server runs for you (an aggregate, an operator). The subject of the still-open design-stop.

### Verdict: MERGE WITH FIXES

The finding under verification, C-PR45-3, is fixed for the direct-grant case: the pass-1 probe
`probe_execute_on_lo_export_passes_and_writes_a_server_file` is now green (it was red on `main`).
The loader is robust against the inputs I threw at it. The two required JIT tests and the two
required leg-2 core tests are present and green. The accepted-list rules (trim, blank refuses,
case-folded shipped name refuses, empty is fail-closed) hold.

Two findings block merge. Both are already open from the build ruling and are design-stop items;
neither is new code from me. PR 46 ships the interim aggregate rule marked `pending ruling` and
must stay draft until they are built.

| Id | Severity | One line | State |
| --- | --- | --- | --- |
| C-PR45-3-15 | MEDIUM | An aggregate owned outside reach runs its support function as the owner, so a role with no grant reads a file; a contrib aggregate re-created over a new support function keeps the symbol `aggregate_dummy` and passes R5b | open; design approved round 5; build its own PR |
| C-PR45-3-17 | MEDIUM | `CREATE OR REPLACE` keeps a core oid while changing language, library and symbol; nothing refuses a core PUBLIC function rewritten over a symbol W does not hold | open; design approved round 5; build its own PR |
| C-PR46-1 | INFO | The new sources-jar allowlist patterns use `*`, which matches a path separator, so any `.tsv` under that directory with the pinned prefix would be admitted | see below |

C-PR45-3-15 and -17 are fixed by the revision-5 mechanism (statement 3, rule R6, rule R7, a
fourth pinned-file family, a manifest column), which I approved on the design page on 2026-10-19.
That is a new mechanism and gets its own PR and its own two passes. PR 46 cannot merge before it.

### C-PR46-1 (INFO): the allowlist glob matches a path separator

`ci.yml` adds three `case` patterns to the sources-jar allowlist, for example
`com/housedevinci/shredding/adapter/jdbc/pg-initdb-withheld-*.tsv`. In a shell `case`, `*` matches
any string including `/`, so a future stray entry such as
`.../pg-initdb-withheld-16/anything.tsv` would be admitted without the extension check firing.
The risk is small (the directory holds only the three generated families, and the byte-for-byte
image test would catch a changed shipped file), and the pattern follows the existing house style
(`postgresql-*-reserved-keywords.txt` is the same shape). Fix: narrow the digit part, for example
`pg-initdb-withheld-[0-9]*.tsv`, or list the shipped names exactly. No-allowance: fix before merge
or have the reviewer reclassify after a repro that closes without a change.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -B clean verify`, Docker up, after the Java wait loop, never `install` | green: core 877, starter 319, sample 25; 0 failures, 0 errors, 0 skipped; JaCoCo gate met; core 6:02, starter 2:20, sample 25 s |
| Pass-1 probe of PR 45 (`CipherProbePr45Test.probe_execute_on_lo_export_passes_and_writes_a_server_file`) | green on `b28e891` (red on `main`) |
| Byte-for-byte image test (`PinnedFilesMatchTheImageTest`, 16 and 17) | green: baseline, manifest and versions files equal a pristine install on both pins; 176 pristine databases per pin give 0 R5 rows |
| Required JIT tests (`statement_two_gives_the_same_rows_with_jit_on_and_off`, `gate_leaves_jit_and_search_path_as_they_were`) | present and green |
| Required leg-2 core tests (`core_function_sharing_a_withheld_extension_symbol_verifies`, `core_function_rewritten_to_language_c_with_a_withheld_symbol_refuses`) | present and green |
| In-tree `FunctionGrantsRulesTest`, `FunctionGrantsPg16Test`, `FunctionGrantsPg17Test`, `AcceptedThirdPartyExtensionsTest` | all green inside the verify above |

### Attacks I ran

| Attack | Result |
| --- | --- |
| Loader: duplicate manifest key | refused ("twice") |
| Loader: a CRLF line ending | refused ("LF-terminated") |
| Loader: a UTF-8 BOM on the first line | refused (oid regex rejects the BOM-prefixed digits) |
| Loader: a manifest line for a version with no `ok` line in the versions file | refused ("no ok line") |
| Loader: a missing column | refused ("tab-separated columns") |
| Loader: a manifest member of a `fails`-only version | refused ("no ok line") |
| Loader: a last line with no trailing newline | refused ("LF-terminated") |
| Accepted-list: empty default | fail-closed; a native function of an unknown extension refuses; no WARN (secure default needs none) |
| Accepted-list: a blank entry | refuses to start (`SHRED-CONFIG-001`, "entry N is blank") |
| Accepted-list: a shipped name, any case | refuses to start (names F41) |
| Accepted-list: a name the image lists but cannot install (`plperl`) | accepted |
| Rule-engine mutation, leg 2 core (compare every core function with the initdb part only) | the leg-2 core test goes red; restored |
| Rule-engine mutation, leg 1 off (`inW` returns false) | the leg-1 test goes red; restored |

The seven loader attacks were reproduction attempts that closed with no code change: the code
already refuses each. I ran them with a throwaway probe class in my worktree and removed it.

### The remaining paths, measured for the design (round 5)

I measured the aggregate and caller-object paths on both pins for the design review (see the design
page, round 5). In short: aggregate `sfunc`, `finalfunc` and moving `mfinalfunc` run the support
function as the owner and are open; a language validator is also open (`(oid) -> void` fits three
withheld built-ins); every operator, cast, type function, range function, conversion, text-search
function, access-method support function and handler is refused by the server because no withheld
built-in fits its `cstring` / `internal` slot. These are closed by the revision-5 mechanism, not by
this PR.

### Not findings

- The stray local `install` the builder ran writes only to the local Maven repository. The build of
  record is CI on a fresh checkout, and my `clean verify` built every module from source and passed.
  No effect on the artifact. Worth a note only: a stale local `0.1.0-SNAPSHOT` could mislead a later
  local-only build.
- `R5a` case 4 refusing a member of an accepted extension that reuses a withheld symbol is by design,
  not a false refusal.
- The superuser-login early return skips the execute legs but still runs the record rules; a superuser
  login is the dominant finding elsewhere, so this is not a new hole.

The reviewer
