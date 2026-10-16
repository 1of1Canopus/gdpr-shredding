# Security review: fix/verified-schema-datasource (PR 38, finding C-PR-1)

## Pass 1, 2026-10-16

Head reviewed: `c09f9b4` ("docs(core): document the datasource binding and the upgrade"), base
`4a31373`. Design: the C-PR-1 design page, approved at design review round 2 (2026-10-15).
Method: full build and tests, every earlier probe re-run, the builder's six mutations re-run, two
new mutations, then attacks on the identity check, the capability type, the overload chain, the
equality change, the architecture rule, the published jars and the public text.

### Verdict: MERGE WITH FIXES

No HIGH, no MEDIUM. Three LOWs and one INFO. Under the no-allowance rule all four are closed
before merge. None needs a new mechanism: two are a changed architecture rule, one is a jar
manifest entry plus truthful text, one is text in the PR body.

The mechanism itself holds. Every path the design names behaves as the PR body says, the check is
`!=` on the pool in the one place all four deprecated constructors reach, and no property, helper
or published artifact weakens it.

### Numbers on this head

| What | Result |
| --- | --- |
| `./mvnw -o -B verify`, Docker up, tests run | green: core 571, starter 298, sample 25; 0 failures, 0 errors, 0 skipped |
| Earlier `CipherProbe*` classes | all green inside the run above; the original `CipherProbeSecondDataSourceTest` (pre-fix copy, unchanged) run in place of the suite copy: green |
| Builder's mutations M1, M2, M3a, M3b, M4, M5 | all six red, with the failing tests the PR body lists (M1: core 14, starter 7; M2: 7; M3a: 3; M3b: the architecture rule; M4: the binding test and `t14`; M5: the delegate case of the P15 test) |
| Review mutation M7: `VerifiedSchema::new` held in a field of `JdbcSupport` | survives: core suite green (finding C-PR38-2) |
| Review mutation M8: a class in the starter's `main`, package `adapter.jdbc`, calls the constructor | survives: core 571 and starter 298 green (finding C-PR38-3) |
| Main jars and sources jars (core, starter) | no test class, no `TestSchemas`; no test-jar is built or attached |
| New probes from this pass | 4: 3 RED (C-PR38-1, -2, -3), plus 3 green characterisations |

### Builder's open questions

- **C-33 (34 call sites, 19 rebound through `TestSchemas.reboundTo`): accepted.** The helper is in
  the core test tree only. Verified on the built jars: it is in neither the main jar nor the
  sources jar of any module, and no test-jar is published. Rewriting the 19 tests to verify on the
  wrapper would change what they test. One correction: its Javadoc says "Production code cannot do
  this". Application code can, by the same route the helper takes (C-PR38-1). The sentence is fixed
  with that finding.
- **C-34 (lazy store refuses at creation, not first use): accepted.** The test accepts the
  refusal at either point and asserts no write reached the unguarded database. Stricter than
  designed.
- **C-35 (design-review probe file not added): accepted.** Its four tests belong to C-PR-1b,
  C-PR-1c and C-PR-1d. This PR does not claim them.

### Attacks that held (no finding)

| Attack | Result | Evidence |
| --- | --- | --- |
| Overload chain: does every deprecated form reach the check | yes. 5-arg and 6-arg forms delegate to the 7-arg form, which calls `requireVerifiedOn` inside `this(...)`, before the body opens a connection | M2 red; `each_deprecated_constructor_refuses_a_foreign_pool` (4 cases) |
| `equals` on a hostile pool | refused: identity, not `equals` | M5 red |
| `@Lazy` on the context's DataSource bean definition | starts; gate and an application store holding the bean by type see one object; the row lands in the verified database | `lazy_datasource_bean_definition_starts_and_writes_to_the_verified_database`, green |
| `@Lazy` on the injection point of an application store on a deprecated constructor | refused with `SHRED-SCHEMA-011`: Spring injects a lazy-resolution proxy, a different object. Strict, and the message names the remedy. The P15 rule (a wrapper is refused) | `lazy_injection_point_on_the_deprecated_constructor_is_refused_with_011`, green |
| Post-processor that wraps the DataSource "after the gate ran" | not possible for a singleton: it runs once, before injection. The PR's P8 tests cover the wrapper the gate sees | P8 tests |
| Copy of a `VerifiedSchema` by serialization or clone | not `Serializable`, not `Cloneable`, `final`; `SchemaVerdict` not `Serializable` | `verified_schema_and_verdict_cannot_be_copied_by_serialization_or_clone`, green |
| `SchemaVerdict` and `VerifiedSchema` equality callers in `main` | none. The one `equals` near a schema (`CopyCatalogue.entryFor`) compares `Optional<String>` | read and grep of every module's `main` |
| `upgrading-0.2.1.md` | true for this PR: default beans unchanged, both forms shown, the refusal and its remedy, the P7 and P12 sentences, the equality change. One line to add with C-PR38-1 | read against the code |
| "Not covered yet" line for C-PR-1b | present in the PR body and in SECURITY-NOTES | read |

### Findings

**C-PR38-1 (LOW, framework path). Application code in the module's package mints a
`VerifiedSchema` on any DataSource, and the notes say this is impossible.**
The capability rests on a package-private constructor. The core jar does not seal the package. So
an application jar that declares a class in `com.housedevinci.shredding.adapter.jdbc` (a split
package) calls `new VerifiedSchema("public", anyPool)` with no reflection, and the new constructors
accept it. The module's own public test tree shows the route (`TestSchemas.reboundTo`), so a
developer who meets `SHRED-SCHEMA-011` can copy it. SECURITY-NOTES says "impossible: one
package-private constructor, an architecture test refuses any other caller"; the architecture test
sees the module's own classes only.

- Probe: `cipher-probe-c-pr-1-split-package.sh` (`probe_application_class_in_the_module_package_mints_a_verified_schema`).
  On `c09f9b4`: RED, the forged class prints `MINTED public bound to the unverified DataSource`.
- Fix tried on a scratch copy: with the package sealed, the probe is GREEN (`SecurityException:
  sealing violation`) and the full build stays green (571 / 298 / 25).
- Limit, measured: Spring Boot's executable-jar launcher does not enforce sealing. The forged class
  planted in `BOOT-INF/classes` of the sample's Boot jar, with the sealed core jar nested, still
  printed `MINTED`. So sealing is a control on a plain classpath only. Under the Boot launcher this
  path is application code acting on purpose, the same trust class as P7.
- Fix, for the fix pass:
  1. `gdpr-shredding-core/pom.xml`: `maven-jar-plugin` `archive/manifestSections`, one section
     named `com/housedevinci/shredding/adapter/jdbc/` with `Sealed: true`. Seal that package only;
     no other module declares a class in it.
  2. Copy the probe to `tools/cipher-probe-sealed-package.sh` and run it in the `cipher-probes` CI
     job after a `package` of core. Exit 2 (no jar, neither outcome) fails the job.
  3. SECURITY-NOTES, row "Application constructs its own `VerifiedSchema`": "refused on a plain
     classpath: one package-private constructor, the package is sealed in the core jar, and an
     architecture rule refuses any other minting point in the module. Under Spring Boot's
     executable-jar launcher, which does not enforce sealing, a class the application places in
     this package can still mint one: that is application code, as for your own `KeyProvider`."
  4. `TestSchemas` Javadoc: replace "Production code cannot do this" with the same two facts.
  5. `docs/upgrading-0.2.1.md` and CHANGELOG `[Unreleased]` "Changed": the core jar now seals
     `com.housedevinci.shredding.adapter.jdbc`; a class of yours in that package fails to load with
     `sealing violation` on a plain classpath.

**C-PR38-2 (LOW, framework path). The architecture rule misses a constructor reference.**
`only_SchemaVerification_constructs_VerifiedSchema` matches `callConstructorWhere`. ArchUnit models
`VerifiedSchema::new` as a constructor reference, not a call. Mutation M7 (a `BiFunction` field
holding `VerifiedSchema::new` in `JdbcSupport`) keeps the whole core suite green.

- Probe: `CipherProbePr38Test.probe_a_constructor_reference_outside_SchemaVerification_passes_the_rule`
  (core, package `architecture`, with fixtures `CipherProbePr38MintFixtures` in `adapter.jdbc` of
  the test tree). RED on `c09f9b4`. Its control (a direct call is a violation) is green.
- Fix, tried on a scratch copy: in `HexagonalArchitectureTest`, replace `callConstructorWhere(...)`
  with `accessTargetWhere(...)` on a `JavaAccess` whose target owner is `VerifiedSchema` and whose
  name is `<init>`. With it: the probe is green, the existing rules stay green, and M7 turns red.
  Name the predicate "a constructor of VerifiedSchema, by call or by reference".

**C-PR38-3 (LOW, framework path). The architecture rule does not cover the starter.**
The rule runs in core's test tree and imports core's classes only. Mutation M8 (a class
`StarterMint` in the starter's `main`, package `com.housedevinci.shredding.adapter.jdbc`, that
calls the constructor) keeps core 571 and starter 298 green. The starter is the module most likely
to grow a helper beside the stores.

- Probe: `cipher-probe-c-pr-1-starter-scope.sh`
  (`probe_a_starter_class_in_a_core_package_mints_a_verified_schema_unseen`). It plants the class
  in a scratch copy of the tree and runs both suites. RED on `c09f9b4`.
- Fix, for the fix pass: an architecture test in the starter's test tree, importing the starter's
  `main` (`ImportOption.DoNotIncludeTests`), with two rules: (a) no starter class resides in a core
  package (`..shredding.adapter..`, `..shredding.domain..`, `..shredding.application..`,
  `..shredding.api..`); (b) the C-PR38-2 rule (no access to a constructor of `VerifiedSchema`).
  The probe turns green when a starter test fails on the planted class.

**C-PR38-4 (INFO, docs). The draft advisory says the default beans are not affected, in a text
that also announces two issues that reach them.**
The draft's first paragraph ends "The starter's default beans are not affected." That is true for
C-PR-1. The same text then announces C-PR-1b and C-PR-1c, and both reach the starter's default
beans (design review of 2026-10-15, rows C-PR-1b and C-PR-1c: "default beans are hit too", "default
beans have it too"). A reader deciding how urgent the upgrade is takes the sentence for the whole
advisory. "Affected" names the core artifact only, while C-PR-1b and C-PR-1c live in the gate the
starter wires.

- Probe: none can execute PR text. Repro: the two quotations above, side by side.
- Fix, in the PR body: "For this first issue, the starter's default beans are not affected.
  C-PR-1b and C-PR-1c do affect the default beans." Affected: `gdpr-shredding-core` and
  `gdpr-shredding-spring-boot-starter` 0.2.0.

### Routing

All four go to the fix pass. None is a design stop. The fixer adds the three RED probes to the
suite first, then fixes. The second pass checks each probe green, re-runs M7 and M8 (both must be
red), and re-runs the sealed-package probe on the sample's build.
