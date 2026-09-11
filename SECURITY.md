# Security policy

## Reporting a vulnerability

Email **security@housedevinci.com**.

Please do not open a public GitHub issue for a suspected vulnerability. Include:

- the version of `gdpr-shredding-core` / `gdpr-shredding-spring-boot-starter` affected
- a description of the vulnerability and its impact
- steps to reproduce, or a minimal repro project if practical

## Supported versions

GDPR Shredding is pre-1.0. Until `1.0.0`, only the latest published minor version receives
security fixes.

| Version | Supported |
|---|---|
| latest `0.x` | yes |
| older `0.x` | no |

After `1.0.0`, this table will list the latest minor of the current and previous major.

## Disclosure window

We ask for **90 days** from first report before public disclosure, to give us time to
develop, test and publish a fix and to notify known downstream users where practical. We
will acknowledge a report within 5 business days and keep the reporter updated as a fix
progresses. A fix earlier than 90 days does not obligate early public disclosure; a
reporter who needs a longer window for coordinated disclosure elsewhere should say so.

## Scope

In scope: `gdpr-shredding-core`, `gdpr-shredding-spring-boot-starter`, and the CI workflows
that build and test them (`.github/workflows/ci.yml`, `.github/workflows/security-scan.yml`).
`gdpr-shredding-sample` is a demo application, never published, and is in scope only insofar
as a vulnerability in it also reaches the library code.
