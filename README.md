# GDPR Shredding

**GDPR erasure without deleting a row? Crypto-shredding for Spring Boot and JPA.**

When a person asks to be forgotten, GDPR says delete. Audit, accounting and AML rules say keep.
Crypto-shredding is how teams square the two: encrypt each person's personal fields under that
person's own key, and destroy the key. That **renders the data unreadable to anyone who does not
hold the key, and the key no longer exists** - within the residual risks set out in
`SECURITY-NOTES.md`. The row survives, and so do the foreign keys and the audit trail.

Be precise about what that is. This is pseudonymisation, not anonymisation and not deletion:
WP216 section 4 lists encryption with a secret key as a pseudonymisation technique and says
pseudonymisation is a security measure, not anonymisation (WP216 s.4; the ICO's guidance on
deleting personal data and "putting beyond use" points the same way). It is squarely
Art. 32(1)(a), and it is what lets an Art. 17(1) request be answered without dropping rows another
law requires you to keep (Art. 17(3)(b)) - but whether it satisfies a given erasure request is
your DPO's call on your facts. The residual risks are in `SECURITY-NOTES.md` and the sources are
in `docs/index.md`.

Fair source (FSL-1.1-ALv2): free to use for any purpose except a Competing Use - offering a
commercial product or service that substitutes for this one, substitutes for anything we offer
using it, or has the same or substantially similar functionality - becomes
Apache-2.0 two years after each release. Pro edition under a separate commercial licence.
Java 21, Spring Boot 4.1, PostgreSQL. **Zero crypto dependencies**: AES-256-GCM,
HMAC-SHA-256 and a hand-written HKDF checked against the RFC 5869 vectors, all from the JDK.

```xml
<dependency>
  <groupId>com.housedevinci</groupId>
  <artifactId>gdpr-shredding-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Try it in two minutes

```bash
docker compose -f gdpr-shredding-sample/docker-compose.yml up -d

export SHREDDING_MASTER_KEY=$(head -c 32 /dev/urandom | base64)
export SHREDDING_ERASURE_LOG_SECRET=$(head -c 32 /dev/urandom | base64)
export SHREDDING_BLIND_INDEX_SECRET=$(head -c 32 /dev/urandom | base64)

cd gdpr-shredding-sample && ../mvnw spring-boot:run
```

```bash
curl -s localhost:8080/customers -H 'content-type: application/json' -d '{
  "tenantId":"acme","customerId":"cust-42",
  "email":"alice@example.com","phone":"+33100000000" }'
```

Full walkthrough, including the erasure call and the row going unreadable: [`gdpr-shredding-sample/README.md`](gdpr-shredding-sample/README.md).

## Sixty lines

```java
@Entity
@Table(name = "customer")
public class Customer {

  @Id @GeneratedValue Long id;

  @Column(name = "tenant_id")   String tenantId;    // stays readable
  @Column(name = "customer_id") String customerId;  // stays readable: the audit rows point here

  @Shredded(subject = "#{customerId}", tenant = "#{tenantId}")
  @Convert(converter = CustomerEmailConverter.class)
  @Column(name = "email")
  String email;                                     // encrypted under this customer's own key

  @BlindIndex(of = "email", subjectColumn = "customer_id", tenantColumn = "tenant_id")
  @Column(name = "email_bidx")
  byte[] emailBidx;                                 // equality lookups; nulled by an erasure

  @Override public String toString() { return "Customer[" + customerId + "]"; }
}

@Converter
public class CustomerEmailConverter extends ShreddedStringConverter {
  public CustomerEmailConverter() { super("Customer", "email"); }
}
```

```yaml
shredding:
  master-key: ${SHREDDING_MASTER_KEY}                    # base64, >= 32 bytes, environment only
  erasure-log:
    hmac-secret: ${SHREDDING_ERASURE_LOG_SECRET}
  blind-index:
    hmac-secret: ${SHREDDING_BLIND_INDEX_SECRET}
```

```java
erasureService.erase(new ErasureRequest(
    TenantId.of("acme"), SubjectId.of("cust-42"), "dpo", "art 17 request"));
```

Afterwards the row is still there, `customer_id` still joins, the audit rows are untouched, and
`customer.getEmail()` reads `[erased]` because the key it needed no longer exists. The erasure log holds a hash-chained, HMAC-keyed record of
what was destroyed, when, by whom, and the date the erasure is also complete in backups.

## What it is careful about

- **Data keys are random, never derived from the master key.** A derived key is re-derivable
  forever, which makes erasure a no-op.
- **Key destruction and its proof are one transaction.** A destroyed key with no record is an
  unprovable erasure; a record with a live key is a false proof. Neither can happen.
- **A key-store outage is not an erasure.** `KEY_UNAVAILABLE` (retry, 503, health DOWN) and
  `KEY_DESTROYED` (terminal) are different failures.
- **An erasure nulls the subject's blind-index columns.** Not configurable: an index that survives
  keeps the erased subject searchable for ever.
- **The plaintext leak paths fail at startup**, not by convention: a second-level cached
  `@Shredded` entity, a converter that names the wrong field, a subject expression that reaches a
  bean or a static type, or a sample-looking master key are all startup failures.
- **The converter never hands out plaintext.** It decrypts and files what it decrypted; the entity
  load event, which is the only thing that knows the row, verifies it against that row's tenant,
  subject and identifier and installs it. A Spring Data repository call works transparently. A raw
  `EntityManager` entity operation (`find`, `merge`, `refresh`, an entity-returning query) needs
  `ShreddingContext.withReadBracket(...)`:
  ```java
  Doc doc = ShreddingContext.withReadBracket(() -> entityManager.find(Doc.class, id));
  ```
  Anything that is not a managed entity load - a `@Query` scalar/`Tuple`/interface projection, a
  `Stream<T>` consumed after the repository call already returned, a hand-written DAO's own
  `EntityManager` use, a `StatelessSession` - is refused (`SHRED-READ-UNVERIFIED` or
  `SHRED-READ-UNSCOPED`) with nothing decrypted returned. See `docs/index.md` for the full contract.
  `ShreddingContext.withReadBracket(...)` is the one stable entry point an application calls
  directly; `enterRegion`, `recordDecoded`, `drain` and `pendingKeysFor` are this module's internal
  SPI for its own converters and listeners, not application API, and may change without a major
  version.
- **Every stored value is bound to its row.** Tenant, subject *and* the row's own identifier go into
  the header and the AAD, so a ciphertext copied between two rows of the same person is
  `SHRED-ROW-MISMATCH` rather than displayed as the second row's own value.

### Two rules for a `@Shredded` entity

1. **A `@Shredded` field must never participate in `equals` or `hashCode`.** Between the decrypt and
   the install the field holds a placeholder, so an instance put into a `HashSet` or used as a
   `HashMap` key before the install is unreachable afterwards.
2. **The identifier must be basic and single-column** - a numeric id, a `UUID`, a `String` or a
   `byte[]`. It is bound into every stored value; a composite or embedded id, including a
   single-column `@EmbeddedId`, is refused at startup, as are optimistic locking `ALL`/`DIRTY`,
   select-before-update, and a `@Shredded` column inside the natural id.
- **There is no fail-open property anywhere.** Every weaker mode is explicit and WARNs at *every*
  startup.
- **The honest bound is written down.** This is pseudonymisation with key destruction, not
  anonymisation. An insider who snapshots the key table before an erasure and restores it afterwards
  gets the data back, and backups hold the wrapped key until their retention expires.
  `SECURITY-NOTES.md` says so, and a test asserts it says so.

## Modules

| Module | What |
|---|---|
| `gdpr-shredding-core` | JDK-only domain and application: envelope encryption, key model, erasure and the hash-chained erasure log |
| `gdpr-shredding-spring-boot-starter` | Auto-configuration, Hibernate converters and write-path listeners, startup refusals, actuator |
| `gdpr-shredding-sample` | A customer with an encrypted email and phone, an audit table that keeps `customer_id`, an erasure endpoint |

## Free vs Pro

Free core is everything above. The Pro edition adds Vault / AWS KMS / Azure Key Vault / GCP KMS key
providers with master-key rotation and re-wrap, per-tenant master keys, the erasure workflow
(intake, identity verification, grace period, erasure record PDF for the DPO), the admin UI, and
the resumable batch migrator that encrypts existing plaintext columns.

## Documentation

`docs/index.md` (quickstart, configuration table, error codes, FAQ) - `SECURITY-NOTES.md`
(residuals and threat model) - `CHANGELOG.md`.

## Build

```
./mvnw -B clean verify        # needs Docker: Testcontainers starts PostgreSQL
```
