# Sample

A customer whose email and phone are encrypted under that customer's own key, an audit table that
keeps `customer_id`, and an erasure endpoint.

## Run

```
docker compose -f gdpr-shredding-sample/docker-compose.yml up -d

export SHREDDING_MASTER_KEY=$(head -c 32 /dev/urandom | base64)
export SHREDDING_ERASURE_LOG_SECRET=$(head -c 32 /dev/urandom | base64)
export SHREDDING_BLIND_INDEX_SECRET=$(head -c 32 /dev/urandom | base64)

./mvnw -pl gdpr-shredding-sample -am spring-boot:run
```

Nothing starts without those three. There is no default master key and none is generated.

## Try it

```bash
curl -s localhost:8080/customers -H 'content-type: application/json' -d '{
  "tenantId":"acme","customerId":"cust-42",
  "email":"alice@example.com","phone":"+33100000000" }'

curl -s localhost:8080/customers/acme/cust-42
# [{"customerId":"cust-42","email":"alice@example.com","phone":"+33100000000","erased":false}]
```

The read path takes the tenant explicitly, not just `customerId`: control 15 makes the tenant
mandatory with no default, and a read that skips it would look through every tenant's rows for a
customer id that happens to match.

The column is already unreadable:

```
docker compose -f gdpr-shredding-sample/docker-compose.yml exec postgres \
  psql -U shredding -c "select customer_id, encode(email,'escape') from customer"
#  cust-42 | SH1\001\001...
```

Erase (behind HTTP Basic - `SecurityConfig` ships one user, `dpo`/`dpo`, for this sample only):

```bash
curl -s -u dpo:dpo localhost:8080/customers/erasures -H 'content-type: application/json' -d '{
  "tenantId":"acme","customerId":"cust-42","reason":"art 17 request" }'
# {"outcome":"COMPLETE","keysDestroyed":1,"blindIndexColumnsCleared":1,
#  "completeInBackupsAt":"2026-10-08T..."}

curl -s localhost:8080/customers/acme/cust-42
# [{"customerId":"cust-42","email":"[erased]","phone":"[erased]","erased":true}]

curl -s localhost:8080/customers/erasures/verify
# {"status":"INTACT","verified":1,...}
```

The row is still there, `customer_id` still joins, the audit rows are untouched, and the erasure log
verifies. The email and phone are permanently unreadable because the key they needed no longer
exists - which regulators classify as pseudonymisation with key destruction, not anonymisation and
not deletion. See `docs/index.md`, "Is this legally erasure?". `completeInBackupsAt` is when the erasure is also complete in backups and WAL: until then
a restore brings the key back. That is `shredding.erasure.backup-retention`, and you should set it
to your real retention.

## Test

```
./mvnw -pl gdpr-shredding-sample -am test
```

`SampleEndToEndTest` proves the whole acceptance check against a Testcontainers PostgreSQL, and
carries several of Cipher's probes.

## L7: this endpoint shape, not this security model

`SecurityConfig`'s single hard-coded HTTP Basic user is a copyable *shape*, not a real
authorization model: a real erasure endpoint is authenticated against your actual identity
provider, and `requestedBy` comes from the authenticated principal - `CustomerEndpoints.erase`
takes it from `Principal.getName()`, never from the request body, because a body field is whatever
the caller says it is and the erasure log's `requestedBy` column is meant to be an audit fact.
