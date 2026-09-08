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

curl -s localhost:8080/customers/cust-42
# [{"customerId":"cust-42","email":"alice@example.com","phone":"+33100000000","erased":false}]
```

The column is already unreadable:

```
docker compose -f gdpr-shredding-sample/docker-compose.yml exec postgres \
  psql -U shredding -c "select customer_id, encode(email,'escape') from customer"
#  cust-42 | SH1\001\001...
```

Erase:

```bash
curl -s localhost:8080/customers/erasures -H 'content-type: application/json' -d '{
  "tenantId":"acme","customerId":"cust-42","requestedBy":"dpo","reason":"art 17 request" }'
# {"outcome":"COMPLETE","keysDestroyed":1,"blindIndexColumnsCleared":1,
#  "completeInBackupsAt":"2026-10-08T..."}

curl -s localhost:8080/customers/cust-42
# [{"customerId":"cust-42","email":"[erased]","phone":"[erased]","erased":true}]

curl -s localhost:8080/customers/erasures/verify
# {"status":"INTACT","verified":1,...}
```

The row is still there, `customer_id` still joins, the audit rows are untouched, and the erasure log
verifies. `completeInBackupsAt` is when the erasure is also complete in backups and WAL: until then
a restore brings the key back. That is `shredding.erasure.backup-retention`, and you should set it
to your real retention.

## Test

```
./mvnw -pl gdpr-shredding-sample -am test
```

`SampleEndToEndTest` proves the whole acceptance check against a Testcontainers PostgreSQL, and
carries three of Cipher's probes.
