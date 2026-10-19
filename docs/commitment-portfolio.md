# Existing AWS commitment observations

Finance users can select issued AWS commitment and CUR receipts from **Connections & quality → AWS commitment portfolio**. The API accepts receipt identifiers and a complete UTC measurement period; it resolves amounts and native terms from persisted evidence. A separate tenant-bound Go worker calls a private Python model and publishes an immutable result. Reopening the analysis reads that result rather than recalculating it in the browser.

The result preserves account, class, currency, region, native rate units and source references. It reports observed hourly Savings Plan utilization, unused commitment, partitioned native-rate concentration and expiry where the evidence supports them. Sparse Reserved Instance terms remain unavailable or unclassified. Billing for commitments absent from the current inventory stays visible separately. Signed native charges and allocated costs retain their distinct pricing bases.

Coverage, effective discounts, break-even utilization, remaining cash value, forecasts and purchase recommendations require further implementation and evidence. Their fields remain unavailable. This analysis grants no purchase, execution or savings-verification authority. The five optimization-order stages remain blocked until their separately issued decisions and outcomes exist.

## API

- `GET /v1/commitment-portfolio-sources` lists scoped sources.
- `GET /v1/commitment-portfolio-sources/{id}/receipts` pages the source's issued receipt selectors.
- `POST /v1/commitment-portfolio-analyses` queues an IDs-only request with `Idempotency-Key` and `If-Match: "0"`.
- `GET /v1/commitment-portfolio-analyses` returns a cursor-paginated history.
- `GET /v1/commitment-portfolio-analyses/{id}` returns the persisted request and result.

The OpenAPI contract defines the exact wire types. Finance and FinOps administrator access is tenant scoped. Changed input under an existing idempotency key conflicts. Source, credential and tenant authority are rechecked before publication; legacy evidence cannot become authoritative through this API.

## Optional installation

The `commitment-portfolio` Compose profile and Helm component default to disabled. Migration 039 creates the constrained NOLOGIN role and append-only tenant-isolated records; it does not commission a login or enable the worker.

For a local installation, set `COMMITMENT_PORTFOLIO_ENABLED=true`, the exact `COMMITMENT_PORTFOLIO_TENANT_ID`, and `COMMITMENT_PORTFOLIO_DATABASE_MODE=LOCAL_PRIVATE`, then run `node scripts/bootstrap-commitment-portfolio.mjs`. This only materializes private files under `work/private/commitment-portfolio-secrets`; it does not connect to the database or AWS. After migration 039, the database operator applies the private `commission.sql` through a secret-safe channel. The transaction binds the new login's actual PostgreSQL role OID to the tenant.

Start the profile's secret initializer, model and worker only after commissioning. The analyst receives its database credential and model token in a read-only volume. The model receives only its token. Neither receives cloud, signing, execution or financial-ledger credentials. Revocation appends to `commitment_portfolio_revocations`; existing signed scheduling restoration remains independent.

Hosted configuration additionally requires separate database and model CA bundles, verified database TLS, a private model certificate/key, distinct Secrets, and the rendered network policies. The model terminates TLS on 8443 behind its port-443 Service. Hosted runtime and authentic AWS acceptance remain separate commissioning gates. Provision no resources as part of local acceptance.

## Repeatable local acceptance

The `commitment-portfolio` job in [CI](../.github/workflows/ci.yaml) lists the exact pinned toolchain images and local image preparation. With these prerequisites prepared, run `node scripts/commitment-portfolio-lab.mjs` from a checkout whose reviewed changes are in the Git index. The fixed driver captures indexed source, creates owned disposable services and fresh module/build caches, and exercises provider-shaped native evidence through versioned objects, ClickHouse, the restricted daemon and real Keycloak Finance PKCE in the production console. The bounded receipt is written under `work/private/commitment-portfolio/<run-id>/receipt.json` after owned cleanup.

Cloud responses and financial history in this journey are visibly labelled fixtures. Real local databases, object storage, Python, worker processes, identity and browser transport are used. The acceptance does not establish authentic cloud provenance, genuine customer history, production operation or verified savings.
