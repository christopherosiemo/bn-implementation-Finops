# Pilot decisions and specification errata

The accepted implementation target is one complete AWS non-production scheduling loop, with a local fixture stack and opt-in AWS pilot infrastructure in Ireland (`eu-west-1`). It is not commercial GA. The original specification remains normative for the final product and is preserved unchanged.

## Architecture

Go control-plane modules share PostgreSQL transactions. Ingestion, signing, execution and workflow coordination run as separate processes and database identities. Only ingestion receives source-reading and evidence-storage credentials; only signer receives the private signing key; only executor receives customer mutation permissions. Python economics has no execution credentials. Analytics facts use ClickHouse and immutable raw/audit evidence uses S3-compatible storage. Temporal persists workflow progress. Kafka/Redis are deferred without changing domain contracts.

Local Keycloak is a development identity provider; hosted deployments use a configured OIDC issuer and JWKS. Keycloak's password grant is enabled only in the local fixture realm for automated acceptance. Browser login uses authorization code and PKCE; the access token stays in memory. No AWS resource change is authorized by creating a local demo account.

Hosted signing uses an Ed25519 key injected from an externally managed secret, encrypted with a dedicated KMS key. This is KMS encryption at rest, not a claim that AWS KMS performs Ed25519 signing. Cloud identities use STS and workload identity.

## Corrected examples

1. Section 200's signed inputs total **£840,000**: £700k usage + £150k commitment − £80k credit + £50k tax + £20k adjustment. A separate exact £1m fixture uses **£860k usage**. Credits keep their source sign.
2. Section 5's £241k − £174k is **£67k**. A £64.3k verified result requires a separate evidenced £2.7k adjustment; the product never invents it.
3. Hard SLO limits and baseline regression guards are independent constraints. The section 106 `max(SLO, baseline × 1.15)` expression must never permit a hard SLO breach.
4. Immutable ledger entries are corrected by append-only superseding revisions, not edits or deletion. Current totals exclude superseded revisions and duplicate resource/time claims.
5. Canonical lifecycle statuses carry separate `reason_code` values for stale, insufficient and blocked cases.

## Scheduling interpretation

The pilot supports standalone on-demand EBS-backed non-production EC2 only. Terraform ownership requires action-specific delegation of runtime stop/start; unknown authority blocks action. Instance-store devices, managed fleets, production, stop protection, unstable network identity and unresolved dependencies are excluded. On-demand is not proof of uncovered economics: RI/SP exposure must independently be known and absent for the pilot's positive savings claim.

Stop authorization expires independently of its restoration obligation. Freeze/pause, schedule expiry/deletion and stale policy cannot strand an instance previously stopped by that occurrence. An operator can explicitly take over recovery with an audit event. A manually stopped instance is never taken over by a schedule; a manually restarted instance is never stopped again by the same occurrence.

Schedules require a named timezone. DST may skip a nonexistent stop, never duplicate it; restoration moves earlier rather than later where needed. Default lead time is 15 minutes; missed stops more than 15 minutes late are skipped. Health requires application evidence as well as EC2 status. Infrastructure `running` is not application readiness.

## Economics interpretation

The first model compares calendar-matched idle windows over 14 complete baseline and verification days, using observed prior runtime and effective contracted compute prices. Running hours are the intervention, not a workload-output denominator. Observed zero activity is valid; absent activity observations are not zero. Non-idle or confounded work requires a richer model and cannot be verified by this pilot.

All source currencies remain separate. Retained storage/IP charges are visible but not claimed as savings; startup and incremental charges reduce the claim. Provider-final billing and reconciliation ≥99.5% gate verification. Annualized run-rate is an estimate separate from the verified period amount. A corrected bill can append a negative adjustment.
