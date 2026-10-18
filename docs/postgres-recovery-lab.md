# Encrypted local PostgreSQL physical recovery lab

This lab checks a consistent physical backup and isolated database readback of
the running local fixture stack. It does not provision cloud resources, contact a
cloud provider, replace the running stack, resume Temporal workflows, or claim a
production RTO/RPO. Source application rows stay read-only and source workers
continue running. The only source data change is a uniquely named, test-owned
`local_recovery_sentinel_*` database, which is dropped after acceptance.

Run from the repository:

```sh
node --test scripts/tests/encrypted-backup.test.mjs scripts/tests/postgres-recovery-lab.test.mjs
node scripts/postgres-recovery-lab.mjs
```

The lab accepts no source, destination, credentials or remote-target arguments.
It resolves this repository's running Compose `postgres` and `api` containers,
checks their exact workspace/project/service labels, requires API fixture mode,
and refuses remote Docker endpoints. It requires a local PostgreSQL 17 primary,
full-page WAL writes, a replication-capable local user and no extra tablespaces.
Local Unix-socket authentication is used inside the existing container; database
passwords and role password hashes are never printed or copied into arguments.

The native command uses `pg_basebackup --format=tar --pgdata=-
--wal-method=fetch --checkpoint=fast --max-rate=64M
--manifest-checksums=SHA256`. It backs up the whole PostgreSQL cluster, including
the application, Temporal and visibility databases. WAL is included for a
standalone recovery. Fetch mode fails if required WAL is recycled before transfer;
this lab does not alter source WAL retention or retry an unusable archive as
successful. A fast checkpoint and bounded backup still add local I/O/CPU load.

Native tar bytes stream through gzip and AES-256-GCM into an exclusively created
encrypted partial file. A final archive is published only after both encryption
and the native backup process succeed. No plaintext database archive is written
to the host. The encrypted format authenticates its version/nonce header and the
whole compressed archive, enforces 8 GiB encrypted/16 GiB decoded bounds, and
retains an open descriptor across authentication and recovery. In-place file
changes are rejected. The consumer aborts on any second-pass or extraction error.

The restore consumer is created after complete authentication. It extracts only
into a randomly named, labelled Docker volume under an unprivileged PostgreSQL
UID. The exact source image ID is reused with image pulling disabled. Native
`pg_verifybackup` validates the manifest, file checksums and required WAL parsing
before PostgreSQL starts; checksum/WAL validation is not skipped. Any failure
keeps the destination quarantined and cannot yield successful acceptance.

The recovered server has no network and no published ports, a read-only root
filesystem, a single owned data volume, a temporary socket directory and no cloud
credentials. It listens on a container-local Unix socket only. Archive/restore
commands, upstream replication connection, preload libraries, logical workers,
parallel workers and autovacuum are disabled for the isolated readback. No API,
signer, executor, ingester or Temporal service connects to the recovered cluster.
Application readback runs with default read-only transactions. Sentinel-only
guard checks deliberately attempt writes inside a rolled-back transaction.

Acceptance compares existing application audit/ledger/signed-envelope rows and
stable completed provider-operation rows by SHA-256. It also checks migration
checksums, table/role grants, forced RLS, policies, immutable triggers and indexes.
The restored Temporal databases must retain their schema-version readback. Under
the restored restricted API role, the sentinel proves exact decimal storage,
cross-tenant isolation, append-only UPDATE/DELETE denial, and unique active stop
intent enforcement. The lab does not replay a stop, consume restoration authority,
change an application ledger row or create a new signing/execution envelope.

Only run-labelled containers/volumes with the exact source label may be cleaned.
The sentinel database's exact run comment must match before dropping it. The main
stack and its volumes are never removed. Successful runs retain encrypted
archives, separate binary key files and an acceptance record under ignored
`work/private/postgres-recovery/<run-id>/`. Files use mode 0600 and directories
0700; Windows additionally removes inherited directory access and grants the
current account access. Do not upload these files. The restored temporary volume
contains plaintext database files during the lab and is removed afterward; this
does not establish encrypted disks or production key-management separation.

The retained key and archive are on the same local machine, in separate private
directories. That is useful for a repeatable engineering readback and is not a
production backup custody, rotation, retention, escrow or disaster-site design.
An abrupt host/daemon termination can interrupt cleanup; inspect only the exact
recorded run-labelled resources before removing leftovers. Never use broad volume
pruning as recovery-lab cleanup.

The private acceptance record contains only hashes, counts, flags, timings and
relative artifact paths. It contains no raw database rows, SQL dump, signatures,
passwords or recovery key. Recorded engineering timings do not establish a
production recovery objective. Temporal workflow resumption, application service
reconnection, coordinated S3/ClickHouse recovery, regional failover, point-in-time
recovery and customer commissioning remain separate acceptance work.

Primary references: [PostgreSQL 17 pg_basebackup](https://www.postgresql.org/docs/17/app-pgbasebackup.html)
and [pg_verifybackup](https://www.postgresql.org/docs/17/app-pgverifybackup.html).

## Recorded local acceptance, 18 October 2026

The focused safeguard suite passed 6 tests. The actual PostgreSQL 17.11 lab
passed all 8 checks against the running local fixture stack. It retained a
158,717,788-byte encrypted archive and matched 16 existing rows each from audit,
savings ledger, signed plans and completed provider operations. Temporal and
visibility schema readback covered 36 and 3 tables respectively. All run-owned
containers, the recovery volume and the source sentinel database were removed.

The recorded engineering run took about 78 seconds through backup publication,
11 seconds for offline manifest/WAL verification and 298 seconds overall,
including local Docker and readback overhead. These values are one local test
observation, with no production RTO, RPO, workflow-resume or whole-system recovery
claim. The detailed acceptance record remains private beside the retained
encrypted artifacts and is excluded from version control.
