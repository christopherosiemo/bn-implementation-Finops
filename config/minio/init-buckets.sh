#!/bin/sh
set -eu
until mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1; do sleep 2; done
mc mb --ignore-existing local/finops-raw
mc version enable local/finops-raw
mc mb --ignore-existing --with-lock local/finops-audit
mc retention set --default GOVERNANCE 30d local/finops-audit
mc admin policy create local raw-writer /config/raw-policy.json
mc admin user add local "$OBJECT_ACCESS_KEY" "$OBJECT_SECRET_KEY"
mc admin policy attach local raw-writer --user "$OBJECT_ACCESS_KEY"
mc admin policy create local audit-writer /config/audit-policy.json
mc admin user add local "$AUDIT_ACCESS_KEY" "$AUDIT_SECRET_KEY"
mc admin policy attach local audit-writer --user "$AUDIT_ACCESS_KEY"
