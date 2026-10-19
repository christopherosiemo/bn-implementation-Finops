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
if [ -n "${ASSESSMENT_ACCESS_KEY:-}" ] || [ -n "${ASSESSMENT_SECRET_KEY:-}" ]; then
  test -n "${ASSESSMENT_ACCESS_KEY:-}" && test -n "${ASSESSMENT_SECRET_KEY:-}"
  test "$ASSESSMENT_ACCESS_KEY" != "$MINIO_ROOT_USER"
  test "$ASSESSMENT_ACCESS_KEY" != "$OBJECT_ACCESS_KEY"
  test "$ASSESSMENT_ACCESS_KEY" != "$AUDIT_ACCESS_KEY"
  mc admin policy create local group-assessor /config/group-assessor-policy.json
  mc admin user add local "$ASSESSMENT_ACCESS_KEY" "$ASSESSMENT_SECRET_KEY"
  mc admin policy attach local group-assessor --user "$ASSESSMENT_ACCESS_KEY"
fi
if [ -n "${CAPACITY_ACCESS_KEY:-}" ] || [ -n "${CAPACITY_SECRET_KEY:-}" ]; then
  test -n "${CAPACITY_ACCESS_KEY:-}" && test -n "${CAPACITY_SECRET_KEY:-}"
  test "$CAPACITY_ACCESS_KEY" != "$MINIO_ROOT_USER"
  test "$CAPACITY_ACCESS_KEY" != "$OBJECT_ACCESS_KEY"
  test "$CAPACITY_ACCESS_KEY" != "$AUDIT_ACCESS_KEY"
  test "$CAPACITY_ACCESS_KEY" != "${ASSESSMENT_ACCESS_KEY:-}"
  mc admin policy create local group-capacity /config/group-assessor-policy.json
  mc admin user add local "$CAPACITY_ACCESS_KEY" "$CAPACITY_SECRET_KEY"
  mc admin policy attach local group-capacity --user "$CAPACITY_ACCESS_KEY"
fi
