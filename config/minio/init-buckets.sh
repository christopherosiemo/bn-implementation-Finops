#!/bin/sh
set -eu

# This is a one-shot initializer. Never echo credentials or raw mc errors.
if [ -z "${MINIO_ROOT_USER:-}" ] || [ -z "${MINIO_ROOT_PASSWORD:-}" ] ||
   [ -z "${OBJECT_ACCESS_KEY:-}" ] || [ -z "${OBJECT_SECRET_KEY:-}" ] ||
   [ -z "${AUDIT_ACCESS_KEY:-}" ] || [ -z "${AUDIT_SECRET_KEY:-}" ]; then
  printf '%s\n' MINIO_CONFIGURATION_INVALID >&2
  exit 1
fi

ready=0
attempt=0
while [ "$attempt" -lt 12 ]; do
  attempt=$((attempt + 1))
  if timeout --signal=TERM --kill-after=1s 3s mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if [ "$attempt" -lt 12 ]; then sleep 2; fi
done
if [ "$ready" -ne 1 ]; then
  printf '%s\n' MINIO_READINESS_UNAVAILABLE >&2
  exit 1
fi

run_mc() {
  failure_code=$1
  shift
  if ! timeout --signal=TERM --kill-after=1s 15s mc "$@" >/dev/null 2>&1; then
    printf '%s\n' "$failure_code" >&2
    exit 1
  fi
}

run_mc MINIO_RAW_BUCKET_CREATE_FAILED mb --ignore-existing local/finops-raw
run_mc MINIO_RAW_VERSIONING_FAILED version enable local/finops-raw
run_mc MINIO_AUDIT_BUCKET_CREATE_FAILED mb --ignore-existing --with-lock local/finops-audit
run_mc MINIO_AUDIT_RETENTION_FAILED retention set --default GOVERNANCE 30d local/finops-audit
run_mc MINIO_RAW_POLICY_FAILED admin policy create local raw-writer /config/raw-policy.json
run_mc MINIO_RAW_USER_FAILED admin user add local "$OBJECT_ACCESS_KEY" "$OBJECT_SECRET_KEY"
run_mc MINIO_RAW_POLICY_ATTACH_FAILED admin policy attach local raw-writer --user "$OBJECT_ACCESS_KEY"
run_mc MINIO_AUDIT_POLICY_FAILED admin policy create local audit-writer /config/audit-policy.json
run_mc MINIO_AUDIT_USER_FAILED admin user add local "$AUDIT_ACCESS_KEY" "$AUDIT_SECRET_KEY"
run_mc MINIO_AUDIT_POLICY_ATTACH_FAILED admin policy attach local audit-writer --user "$AUDIT_ACCESS_KEY"
if [ -n "${ASSESSMENT_ACCESS_KEY:-}" ] || [ -n "${ASSESSMENT_SECRET_KEY:-}" ]; then
  if [ -z "${ASSESSMENT_ACCESS_KEY:-}" ] || [ -z "${ASSESSMENT_SECRET_KEY:-}" ] ||
     [ "$ASSESSMENT_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$ASSESSMENT_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$ASSESSMENT_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ]; then
    printf '%s\n' MINIO_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_ASSESSOR_POLICY_FAILED admin policy create local group-assessor /config/group-assessor-policy.json
  run_mc MINIO_ASSESSOR_USER_FAILED admin user add local "$ASSESSMENT_ACCESS_KEY" "$ASSESSMENT_SECRET_KEY"
  run_mc MINIO_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local group-assessor --user "$ASSESSMENT_ACCESS_KEY"
fi
if [ -n "${CAPACITY_ACCESS_KEY:-}" ] || [ -n "${CAPACITY_SECRET_KEY:-}" ]; then
  if [ -z "${CAPACITY_ACCESS_KEY:-}" ] || [ -z "${CAPACITY_SECRET_KEY:-}" ] ||
     [ "$CAPACITY_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$CAPACITY_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$CAPACITY_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ] ||
     [ "$CAPACITY_ACCESS_KEY" = "${ASSESSMENT_ACCESS_KEY:-}" ]; then
    printf '%s\n' MINIO_CAPACITY_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_CAPACITY_POLICY_FAILED admin policy create local group-capacity /config/group-assessor-policy.json
  run_mc MINIO_CAPACITY_USER_FAILED admin user add local "$CAPACITY_ACCESS_KEY" "$CAPACITY_SECRET_KEY"
  run_mc MINIO_CAPACITY_POLICY_ATTACH_FAILED admin policy attach local group-capacity --user "$CAPACITY_ACCESS_KEY"
fi
