#!/bin/sh
set -eu

mode=${1:-all}
if [ "$#" -gt 1 ] || { [ "$mode" != all ] && [ "$mode" != lambda-performance-only ] && [ "$mode" != service-assessor-only ]; }; then
  printf '%s\n' MINIO_INITIALIZER_MODE_INVALID >&2
  exit 1
fi
# This is a one-shot initializer. Never echo credentials or raw mc errors.
if [ -z "${MINIO_ROOT_USER:-}" ] || [ -z "${MINIO_ROOT_PASSWORD:-}" ]; then
  printf '%s\n' MINIO_CONFIGURATION_INVALID >&2
  exit 1
fi
if [ "$mode" = all ] && { [ -z "${OBJECT_ACCESS_KEY:-}" ] || [ -z "${OBJECT_SECRET_KEY:-}" ] || [ -z "${AUDIT_ACCESS_KEY:-}" ] || [ -z "${AUDIT_SECRET_KEY:-}" ]; }; then
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

commission_lambda_performance() {
  if [ -z "${LAMBDA_PERFORMANCE_ACCESS_KEY:-}" ] || [ -z "${LAMBDA_PERFORMANCE_SECRET_KEY:-}" ]; then
    printf '%s\n' MINIO_LAMBDA_PERFORMANCE_CONFIGURATION_INVALID >&2
    exit 1
  fi
  for other in "$MINIO_ROOT_USER" "${OBJECT_ACCESS_KEY:-}" "${AUDIT_ACCESS_KEY:-}" "${ASSESSMENT_ACCESS_KEY:-}" "${CAPACITY_ACCESS_KEY:-}" "${DATABASE_ASSESSOR_ACCESS_KEY:-}" "${STORAGE_ASSESSOR_ACCESS_KEY:-}" "${OBJECT_STORAGE_ASSESSOR_ACCESS_KEY:-}" "${NETWORK_ASSESSOR_ACCESS_KEY:-}" "${LAMBDA_ASSESSOR_ACCESS_KEY:-}" "${SERVICE_ASSESSOR_ACCESS_KEY:-}"; do
    if [ "$LAMBDA_PERFORMANCE_ACCESS_KEY" = "$other" ]; then
      printf '%s\n' MINIO_LAMBDA_PERFORMANCE_CONFIGURATION_INVALID >&2
      exit 1
    fi
  done
  run_mc MINIO_LAMBDA_PERFORMANCE_POLICY_FAILED admin policy create local lambda-performance /config/lambda-performance-policy.json
  run_mc MINIO_LAMBDA_PERFORMANCE_USER_FAILED admin user add local "$LAMBDA_PERFORMANCE_ACCESS_KEY" "$LAMBDA_PERFORMANCE_SECRET_KEY"
  run_mc MINIO_LAMBDA_PERFORMANCE_POLICY_ATTACH_FAILED admin policy attach local lambda-performance --user "$LAMBDA_PERFORMANCE_ACCESS_KEY"
}
commission_service_assessor() {
  if [ -z "${SERVICE_ASSESSOR_ACCESS_KEY:-}" ] || [ -z "${SERVICE_ASSESSOR_SECRET_KEY:-}" ]; then
    printf '%s\n' MINIO_SERVICE_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  for other in "$MINIO_ROOT_USER" "${OBJECT_ACCESS_KEY:-}" "${AUDIT_ACCESS_KEY:-}" "${ASSESSMENT_ACCESS_KEY:-}" "${CAPACITY_ACCESS_KEY:-}" "${DATABASE_ASSESSOR_ACCESS_KEY:-}" "${STORAGE_ASSESSOR_ACCESS_KEY:-}" "${OBJECT_STORAGE_ASSESSOR_ACCESS_KEY:-}" "${NETWORK_ASSESSOR_ACCESS_KEY:-}" "${LAMBDA_ASSESSOR_ACCESS_KEY:-}" "${LAMBDA_PERFORMANCE_ACCESS_KEY:-}"; do
    if [ "$SERVICE_ASSESSOR_ACCESS_KEY" = "$other" ]; then
      printf '%s\n' MINIO_SERVICE_ASSESSOR_CONFIGURATION_INVALID >&2
      exit 1
    fi
  done
  run_mc MINIO_SERVICE_ASSESSOR_POLICY_FAILED admin policy create local aws-service-assessor /config/group-assessor-policy.json
  run_mc MINIO_SERVICE_ASSESSOR_USER_FAILED admin user add local "$SERVICE_ASSESSOR_ACCESS_KEY" "$SERVICE_ASSESSOR_SECRET_KEY"
  run_mc MINIO_SERVICE_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local aws-service-assessor --user "$SERVICE_ASSESSOR_ACCESS_KEY"
}
if [ "$mode" = lambda-performance-only ]; then
  # Existing stores and all unrelated identities remain untouched.
  commission_lambda_performance
  exit 0
fi
if [ "$mode" = service-assessor-only ]; then
  commission_service_assessor
  exit 0
fi

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

if [ -n "${DATABASE_ASSESSOR_ACCESS_KEY:-}" ] || [ -n "${DATABASE_ASSESSOR_SECRET_KEY:-}" ]; then
  if [ -z "${DATABASE_ASSESSOR_ACCESS_KEY:-}" ] || [ -z "${DATABASE_ASSESSOR_SECRET_KEY:-}" ] ||
     [ "$DATABASE_ASSESSOR_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$DATABASE_ASSESSOR_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$DATABASE_ASSESSOR_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ] ||
     [ "$DATABASE_ASSESSOR_ACCESS_KEY" = "${ASSESSMENT_ACCESS_KEY:-}" ] ||
     [ "$DATABASE_ASSESSOR_ACCESS_KEY" = "${CAPACITY_ACCESS_KEY:-}" ]; then
    printf '%s\n' MINIO_DATABASE_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_DATABASE_ASSESSOR_POLICY_FAILED admin policy create local database-assessor /config/group-assessor-policy.json
  run_mc MINIO_DATABASE_ASSESSOR_USER_FAILED admin user add local "$DATABASE_ASSESSOR_ACCESS_KEY" "$DATABASE_ASSESSOR_SECRET_KEY"
  run_mc MINIO_DATABASE_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local database-assessor --user "$DATABASE_ASSESSOR_ACCESS_KEY"
fi

if [ -n "${STORAGE_ASSESSOR_ACCESS_KEY:-}" ] || [ -n "${STORAGE_ASSESSOR_SECRET_KEY:-}" ]; then
  if [ -z "${STORAGE_ASSESSOR_ACCESS_KEY:-}" ] || [ -z "${STORAGE_ASSESSOR_SECRET_KEY:-}" ] ||
     [ "$STORAGE_ASSESSOR_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$STORAGE_ASSESSOR_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$STORAGE_ASSESSOR_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ] ||
     [ "$STORAGE_ASSESSOR_ACCESS_KEY" = "${ASSESSMENT_ACCESS_KEY:-}" ] ||
     [ "$STORAGE_ASSESSOR_ACCESS_KEY" = "${CAPACITY_ACCESS_KEY:-}" ] ||
     [ "$STORAGE_ASSESSOR_ACCESS_KEY" = "${DATABASE_ASSESSOR_ACCESS_KEY:-}" ]; then
    printf '%s\n' MINIO_STORAGE_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_STORAGE_ASSESSOR_POLICY_FAILED admin policy create local storage-assessor /config/group-assessor-policy.json
  run_mc MINIO_STORAGE_ASSESSOR_USER_FAILED admin user add local "$STORAGE_ASSESSOR_ACCESS_KEY" "$STORAGE_ASSESSOR_SECRET_KEY"
  run_mc MINIO_STORAGE_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local storage-assessor --user "$STORAGE_ASSESSOR_ACCESS_KEY"
fi

if [ -n "${OBJECT_STORAGE_ASSESSOR_ACCESS_KEY:-}" ] || [ -n "${OBJECT_STORAGE_ASSESSOR_SECRET_KEY:-}" ]; then
  if [ -z "${OBJECT_STORAGE_ASSESSOR_ACCESS_KEY:-}" ] || [ -z "${OBJECT_STORAGE_ASSESSOR_SECRET_KEY:-}" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "${ASSESSMENT_ACCESS_KEY:-}" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "${CAPACITY_ACCESS_KEY:-}" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "${DATABASE_ASSESSOR_ACCESS_KEY:-}" ] ||
     [ "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" = "${STORAGE_ASSESSOR_ACCESS_KEY:-}" ]; then
    printf '%s\n' MINIO_OBJECT_STORAGE_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_OBJECT_STORAGE_ASSESSOR_POLICY_FAILED admin policy create local object-storage-assessor /config/group-assessor-policy.json
  run_mc MINIO_OBJECT_STORAGE_ASSESSOR_USER_FAILED admin user add local "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY" "$OBJECT_STORAGE_ASSESSOR_SECRET_KEY"
  run_mc MINIO_OBJECT_STORAGE_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local object-storage-assessor --user "$OBJECT_STORAGE_ASSESSOR_ACCESS_KEY"
fi

if [ -n "${NETWORK_ASSESSOR_ACCESS_KEY:-}" ] || [ -n "${NETWORK_ASSESSOR_SECRET_KEY:-}" ]; then
  if [ -z "${NETWORK_ASSESSOR_ACCESS_KEY:-}" ] || [ -z "${NETWORK_ASSESSOR_SECRET_KEY:-}" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "${ASSESSMENT_ACCESS_KEY:-}" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "${CAPACITY_ACCESS_KEY:-}" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "${DATABASE_ASSESSOR_ACCESS_KEY:-}" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "${STORAGE_ASSESSOR_ACCESS_KEY:-}" ] ||
     [ "$NETWORK_ASSESSOR_ACCESS_KEY" = "${OBJECT_STORAGE_ASSESSOR_ACCESS_KEY:-}" ]; then
    printf '%s\n' MINIO_NETWORK_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_NETWORK_ASSESSOR_POLICY_FAILED admin policy create local network-assessor /config/group-assessor-policy.json
  run_mc MINIO_NETWORK_ASSESSOR_USER_FAILED admin user add local "$NETWORK_ASSESSOR_ACCESS_KEY" "$NETWORK_ASSESSOR_SECRET_KEY"
  run_mc MINIO_NETWORK_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local network-assessor --user "$NETWORK_ASSESSOR_ACCESS_KEY"
fi

if [ -n "${LAMBDA_ASSESSOR_ACCESS_KEY:-}" ] || [ -n "${LAMBDA_ASSESSOR_SECRET_KEY:-}" ]; then
  if [ -z "${LAMBDA_ASSESSOR_ACCESS_KEY:-}" ] || [ -z "${LAMBDA_ASSESSOR_SECRET_KEY:-}" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "$MINIO_ROOT_USER" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "$OBJECT_ACCESS_KEY" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "$AUDIT_ACCESS_KEY" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "${ASSESSMENT_ACCESS_KEY:-}" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "${CAPACITY_ACCESS_KEY:-}" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "${DATABASE_ASSESSOR_ACCESS_KEY:-}" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "${STORAGE_ASSESSOR_ACCESS_KEY:-}" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "${OBJECT_STORAGE_ASSESSOR_ACCESS_KEY:-}" ] ||
     [ "$LAMBDA_ASSESSOR_ACCESS_KEY" = "${NETWORK_ASSESSOR_ACCESS_KEY:-}" ]; then
    printf '%s\n' MINIO_LAMBDA_ASSESSOR_CONFIGURATION_INVALID >&2
    exit 1
  fi
  run_mc MINIO_LAMBDA_ASSESSOR_POLICY_FAILED admin policy create local lambda-assessor /config/group-assessor-policy.json
  run_mc MINIO_LAMBDA_ASSESSOR_USER_FAILED admin user add local "$LAMBDA_ASSESSOR_ACCESS_KEY" "$LAMBDA_ASSESSOR_SECRET_KEY"
  run_mc MINIO_LAMBDA_ASSESSOR_POLICY_ATTACH_FAILED admin policy attach local lambda-assessor --user "$LAMBDA_ASSESSOR_ACCESS_KEY"
fi

if [ -n "${SERVICE_ASSESSOR_ACCESS_KEY:-}" ] || [ -n "${SERVICE_ASSESSOR_SECRET_KEY:-}" ]; then
  commission_service_assessor
fi

# Independent machine ingress has no source-reader or analytical credentials.
if [ -n "${LAMBDA_PERFORMANCE_ACCESS_KEY:-}" ] || [ -n "${LAMBDA_PERFORMANCE_SECRET_KEY:-}" ]; then
  commission_lambda_performance
fi
