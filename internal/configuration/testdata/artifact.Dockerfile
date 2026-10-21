# Isolated acceptance tooling only. The collector never invokes init/plan/apply.
FROM hashicorp/terraform:1.16.0@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e AS terraform
FROM golang:1.27.3-bookworm@sha256:32fa283222e2905d9fee971f60c842e5c815fdc036cf7ea599bf36bd7ca8f67f
COPY --from=terraform /bin/terraform /usr/local/bin/terraform
