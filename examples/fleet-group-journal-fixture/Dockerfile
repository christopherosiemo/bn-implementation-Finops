# Local, credential-free fixture tooling. No provider installation or cloud SDK.
FROM hashicorp/terraform:1.16.0@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e AS terraform
FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
COPY --from=terraform /bin/terraform /usr/local/bin/terraform
USER 10001:10001
