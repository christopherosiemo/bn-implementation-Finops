# Only a credential-free source snapshot enters this local tooling image.
FROM hashicorp/terraform:1.16.0@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e AS terraform
FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
WORKDIR /src
ENV GOTOOLCHAIN=local GOMAXPROCS=1
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked go mod download
COPY internal ./internal
COPY cmd/group-fixture-commission ./cmd/group-fixture-commission
COPY cmd/group-fixture-preparer ./cmd/group-fixture-preparer
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked --mount=type=cache,target=/root/.cache/go-build,sharing=locked CGO_ENABLED=0 go build -p 1 -trimpath -ldflags="-s -w" -o /compiled/commission ./cmd/group-fixture-commission && CGO_ENABLED=0 go build -p 1 -trimpath -ldflags="-s -w" -o /compiled/preparer ./cmd/group-fixture-preparer
COPY --from=terraform /bin/terraform /usr/local/bin/terraform
USER 10001:10001
WORKDIR /tmp
CMD []
