# Multi-architecture image: the binary is cross-compiled on the build
# platform (no emulation) and shipped on a distroless, non-root base. Both
# base images are pinned by digest; Dependabot proposes digest updates.
FROM --platform=$BUILDPLATFORM golang:1@sha256:957861185dbf29d93668ace41e011d091c6e779953d47f0316ef2cc58e28fe2b AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.10.4-dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X github.com/ManintheiCloud/Hardex.Version=${VERSION}" -o /hardex ./cmd/hardex

FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087
LABEL org.opencontainers.image.source="https://github.com/ManintheiCloud/Hardex" \
      org.opencontainers.image.description="Hardex: Kubernetes security hardening" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /hardex /hardex
USER 65532:65532
ENTRYPOINT ["/hardex"]
