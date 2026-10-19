# Multi-architecture image: the binary is cross-compiled on the build
# platform (no emulation) and shipped on a distroless, non-root base.
FROM --platform=$BUILDPLATFORM golang:1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.8.4-dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X github.com/ManintheiCloud/Hardex.Version=${VERSION}" -o /hardex ./cmd/hardex

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/ManintheiCloud/Hardex" \
      org.opencontainers.image.description="Hardex: Kubernetes security hardening" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /hardex /hardex
USER 65532:65532
ENTRYPOINT ["/hardex"]
