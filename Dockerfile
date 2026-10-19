# Build a static binary and ship it on a distroless, non-root base.
FROM golang:1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=0.4.0-dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/ManintheiCloud/Hardex.Version=${VERSION}" -o /hardex ./cmd/hardex

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /hardex /hardex
USER 65532:65532
ENTRYPOINT ["/hardex"]
