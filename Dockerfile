# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/kuberoam/roam-gate/internal/server.Version=${VERSION}" \
    -o /out/roam-gate ./cmd/roam-gate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/roam-gate /roam-gate
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/roam-gate"]
