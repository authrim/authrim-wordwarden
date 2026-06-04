# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/wordwarden ./cmd/wordwarden

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/wordwarden /usr/local/bin/wordwarden

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/wordwarden"]
CMD ["serve"]
