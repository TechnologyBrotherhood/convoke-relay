# syntax=docker/dockerfile:1

# The protocol's own tests (crypto, session state machines) gate the image: the final
# stage copies this stage's marker, so the image can't be built without them passing.
FROM node:24-slim AS protocol-tests
WORKDIR /src
COPY protocol protocol
COPY test/crypto.test.ts test/session.test.ts test/
RUN node --test test/crypto.test.ts test/session.test.ts && touch /tests-passed

# Relay: a static Go binary.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relay .
# An empty /data owned by the relay user: docker copies that ownership into a new named
# volume mounted there (Kubernetes chowns its volume in an init container instead).
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relay /relay
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=protocol-tests /tests-passed /tests-passed
# No web client (pairing and use are iPhone-only): just a page that hands a pairing
# link opened in a browser to the app.
COPY web/index.html web/pair.js web/pair.css /web/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/relay", "-addr", ":8080", "-data", "/data", "-web", "/web"]
