FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pam-server ./cmd/pam-server

# Distroless, static, non-root: minimal attack surface for a credential vault.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pam-server /pam-server
EXPOSE 8080 2222
# Numeric UID (distroless nonroot = 65532) so Kubernetes runAsNonRoot can verify
# the container is non-root without resolving a username.
USER 65532:65532
# Distroless has no shell/curl, so probe via the binary's own -healthcheck flag.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
	CMD ["/pam-server", "-healthcheck"]
ENTRYPOINT ["/pam-server"]
