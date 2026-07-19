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
USER nonroot
ENTRYPOINT ["/pam-server"]
