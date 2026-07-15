<div align="center">
  <h1>RSHS</h1>
</div>

<div align="center">
  <h3>WebDAV, simplified</h3>
  <a href="https://github.com/mogeko/rshs/blob/master/docs/usage.md">Guide</a> •
  <a href="https://docs.rs/rshs">API&nbsp;Docs</a> •
  <a href="https://github.com/mogeko/rshs/blob/master/docs/benchmark-report.md">Benchmark</a> •
  <a href="https://github.com/mogeko/rshs/blob/master/docs/litmus-test-report.md">Litmus&nbsp;Test</a> •
  <a href="https://www.rfc-editor.org/info/rfc4918">RFC&nbsp;4918</a>
</div>

<br/>

<div align="center">

[![crates.io](https://img.shields.io/crates/v/rshs)](https://crates.io/crates/rshs)
[![Build & Test](https://github.com/mogeko/rshs/actions/workflows/build+test.yaml/badge.svg)](https://github.com/mogeko/rshs/actions/workflows/build+test.yaml)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

</div>

A WebDAV server that Just Works — zero config, [litmus 100%](./docs/litmus-test-report.md). Built in Rust for speed and correctness, packaged as a single Docker image for easy deployment.

## Features

- **Browser + WebDAV hybrid** — HTML directory listings for humans, WebDAV protocol for mounting (Finder, Explorer, davfs).
- **Fast and lightweight** — dispatch ~42µs (GET); 10MB read at 835 MiB/s, 1000-file directory listing in 1.7ms, PROPFIND 200 files in 1.1ms. [Full benchmark report](./docs/benchmark-report.md)
- **Zero config, [one command](#quick-start)** — no config files, daemons, or runtime dependencies beyond Docker. Just mount a volume and go.
- **Litmus 102/102** — full [RFC 4918 Class 2](https://www.rfc-editor.org/info/rfc4918) compliance: locks, copy/move, conditional `If` headers, dead properties. All five suites pass.
- **TLS + HTTP/2** — built-in HTTPS with automatic HTTP/2 negotiation.
- **Optional Basic Auth** — per-user credentials with persistent shadow files (SHA-512 crypt).
- **Optional Tailscale identity auth** — trust `tailscale serve`'s injected user headers instead of (or alongside) Basic Auth. No shared secrets, per-user access straight from your tailnet identity.

## Installation

```sh
docker pull docker.io/mogeko/rshs:latest
# or
docker pull ghcr.io/mogeko/rshs:latest
```

## Quick Start

```sh
# Serve ./data on port 8080
docker run --rm -p 8080:8080 -v ./data:/mnt/data mogeko/rshs

# With TLS (default port 8443)
docker run --rm -p 8443:8443 \
  -v ./certs:/certs -v ./data:/mnt/data \
  mogeko/rshs --tls-cert /certs/cert.pem --tls-key /certs/key.pem

# With authentication
docker run --rm -p 8080:8080 -v ./data:/mnt/data \
  mogeko/rshs --user admin:secret123
```

Open `http://localhost:8080` in a browser, or mount as WebDAV:

```sh
# Linux (davfs2)
sudo mount -t davfs http://localhost:8080 /mnt/webdav
# macOS (Finder)
Cmd+K → `http://localhost:8080`
# Windows (Explorer)
Map Network Drive → `http://localhost:8080`
```

## Documentation

| Document                             | Description                                      |
| ------------------------------------ | ------------------------------------------------ |
| [Usage Guide][usage-guide]           | Full usage, auth, shadow files, CLI              |
| [Tailscale Auth][tailscale-auth]     | Identity auth via `tailscale serve`, no passwords |
| [Docker Compose][docker-compose]     | Docker Compose deployment                        |
| [Podman Quadlet][podman-quadlet]     | Podman Quadlet deployment                        |
| [Kubernetes][kubernetes]             | K8s deployment, PVC, Ingress                     |
| [Benchmark Report][benchmark-report] | Performance benchmarks (56 benchmarks, 6 suites) |
| [Litmus Test Report][litmus-report]  | WebDAV conformance test results                  |

[usage-guide]: ./docs/usage.md
[tailscale-auth]: ./docs/tailscale-auth.md
[docker-compose]: ./docs/deploy-docker-compose.md
[podman-quadlet]: ./docs/deploy-podman-quadlet.md
[kubernetes]: ./docs/deploy-k8s.md
[benchmark-report]: ./docs/benchmark-report.md
[litmus-report]: ./docs/litmus-test-report.md

## Environment Variables

| Variable                            | Description                                           | Default   |
| ------------------------------------ | ----------------------------------------------------- | --------- |
| `RSHS_ROOT_DIR`                     | Root directory to serve                               | `.`       |
| `RSHS_HOST`                         | Bind address                                          | `0.0.0.0` |
| `RSHS_PORT`                         | Bind port (8080 plain, 8443 with TLS)                 | —         |
| `RSHS_TLS_CERT`                     | TLS certificate file path (PEM)                       | —         |
| `RSHS_TLS_KEY`                      | TLS private key file path (PEM)                       | —         |
| `RSHS_USERS`                        | `user:pass;...` auth pairs                            | —         |
| `RSHS_SHADOW_FILE`                  | Shadow file path                                      | —         |
| `RSHS_ACCEPT_TAILSCALE_SERVE_AUTH`  | `all` or comma-separated Tailscale logins to trust    | —         |
| `RSHS_TAILSCALE_USERS_FILE`         | File mapping Tailscale logins to access               | —         |
| `RSHS_LOCK_TIMEOUT`                 | Default WebDAV lock timeout in seconds (default: 300) | `300`     |
| `RSHS_LOG`                          | Log filter (e.g. `debug`, `rshs[status=500]=trace`)   | —         |
| `RSHS_LOG_STYLE`                    | Log output style                                      | `auto`    |

## License

MIT License. See [LICENSE](./LICENSE) for details.
