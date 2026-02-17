# tor-go

A Tor client implementation in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cvsouth/tor-go.svg)](https://pkg.go.dev/github.com/cvsouth/tor-go)
[![Test](https://github.com/cvsouth/tor-go/actions/workflows/test.yml/badge.svg)](https://github.com/cvsouth/tor-go/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/cvsouth/tor-go)](https://goreportcard.com/report/github.com/cvsouth/tor-go)

## Features

- Tor v3 client protocol (link handshake, circuit building, stream multiplexing)
- 3-hop onion-routed circuits with ntor key exchange
- v3 onion service client (.onion address resolution and connection)
- SOCKS5 proxy server for transparent traffic routing
- Directory authority consensus fetching with cryptographic signature validation
- Bandwidth-weighted relay selection (guard, middle, exit)
- Minimal dependencies — only `golang.org/x/crypto` and `filippo.io/edwards25519`

## Quick Start

```sh
go run github.com/cvsouth/tor-go/cmd/tor-client@latest
```

In another terminal:

```sh
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"..."}
```

## Installation

```sh
go get github.com/cvsouth/tor-go
```

## Documentation

See the [API reference on pkg.go.dev](https://pkg.go.dev/github.com/cvsouth/tor-go) and [`cmd/tor-client`](cmd/tor-client) for a complete working example.

## Security

To report a security vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
