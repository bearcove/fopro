[![license: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![crates.io](https://img.shields.io/crates/v/fopro.svg)](https://crates.io/crates/fopro)
[![docs.rs](https://docs.rs/fopro/badge.svg)](https://docs.rs/fopro)

# fopro

An proof-of-concept(TM) caching HTTP forward proxy

## Limitations

  * Will only accept to negotiate http/2 over TLS (via CONNECT) right now
  * Very naive rules to decide if something is cachable (see sources)
    specifically, **fopro DOES NOT RESPECT `cache-control`, `vary`, ETC**.
  * The cache is boundless (both in memory and on disk)
  * Responses are buffered in memory completely before being proxied
    (instead of being streamed)
  * Partial responses (HTTP 206) are not cached at all.
  * Really you shouldn't use fopro, it currently does the bare minimum
    to get _most_ of the [uv](https://github.com/astral-sh/uv) test suite passing.

## Features

  * Supports `CONNECT` requests
  * Caches 200 responses in memory and on-disk
