[![license: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![crates.io](https://img.shields.io/crates/v/fopro.svg)](https://crates.io/crates/fopro)
[![docs.rs](https://docs.rs/fopro/badge.svg)](https://docs.rs/fopro)

# fopro

An proof-of-concept(TM) caching HTTP forward proxy

Limitations:

  * Will only accept to negotiate http/2 over TLS (via CONNECT) right now
  * Will serve self-signed certificates, no way to export a CA cert so it
    can be "installed" on whichever client talks to it right now
  * Very naive rules to decide if something is cachable (see sources)
    specifically, fopro DOES NOT RESPECT CACHE-CONTROL, VARY, ETC.
  * Really you shouldn't use fopro, it currently does the bare minimum
    to get _most_ of the [uv](https://github.com/astral-sh/uv) test suite passing.
