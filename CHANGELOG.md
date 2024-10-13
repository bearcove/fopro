# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.3](https://github.com/bearcove/fopro/compare/v2.0.2...v2.0.3) - 2024-10-13

### Other

- cache requests with authorization

## [2.0.2](https://github.com/bearcove/fopro/compare/v2.0.1...v2.0.2) - 2024-10-13

### Other

- take _some_ headers into account when computing the cache key

## [2.0.1](https://github.com/bearcove/fopro/compare/v2.0.0...v2.0.1) - 2024-10-13

### Fixed

- Version cache

### Other

- Build with debug symbols (some)
- Don't constantly regenerate certs
- version the cache

## [2.0.0](https://github.com/bearcove/fopro/compare/v1.0.5...v2.0.0) - 2024-10-13

### Added

- [**breaking**] Add CLI args via argh

### Fixed

- show actual path the cert was written

### Other

- write to /tmp/ on non-windows I suppose
- too eager

## [1.0.5](https://github.com/bearcove/fopro/compare/v1.0.4...v1.0.5) - 2024-10-13

### Other

- use system temp dir, which hopefully fixes things on windows

## [1.0.4](https://github.com/bearcove/fopro/compare/v1.0.3...v1.0.4) - 2024-10-13

### Other

- Enable nodelay

## [1.0.3](https://github.com/bearcove/fopro/compare/v1.0.2...v1.0.3) - 2024-10-13

### Other

- Refine caching heuristics, support non-HTTPs requests

## [1.0.2](https://github.com/bearcove/fopro/compare/v1.0.1...v1.0.2) - 2024-10-13

### Added

- Dump CA cert to /tmp/fopro-ca.crt

## [1.0.1](https://github.com/bearcove/fopro/compare/v1.0.0...v1.0.1) - 2024-10-12

### Other

- update cargo-dist
- Set up cargo dist
- release

## [1.0.0](https://github.com/bearcove/fopro/releases/tag/v1.0.0) - 2024-10-12

### Other

- Add release-plz + test
- Add README
- In-memory cache layer
- add in-memory
- Only cache 200 actually
- don't panic
- Only cache 200
- Format better
- Show status/method
- Don't cache everything
- Different cache key strat
- Add on-disk caching
- debug++
- don't print broken pipe errors
- Proxy request bodies (makes POST work, which makes git clones over HTTPS work)
- Actually forward to upstream
- Proxy reqwests upstream, just missing roots..
- Service proxied requests (WIP)
- Negotiate TLS
- perform upgrade
- Dump incoming request
- Initial setup
- Initial release
