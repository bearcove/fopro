w:
    just watch

watch:
    cargo watch -E RUST_LOG=info,fopro=info -s 'cargo run --release'

r:
    just run

run:
    RUST_LOG=trace cargo run
