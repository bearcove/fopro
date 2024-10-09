w:
    just watch

watch:
    cargo watch -E RUST_LOG=info,fopro=trace -x run

r:
    just run

run:
    RUST_LOG=trace cargo run
