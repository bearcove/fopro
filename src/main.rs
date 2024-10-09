use color_eyre::eyre;
use std::str::FromStr;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

use tracing_subscriber::{
    filter::Targets, layer::SubscriberExt, util::SubscriberInitExt, Layer, Registry,
};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let rust_log_var = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let log_filter = Targets::from_str(&rust_log_var)?;

    Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_filter(log_filter),
        )
        .init();
    tracing::debug!("Debug logging is enabled");

    let host = "127.0.0.1";
    let port = 8080;

    let ln = TcpListener::bind(format!("{host}:{port}")).await?;
    tracing::info!("Listening on {host}:{port}");

    while let Ok((stream, remote_addr)) = ln.accept().await {
        tracing::debug!("Accepted connection from {remote_addr}");
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream).await {
                tracing::error!("Error handling stream: {e}")
            }
        });
    }

    Ok(())
}

async fn handle_stream(mut stream: TcpStream) -> eyre::Result<()> {
    let mut buf = vec![0; 1024];
    let n = stream.read(&mut buf).await?;
    let read_slice = &buf[..n];
    tracing::debug!("Received:\n{}", pretty_hex::pretty_hex(&read_slice));

    eyre::bail!("Not implemented");
}
