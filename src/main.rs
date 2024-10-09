use color_eyre::eyre;
use std::str::FromStr;

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
    tracing::info!("Starting server on {host}:{port}");

    Ok(())
}
