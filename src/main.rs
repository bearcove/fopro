use color_eyre::eyre;
use futures_util::future::BoxFuture;
use hyper::{
    body::Body, server::conn, service::Service, upgrade::OnUpgrade, Method, Request, Response,
    StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{fmt::Debug, str::FromStr};
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

async fn handle_stream(stream: TcpStream) -> eyre::Result<()> {
    let stream = TokioIo::new(stream);
    let conn = conn::http1::Builder::new()
        .serve_connection(stream, ProxyService)
        .with_upgrades();
    conn.await?;
    Ok(())
}

struct ProxyService;

impl<ReqBody> Service<Request<ReqBody>> for ProxyService
where
    ReqBody: Body + Debug + Send + 'static,
{
    type Response = hyper::Response<String>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        Box::pin(async move {
            if req.method() != Method::CONNECT {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(String::from("we're a forward proxy, we only serve CONNECT"))
                    .unwrap());
            }

            tracing::trace!(
                "Got CONNECT to {}, headers = {:#?}",
                req.uri(),
                req.headers()
            );

            let on_upgrade = hyper::upgrade::on(req);
            tokio::spawn(async move {
                if let Err(e) = handle_upgraded_conn(on_upgrade).await {
                    tracing::error!("Error handling upgraded conn: {e:?}");
                }
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(String::from(
                    "you're connected, prepare to accept an invalid TLS cert because we're MITM'ing today"
                ))
                .unwrap())
        })
    }
}

async fn handle_upgraded_conn(on_upgrade: OnUpgrade) -> eyre::Result<()> {
    let c = on_upgrade.await.unwrap();
    let mut c = TokioIo::new(c);

    let mut buf = vec![0u8; 1024];
    let n = c.read(&mut buf).await?;
    let read_slice = &buf[..n];
    tracing::trace!("Read: {}", pretty_hex::pretty_hex(&read_slice));

    Ok(())
}
