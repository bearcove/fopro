use color_eyre::eyre;
use futures_util::future::BoxFuture;
use http_body_util::Full;
use hyper::{
    body::{Body, Bytes},
    server::conn,
    service::Service,
    upgrade::OnUpgrade,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{fmt::Debug, str::FromStr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{pki_types::PrivateKeyDer, ServerConfig};

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
        .serve_connection(stream, UpgradeService)
        .with_upgrades();
    conn.await?;
    Ok(())
}

struct UpgradeService;

impl<ReqBody> Service<Request<ReqBody>> for UpgradeService
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

            let uri = req.uri().clone();
            tracing::trace!("Got CONNECT to {uri}, headers = {:#?}", req.headers());

            let on_upgrade = hyper::upgrade::on(req);
            tokio::spawn(async move {
                if let Err(e) = handle_upgraded_conn(uri, on_upgrade).await {
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

async fn handle_upgraded_conn(uri: Uri, on_upgrade: OnUpgrade) -> eyre::Result<()> {
    let c = on_upgrade.await.unwrap();
    let c = TokioIo::new(c);

    let host: String = uri
        .host()
        .ok_or_else(|| eyre::eyre!("expected host in CONNECT request"))?
        .to_string();
    let cert_key = rcgen::generate_simple_self_signed([host.clone()])?;

    let mut server_conf = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_key.cert.into()],
            PrivateKeyDer::Pkcs8(cert_key.key_pair.serialize_der().into()),
        )?;
    server_conf.alpn_protocols.push(b"h2".to_vec());

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_conf));
    let tls_stream = acceptor.accept(c).await?;

    {
        let (_stream, server_conn) = tls_stream.get_ref();

        tracing::trace!(
            "Negotiated TLS session, ALPN proto:\n{}",
            pretty_hex::pretty_hex(&server_conn.alpn_protocol().unwrap_or_default())
        );
    }

    let service = ProxyService { host };
    let conn = conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls_stream), service);
    conn.await?;

    Ok(())
}

struct ProxyService {
    // the host we're proxying to, e.g. `pypi.org`
    host: String,
}

impl<ReqBody> Service<Request<ReqBody>> for ProxyService
where
    ReqBody: Body + Debug + Send + 'static,
{
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let host = self.host.clone();

        Box::pin(async move {
            let uri = req.uri().clone();
            tracing::trace!(%host, %uri, "Should proxy request");

            Ok(Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Bytes::new().into())
                .unwrap())
        })
    }
}
