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
use std::{fmt::Debug, str::FromStr, sync::Arc, time::Instant};
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

    let client = reqwest::Client::builder()
        .no_proxy()
        .use_rustls_tls()
        .user_agent("fopro/1.0 — https://github.com/bearcove/fopro")
        .build()?;
    let service = UpgradeService { client };

    while let Ok((stream, remote_addr)) = ln.accept().await {
        tracing::debug!("Accepted connection from {remote_addr}");
        let service = service.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream, service).await {
                tracing::error!("Error handling stream: {e}")
            }
        });
    }

    Ok(())
}

async fn handle_stream(stream: TcpStream, service: UpgradeService) -> eyre::Result<()> {
    let stream = TokioIo::new(stream);
    let conn = conn::http1::Builder::new()
        .serve_connection(stream, service)
        .with_upgrades();
    conn.await?;
    Ok(())
}

#[derive(Clone)]
struct UpgradeService {
    client: reqwest::Client,
}

impl<ReqBody> Service<Request<ReqBody>> for UpgradeService
where
    ReqBody: Body + Debug + Send + 'static,
{
    type Response = hyper::Response<String>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let client = self.client.clone();

        Box::pin(async move {
            if req.method() != Method::CONNECT {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(String::from("we're a forward proxy, we only serve CONNECT"))
                    .unwrap());
            }

            let uri = req.uri().clone();
            tracing::trace!("Got CONNECT to {uri}, headers = {:#?}", req.headers());

            let host = match uri.host() {
                Some(host) => host.to_string(),
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(String::from("expected host in CONNECT request"))
                        .unwrap())
                }
            };
            let settings = ProxySettings { host, client };

            let on_upgrade = hyper::upgrade::on(req);
            tokio::spawn(async move {
                if let Err(e) = handle_upgraded_conn(uri, on_upgrade, settings).await {
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

async fn handle_upgraded_conn(
    uri: Uri,
    on_upgrade: OnUpgrade,
    settings: ProxySettings,
) -> eyre::Result<()> {
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

    let service = ProxyService { settings };
    let conn = conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls_stream), service);
    match conn.await {
        Ok(_) => (),
        Err(e) if e.to_string().contains("broken pipe") => {
            tracing::debug!("Connection closed (broken pipe): {}", e);
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

#[derive(Clone)]
struct ProxySettings {
    /// the host we're proxying to, e.g. `pypi.org`
    host: String,

    /// the shared reqwest client for upstream
    client: reqwest::Client,
}

impl std::fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySettings")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct ProxyService {
    settings: ProxySettings,
}

impl<ReqBody> Service<Request<ReqBody>> for ProxyService
where
    ReqBody: Body + Send + Sync + Debug + 'static,
    <ReqBody as Body>::Data: Into<Bytes>,
    <ReqBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let settings = self.settings.clone();

        Box::pin(async move {
            match proxy_request(req, settings).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    tracing::error!("Error proxying request: {e}");
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Bytes::copy_from_slice(format!("{e}").as_bytes()).into())
                        .unwrap())
                }
            }
        })
    }
}

async fn proxy_request<ReqBody>(
    req: Request<ReqBody>,
    settings: ProxySettings,
) -> Result<Response<Full<Bytes>>, eyre::Error>
where
    ReqBody: Body + Send + Sync + Debug + 'static,
    <ReqBody as Body>::Data: Into<Bytes>,
    <ReqBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let uri = req.uri().clone();
    tracing::trace!(?settings, %uri, "Should proxy request");

    let uri_host = uri
        .host()
        .ok_or_else(|| eyre::eyre!("expected host in CONNECT request"))?;

    if uri_host != settings.host {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(
                Bytes::copy_from_slice(
                    format!("expected host {settings:?}, got {uri_host}").as_bytes(),
                )
                .into(),
            )
            .unwrap());
    }

    let before_req = Instant::now();

    let method = req.method().clone();
    let (part, body) = req.into_parts();

    tracing::debug!("Proxying {method} {uri}");

    let upstream_res = match settings
        .client
        .request(method.clone(), uri.to_string())
        .body(reqwest::Body::wrap(body))
        .headers(part.headers.clone())
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("Error sending request: {e}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Bytes::copy_from_slice(format!("{e}").as_bytes()).into())
                .unwrap());
        }
    };

    let headers_elapsed = before_req.elapsed();
    tracing::debug!(?headers_elapsed, "Upstream response: {upstream_res:?}");

    let status = upstream_res.status();
    let headers = upstream_res.headers().clone();

    let before_body = Instant::now();

    // collect the body as bytes
    let body = match upstream_res.bytes().await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("Error reading upstream response body: {e}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Bytes::copy_from_slice(format!("{e}").as_bytes()).into())
                .unwrap());
        }
    };

    let body_elapsed = before_body.elapsed();

    tracing::info!("Proxied {method} {uri} (headers {headers_elapsed:?} + body {body_elapsed:?})");

    let mut res = Response::builder().status(status);
    res.headers_mut().unwrap().extend(headers);
    Ok(res.body(body.into()).unwrap())
}
