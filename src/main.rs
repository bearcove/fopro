use color_eyre::eyre;
use futures_util::future::BoxFuture;
use http_body_util::Full;
use hyper::{
    body::{Body, Bytes},
    server::conn,
    service::Service,
    upgrade::OnUpgrade,
    HeaderMap, Method, Request, Response, StatusCode, Uri,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr, sync::Arc, time::Instant};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
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
        Err(e) => {
            let mut current_error: &dyn std::error::Error = &e;
            let mut is_broken_pipe = false;
            while let Some(source) = current_error.source() {
                if let Some(io_error) = source.downcast_ref::<std::io::Error>() {
                    if io_error.kind() == std::io::ErrorKind::BrokenPipe {
                        is_broken_pipe = true;
                        break;
                    }
                }
                current_error = source;
            }
            if is_broken_pipe {
                tracing::debug!("Connection closed (broken pipe): {}", e);
            } else {
                return Err(e.into());
            }
        }
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

    let cache_key = format!(
        "{}{}",
        uri.host().unwrap_or_default(),
        uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or_default()
    );
    let cache_key = cache_key.replace(':', "_COLON_");
    let cache_key = cache_key.replace("//", "_SLASHSLASH_");
    if cache_key.contains("..") {
        panic!("nope");
    }
    let cache_key = cache_key.strip_suffix('/').unwrap_or(&cache_key);
    tracing::debug!("Cache key: {}", cache_key);

    let mut cachable = true;
    if uri.host().unwrap_or_default() == "github.com" {
        // don't cache, probably a git clone, we don't know how to cache that yet
        cachable = false;
    }
    if method != Method::GET {
        // only cache GET requests for now
        cachable = false;
    }

    let cache_dir = std::env::current_dir()?.join(".fopro-cache");
    let cache_path_on_disk = cache_dir.join(cache_key);

    if cachable {
        tokio::fs::create_dir_all(cache_path_on_disk.parent().unwrap()).await?;

        match tokio::fs::File::open(&cache_path_on_disk).await {
            Ok(mut file) => {
                tracing::debug!("Cache hit: {}", cache_key);
                let cache_entry = read_cache_entry(&mut file).await?;
                let mut res = Response::builder().status(cache_entry.header.response_status);
                res.headers_mut()
                    .unwrap()
                    .extend(cache_entry.header.response_headers);

                let before_read = Instant::now();

                let body = tokio::fs::read(&cache_path_on_disk).await?
                    [cache_entry.body_offset as usize..]
                    .to_vec();
                let res_size = body.len();
                let body = Full::new(Bytes::from(body));

                let read_elapsed = before_read.elapsed();

                {
                    let status = cache_entry.header.response_status;
                    let status = format_status(status);
                    tracing::info!("\x1b[32m[HIT!]\x1b[0m {status} {res_size}B {method} {uri} (read {read_elapsed:?})");
                }

                return Ok(res.body(body).unwrap());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Cache miss, continue with the original request
            }
            Err(e) => {
                // Unexpected error
                return Err(e.into());
            }
        }
    }

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
    tracing::debug!(?headers_elapsed, "Upstream response: {upstream_res:#?}");

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
    let res_size = body.len();

    let body_elapsed = before_body.elapsed();
    {
        let status = format_status(status);
        tracing::info!(
            "\x1b[31m[MISS]\x1b[0m {status} {res_size}B {method} {uri} (headers {headers_elapsed:?} + body {body_elapsed:?})"
        );
    }

    if cachable && status.is_success() {
        // Create cache entry
        let cache_entry = CacheEntry {
            header: CacheHeader {
                response_status: status,
                response_headers: headers.clone(),
            },
            body_offset: 0, // This will be updated when writing
        };

        // Write to a temporary file
        let temp_file = cache_path_on_disk.with_extension("tmp");
        let mut file = tokio::fs::File::create(&temp_file).await?;

        // Write the cache entry
        write_cache_entry(&mut file, cache_entry).await?;

        // Write the body
        file.write_all(&body).await?;

        // Ensure all data is written to disk
        file.flush().await?;

        // Rename the temporary file to the final cache file
        tokio::fs::rename(temp_file, cache_path_on_disk).await?;
    }

    let mut res = Response::builder().status(status);
    res.headers_mut().unwrap().extend(headers);
    Ok(res.body(body.into()).unwrap())
}

struct CacheEntry {
    header: CacheHeader,
    body_offset: u64,
}

#[derive(Serialize, Deserialize)]
struct CacheHeader {
    #[serde(with = "http_serde::status_code")]
    response_status: StatusCode,

    #[serde(with = "http_serde::header_map")]
    response_headers: HeaderMap,
}

async fn read_cache_entry(mut r: impl AsyncRead + Unpin) -> eyre::Result<CacheEntry> {
    let mut buf = [0; 8];
    tokio::io::AsyncReadExt::read_exact(&mut r, &mut buf).await?;
    let header_len = u64::from_be_bytes(buf);

    let mut header_buf = vec![0u8; header_len as usize];
    tokio::io::AsyncReadExt::read_exact(&mut r, &mut header_buf).await?;
    let header: CacheHeader = postcard::from_bytes(&header_buf)?;

    Ok(CacheEntry {
        header,
        body_offset: 8 + header_len,
    })
}

async fn write_cache_entry(mut w: impl AsyncWrite + Unpin, entry: CacheEntry) -> eyre::Result<()> {
    let header_bytes = postcard::to_stdvec(&entry.header)?;
    let header_len = header_bytes.len() as u64;

    w.write_all(&header_len.to_be_bytes()).await?;
    w.write_all(&header_bytes).await?;

    Ok(())
}

fn format_status(status: StatusCode) -> String {
    match status.as_u16() {
        200..=299 => format!("\x1b[32m{}\x1b[0m", status),
        _ => format!("\x1b[33m{}\x1b[0m", status),
    }
}
