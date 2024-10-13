use color_eyre::eyre::{self, Context};
use futures_util::future::BoxFuture;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    server::conn,
    service::Service,
    upgrade::OnUpgrade,
    HeaderMap, Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::DistinguishedName;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::Debug,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::rustls::{pki_types::PrivateKeyDer, ServerConfig};

use tracing_subscriber::{
    filter::Targets, layer::SubscriberExt, util::SubscriberInitExt, Layer, Registry,
};

/// Our (self-signed) certificate authority
struct CertAuth {
    keypair: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

impl CertAuth {
    async fn new() -> Self {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(
            rcgen::DnType::CommonName,
            "DO NOT INSTALL! — fopro certificate authority (see https://github.com/bearcove/fopro)",
        );
        params.distinguished_name = dn;

        let keypair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&keypair).unwrap();

        let temp_dir = std::env::temp_dir();
        if !temp_dir.exists() {
            tracing::info!("Creating temp dir {temp_dir:?}");
            std::fs::create_dir_all(&temp_dir).unwrap();
        }
        let path = temp_dir.join("fopro-ca.crt");

        tokio::fs::write(&path, cert.pem()).await.unwrap();
        tracing::info!("Wrote CA cert to {} (in PEM format)", path.display());

        Self { keypair, cert }
    }
}

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

    let imch = Arc::new(InMemoryCache::default());
    let ca = Arc::new(CertAuth::new().await);
    let settings = ProxySettings { client, ca, imch };
    let service = UpgradeService { settings };

    while let Ok((stream, remote_addr)) = ln.accept().await {
        stream.set_nodelay(true).unwrap();

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

type InMemoryCacheHandle = Arc<InMemoryCache>;

#[derive(Default)]
struct InMemoryCache {
    entries: Mutex<HashMap<String, (CacheEntry, Bytes)>>,
}

impl std::fmt::Debug for InMemoryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCache")
            .field("num_entries", &self.entries.lock().unwrap().len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct UpgradeService {
    settings: ProxySettings,
}

impl<ReqBody> Service<Request<ReqBody>> for UpgradeService
where
    ReqBody: Body + Send + Sync + Debug + 'static,
    <ReqBody as Body>::Data: Into<Bytes>,
    <ReqBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = hyper::Response<OurBody>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let settings = self.settings.clone();
        tracing::debug!("Got request {req:#?}");

        Box::pin(async move {
            let uri = req.uri().clone();
            tracing::trace!(
                "Got {} to {uri}, headers = {:#?}",
                req.method(),
                req.headers()
            );

            let host = match uri.host() {
                Some(host) => host.to_string(),
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::from("expected host in request").boxed())
                        .unwrap())
                }
            };

            if req.method() != Method::CONNECT {
                let service = ProxyService { host, settings };
                return match service.proxy_request(req).await {
                    Ok(resp) => Ok(resp),
                    Err(e) => {
                        tracing::error!("Error proxying request: {e}");
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::from(format!("{e}")).boxed())
                            .unwrap())
                    }
                };
            }

            let on_upgrade = hyper::upgrade::on(req);
            tokio::spawn(async move {
                if let Err(e) = handle_upgraded_conn(on_upgrade, host, settings).await {
                    tracing::error!("Error handling upgraded conn: {e:?}");
                }
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::from("you're connected, have you added fopro's CA cert as a root for your client??").boxed())
                .unwrap())
        })
    }
}

async fn handle_upgraded_conn(
    on_upgrade: OnUpgrade,
    host: String,
    settings: ProxySettings,
) -> eyre::Result<()> {
    let c = on_upgrade.await.unwrap();
    let c = TokioIo::new(c);

    let mut srv_params = rcgen::CertificateParams::new(vec![host.clone()]).unwrap();
    srv_params.is_ca = rcgen::IsCa::NoCa;

    let srv_keypair = rcgen::KeyPair::generate()?;
    let srv_cert = srv_params
        .signed_by(&srv_keypair, &settings.ca.cert, &settings.ca.keypair)
        .unwrap();

    let mut server_conf = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![srv_cert.into()],
            PrivateKeyDer::Pkcs8(srv_keypair.serialize_der().into()),
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

    let service = ProxyService { host, settings };
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

type OurBody = BoxBody<Bytes, Infallible>;

#[derive(Clone)]
struct ProxySettings {
    /// the shared reqwest client for upstream
    client: reqwest::Client,

    /// the shared certificate authority
    ca: Arc<CertAuth>,

    /// the shared in-memory cache
    imch: InMemoryCacheHandle,
}

impl std::fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxySettings").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct ProxyService {
    host: String,

    settings: ProxySettings,
}

impl<ReqBody> Service<Request<ReqBody>> for ProxyService
where
    ReqBody: Body + Send + Sync + Debug + 'static,
    <ReqBody as Body>::Data: Into<Bytes>,
    <ReqBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<OurBody>;
    type Error = hyper::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<ReqBody>) -> Self::Future {
        let this = self.clone();

        Box::pin(async move {
            match this.proxy_request(req).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    tracing::error!("Error proxying request: {e}");
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::from(format!("{e}")).boxed())
                        .unwrap())
                }
            }
        })
    }
}

impl ProxyService {
    async fn proxy_request<ReqBody>(
        self,
        req: Request<ReqBody>,
    ) -> Result<Response<OurBody>, eyre::Error>
    where
        ReqBody: Body + Send + Sync + Debug + 'static,
        <ReqBody as Body>::Data: Into<Bytes>,
        <ReqBody as Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let uri = req.uri().clone();
        tracing::trace!(settings = ?self.settings, %uri, "Should proxy request");

        let uri_host = uri
            .host()
            .ok_or_else(|| eyre::eyre!("expected host in CONNECT request"))?;

        if uri_host != self.host {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(format!("expected host {}, got {uri_host}", self.host)).boxed())
                .unwrap());
        }

        let before_req = Instant::now();

        let method = req.method().clone();
        let (part, body) = req.into_parts();

        let mut cachable = true;

        let cache_key = format!(
            "{}{}",
            uri.authority().map(|a| a.as_str()).unwrap_or_default(),
            uri.path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or_default()
        );
        let cache_key = cache_key.replace(':', "_COLON_");
        let cache_key = cache_key.replace("//", "_SLASHSLASH_");
        if cache_key.contains("..") {
            cachable = false;
        }
        let cache_key = if cache_key.ends_with('/') {
            format!("{cache_key}_INDEX_")
        } else {
            cache_key.to_string()
        };
        tracing::debug!("Cache key: {}", cache_key);

        if let Some(host) = uri.host() {
            if host == "github.com" {
                // don't cache, probably a git clone, we don't know how to cache that yet
                tracing::debug!("Not caching github.com request");
                cachable = false;
            }
            if IpAddr::from_str(host).is_ok() {
                // don't cache, probably a temp local server for testing
                tracing::debug!("Not caching {host} request (IP address)");
                cachable = false;
            }
        }

        if method != Method::GET {
            // only cache GET requests for now
            tracing::debug!("Not caching request with method {method}");
            cachable = false;
        }

        if part.headers.contains_key(hyper::header::AUTHORIZATION) {
            tracing::debug!("Not caching request with authorization header");
            cachable = false;
        }

        let cache_dir = std::env::current_dir()?.join(".fopro-cache");
        let cache_path_on_disk = cache_dir.join(&cache_key);

        if cachable {
            enum Source {
                Memory,
                Disk,
                Unknown,
            }

            let mut source = Source::Unknown;
            let mut maybe_entry_and_body: Option<(CacheEntry, Bytes)> = {
                let entries = self.settings.imch.entries.lock().unwrap();
                entries.get(&cache_key).cloned()
            };

            if maybe_entry_and_body.is_some() {
                source = Source::Memory;
            } else {
                match fs_err::tokio::File::open(&cache_path_on_disk).await {
                    Ok(mut file) => {
                        source = Source::Disk;

                        tracing::debug!("Cache hit: {}", cache_key);
                        let cache_entry =
                            read_cache_entry(&mut file).await.wrap_err_with(|| {
                                format!(
                                    "Error reading cache entry for {cache_key} at {}",
                                    cache_path_on_disk.display()
                                )
                            })?;
                        let body =
                            tokio::fs::read(&cache_path_on_disk)
                                .await
                                .wrap_err_with(|| {
                                    format!(
                                        "Error reading cache body for {cache_key} at {}",
                                        cache_path_on_disk.display()
                                    )
                                })?[cache_entry.body_offset as usize..]
                                .to_vec();
                        let body = Bytes::from(body);

                        {
                            let mut entries = self.settings.imch.entries.lock().unwrap();
                            entries
                                .insert(cache_key.to_string(), (cache_entry.clone(), body.clone()));
                        }

                        maybe_entry_and_body = Some((cache_entry, body));
                    }
                    Err(_) => {
                        // Cache miss, continue with the original request
                    }
                }
            }

            if let Some((cache_entry, body)) = maybe_entry_and_body {
                let mut res = Response::builder().status(cache_entry.header.response_status);
                res.headers_mut()
                    .unwrap()
                    .extend(cache_entry.header.response_headers);

                let before_read = Instant::now();

                let res_size = body.len();
                let body = Full::new(body);

                let read_elapsed = before_read.elapsed();

                {
                    let status = cache_entry.header.response_status;
                    let status = format_status(status);
                    let hit_string = match source {
                        Source::Memory => "mHIT",
                        Source::Disk => "dHIT",
                        Source::Unknown => "uHIT",
                    };

                    tracing::info!("\x1b[32m[{hit_string}]\x1b[0m {status} {res_size}B {method} {uri} (read {read_elapsed:?})");
                }

                return Ok(res.body(body.boxed()).unwrap());
            }
        }

        tracing::debug!("Proxying {method} {uri}");

        let upstream_res = match self
            .settings
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
                    .body(Full::from(format!("{e}")).boxed())
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
                    .body(Full::from(format!("{e}")).boxed())
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

        if status == StatusCode::OK {
            // cacheable, okay
        } else if status.is_client_error() {
            // also cacheable
        } else {
            // not cacheable — server error, partial resopnse, etc.
            tracing::debug!("Not caching request with status {status}");
            cachable = false;
        }

        if cachable {
            // Create cache entry
            let cache_entry = CacheEntry {
                header: CacheHeader {
                    response_status: status,
                    response_headers: headers.clone(),
                },
                body_offset: 0, // This will be updated when writing
            };

            // Write to a temporary file
            fs_err::tokio::create_dir_all(cache_path_on_disk.parent().unwrap()).await?;
            let temp_file = cache_path_on_disk.with_extension("tmp");

            {
                let mut file = fs_err::tokio::File::create(&temp_file).await?;

                // Write the cache entry
                write_cache_entry(&mut file, cache_entry.clone()).await?;

                // Write the body
                file.write_all(&body).await?;

                // Ensure all data is written to disk
                file.shutdown().await?;
            }

            // Rename the temporary file to the final cache file
            fs_err::tokio::rename(temp_file, cache_path_on_disk).await?;

            {
                let mut entries = self.settings.imch.entries.lock().unwrap();
                entries.insert(cache_key.to_string(), (cache_entry.clone(), body.clone()));
            }
        }

        let mut res = Response::builder().status(status);
        res.headers_mut().unwrap().extend(headers);
        Ok(res.body(Full::from(body).boxed()).unwrap())
    }
}

#[derive(Clone)]
struct CacheEntry {
    header: CacheHeader,
    body_offset: u64,
}

#[derive(Clone, Serialize, Deserialize)]
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
