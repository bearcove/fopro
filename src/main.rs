use argh::FromArgs;
use color_eyre::eyre::{self, Context};
use futures_util::future::BoxFuture;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use http_serde::http::uri::Scheme;
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
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::rustls::{
    crypto::ring::sign::any_ecdsa_type,
    pki_types::PrivateKeyDer,
    server::{ClientHello, ResolvesServerCert, ServerSessionMemoryCache},
    sign::CertifiedKey,
    ServerConfig,
};

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

        let temp_dir = if cfg!(windows) {
            std::env::temp_dir()
        } else {
            std::path::PathBuf::from("/tmp")
        };

        if !temp_dir.exists() {
            tracing::info!("Creating temp dir {temp_dir:?}");
            std::fs::create_dir_all(&temp_dir).unwrap();
        }
        let path = temp_dir.join("fopro-ca.crt");

        tokio::fs::write(&path, cert.pem()).await.unwrap();
        tracing::info!("🔏 Wrote CA cert to {} (in PEM format)", path.display());

        Self { keypair, cert }
    }
}

// just the output of the 'date' on macOS Sequoia
static CACHE_VERSION: &str = "Sun Oct 13 23:40:34 CEST 2024";

#[derive(FromArgs)]
/// A caching HTTP forward proxy
struct CliArgs {
    /// port to listen on
    #[argh(option, short = 'p', default = "8080")]
    port: u16,

    /// host to bind to
    #[argh(option, short = 'h', default = "String::from(\"127.0.0.1\")")]
    host: String,

    /// directory to store cache files
    #[argh(option, short = 'c', default = "String::from(\".fopro-cache\")")]
    cache_dir: String,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let args: CliArgs = argh::from_env();

    let rust_log_var = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let log_filter = Targets::from_str(&rust_log_var)?;

    Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_filter(log_filter),
        )
        .init();
    tracing::debug!("🐛 Debug logging is enabled");

    let ln = TcpListener::bind(format!("{}:{}", args.host, args.port)).await?;
    tracing::info!("🦊 Listening on {}:{}", args.host, args.port);

    let client = reqwest::Client::builder()
        .no_proxy()
        .use_rustls_tls()
        .user_agent("fopro/1.0 — https://github.com/bearcove/fopro")
        .build()?;

    let imch = Arc::new(InMemoryCache::default());
    let ca = Arc::new(CertAuth::new().await);

    let cache_dir = PathBuf::from(&args.cache_dir);
    let cache_version_file = cache_dir.join("cache-version.txt");

    if cache_dir.exists() {
        let mut can_use_cache_dir = true;

        match fs_err::tokio::read_to_string(&cache_version_file).await {
            Ok(version) => {
                if version != CACHE_VERSION {
                    tracing::warn!(
                        "🙅‍♀️ Cache version mismatch (want {CACHE_VERSION:?}, got {version:?})"
                    );
                    can_use_cache_dir = false;
                }
            }
            Err(_) => {
                tracing::warn!("🙅‍♀️ Cache version file missing");
                can_use_cache_dir = false;
            }
        }

        if can_use_cache_dir {
            tracing::info!("📂 Will re-use cache {}", cache_dir.display());
            let mut cache_size = 0;
            let mut num_entries = 0;
            for entry in walkdir::WalkDir::new(&cache_dir) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    cache_size += entry.metadata()?.len();
                    num_entries += 1;
                }
            }

            fn format_size(size: u64) -> String {
                if size < 1024 {
                    format!("{}B", size)
                } else if size < 1024 * 1024 {
                    format!("{:.1}KiB", size as f64 / 1024.0)
                } else {
                    format!("{:.1}MiB", size as f64 / 1024.0 / 1024.0)
                }
            }

            tracing::info!(
                "📊 Cache stats: {} entries, {} total",
                num_entries,
                format_size(cache_size)
            );
        } else {
            tracing::warn!(
                "🧹 Cache dir {} is not usable, clearing",
                cache_dir.display()
            );
            fs_err::tokio::remove_dir_all(&cache_dir).await?;
        }
    }

    if !cache_dir.exists() {
        fs_err::create_dir_all(&cache_dir)?;
        fs_err::tokio::write(&cache_version_file, CACHE_VERSION).await?;
        tracing::info!("✨ A new cache is born, at {}", cache_dir.display());
    }
    let cache_dir = cache_dir.canonicalize()?;

    let cert_cache = Arc::new(CertCache {
        certs_by_host: Mutex::new(HashMap::new()),
        ca,
    });

    let mut server_conf = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_cache);
    server_conf.alpn_protocols.push(b"h2".to_vec());
    server_conf.alpn_protocols.push(b"http/1.1".to_vec());
    server_conf.max_early_data_size = 4 * 1024;
    server_conf.send_half_rtt_data = true;
    server_conf.session_storage = ServerSessionMemoryCache::new(16 * 1024);
    let server_conf = Arc::new(server_conf);

    let settings = ProxySettings {
        client,
        imch,
        cache_dir,
        server_conf,
    };

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
    // TODO: use https://lib.rs/crates/papaya?
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

            let scheme = if req.uri().port_u16().unwrap_or_default() == 443 {
                Scheme::HTTPS
            } else {
                Scheme::HTTP
            };

            if req.method() != Method::CONNECT {
                let service = ProxyService {
                    host,
                    settings,
                    scheme,
                };

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
                if let Err(e) = handle_upgraded_conn(on_upgrade, host, scheme, settings).await {
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
    scheme: Scheme,
    settings: ProxySettings,
) -> eyre::Result<()> {
    let c = on_upgrade.await.unwrap();
    let c = TokioIo::new(c);

    let before_accept = Instant::now();
    let acceptor = tokio_rustls::TlsAcceptor::from(settings.server_conf.clone());
    let tls_stream = acceptor.accept(c).await?;

    enum Mode {
        H1,
        H2,
    }

    let mode = {
        let (_stream, server_conn) = tls_stream.get_ref();

        tracing::trace!(
            "Negotiated TLS session in {:?}, ALPN proto:\n{}",
            before_accept.elapsed(),
            pretty_hex::pretty_hex(&server_conn.alpn_protocol().unwrap_or_default())
        );

        if server_conn.alpn_protocol().unwrap_or_default() == b"h2" {
            Mode::H2
        } else {
            Mode::H1
        }
    };

    let service = ProxyService {
        host,
        settings,
        scheme,
    };

    let conn = tokio::spawn(async move {
        match mode {
            Mode::H1 => {
                conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await
            }
            Mode::H2 => {
                conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await
            }
        }
    });
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

struct CertCache {
    /// generated certificates
    // TODO: use https://lib.rs/crates/papaya?
    certs_by_host: Mutex<HashMap<String, Arc<CertifiedKey>>>,

    /// the shared certificate authority
    ca: Arc<CertAuth>,
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertCache").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertCache {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = match client_hello.server_name() {
            Some(server_name) => server_name,
            None => {
                tracing::debug!("No server name in client hello, aborting handshake");
                return None;
            }
        };

        let mut certs_by_host = self.certs_by_host.lock().unwrap();
        if let Some(cert) = certs_by_host.get(server_name) {
            return Some(Arc::clone(cert));
        }

        let before_gen = Instant::now();
        let mut srv_params = rcgen::CertificateParams::new(vec![server_name.to_string()]).unwrap();
        srv_params.is_ca = rcgen::IsCa::NoCa;

        let srv_keypair = rcgen::KeyPair::generate().unwrap();
        let srv_cert = srv_params
            .signed_by(&srv_keypair, &self.ca.cert, &self.ca.keypair)
            .unwrap();

        let cert = Arc::new(CertifiedKey::new(
            vec![srv_cert.into()],
            any_ecdsa_type(&PrivateKeyDer::Pkcs8(srv_keypair.serialize_der().into()))
                .expect("Failed to create ECDSA signing key"),
        ));

        certs_by_host.insert(server_name.to_string(), Arc::clone(&cert));
        tracing::info!(
            "Generated cert for {server_name} in {:?}",
            before_gen.elapsed()
        );

        Some(cert)
    }
}

#[derive(Clone)]
struct ProxySettings {
    /// the shared reqwest client for upstream
    client: reqwest::Client,

    /// the shared in-memory cache
    imch: InMemoryCacheHandle,

    /// the cache directory
    cache_dir: PathBuf,

    /// TLS server config
    server_conf: Arc<ServerConfig>,
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
    scheme: Scheme,
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

        let method = req.method().clone();
        let (part, body) = req.into_parts();

        let uri_host = uri
            .host()
            .or_else(|| part.headers.get("host").and_then(|h| h.to_str().ok()))
            .ok_or_else(|| eyre::eyre!("expected host in URI or host header"))?;

        if uri_host != self.host {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::from(format!("expected host {}, got {uri_host}", self.host)).boxed())
                .unwrap());
        }

        let before_req = Instant::now();

        let mut cachable = true;

        let mut cache_key = format!(
            "k/{}{}",
            uri.authority().map(|a| a.as_str()).unwrap_or_default(),
            uri.path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or_default()
        );
        cache_key = cache_key.replace(':', "_COLON_");
        cache_key = cache_key.replace("//", "_SLASHSLASH_");
        if cache_key.contains("..") {
            cachable = false;
        }

        if cache_key.ends_with('/') {
            cache_key = format!("{cache_key}_INDEX_");
        };

        if let Some(authorization) = part.headers.get(hyper::header::AUTHORIZATION) {
            let authorization = authorization.to_str().unwrap();
            let hash = md5::compute(authorization);
            let hash = format!("{:x}", hash);
            cache_key = format!("{cache_key}_AUTH_{hash}");
        }

        if let Some(accept) = part.headers.get(hyper::header::ACCEPT) {
            let accept = accept.to_str().unwrap();
            let hash = md5::compute(accept);
            let hash = format!("{:x}", hash);
            cache_key = format!("{cache_key}_ACCEPT_{hash}");
        }

        if let Some(accept_encoding) = part.headers.get(hyper::header::ACCEPT_ENCODING) {
            let accept_encoding = accept_encoding.to_str().unwrap();
            let hash = md5::compute(accept_encoding);
            let hash = format!("{:x}", hash);
            cache_key = format!("{cache_key}_ACCEPT_ENCODING_{hash}");
        }

        if let Some(accept_language) = part.headers.get(hyper::header::ACCEPT_LANGUAGE) {
            let accept_language = accept_language.to_str().unwrap();
            let hash = md5::compute(accept_language);
            let hash = format!("{:x}", hash);
            cache_key = format!("{cache_key}_ACCEPT_LANGUAGE_{hash}");
        }

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

        let cache_path_on_disk = self.settings.cache_dir.join(&cache_key);

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

        tracing::debug!("Proxying {method} {uri}: {part:#?}");

        let uri = if uri.host().is_none() {
            let mut parts = uri.into_parts();
            parts.scheme = Some(self.scheme.clone());
            parts.authority = Some(format!("{}", self.host).parse().unwrap());
            hyper::Uri::from_parts(parts).unwrap()
        } else {
            uri
        };

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
