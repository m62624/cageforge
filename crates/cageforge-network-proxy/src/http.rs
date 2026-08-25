// SPDX-License-Identifier: Apache-2.0

//! HTTP/1.1 forward-proxy and CONNECT handling.

use std::convert::Infallible;
use std::future::Future;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use hyper::body::Incoming;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::http::uri::PathAndQuery;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::authority::Authority;
use crate::body::{self, ProxyBody, TransferBudget};
use crate::{GatewayError, NetworkGateway, NetworkResolver};

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

#[derive(Clone)]
struct ProtocolTasks {
    inner: Arc<ProtocolTasksInner>,
}

struct ProtocolTasksInner {
    handles: Mutex<Vec<JoinHandle<Result<(), GatewayError>>>>,
}

#[derive(Clone)]
struct HttpActivity {
    inner: Arc<HttpActivityInner>,
}

struct HttpActivityInner {
    armed: AtomicBool,
    last_transfer: Mutex<Instant>,
    changed: Notify,
}

struct TrackedIo<T> {
    inner: T,
    activity: HttpActivity,
}

pub(crate) async fn serve<R, S>(gateway: &NetworkGateway<R>, stream: S) -> Result<(), GatewayError>
where
    R: NetworkResolver,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let activity = HttpActivity::new();
    let request_count = Arc::new(AtomicUsize::new(0));
    let tasks = ProtocolTasks::new();
    let service_gateway = gateway.clone();
    let service_tasks = tasks.clone();
    let service_activity = activity.clone();
    let service = service_fn(move |request| {
        let gateway = service_gateway.clone();
        let request_count = Arc::clone(&request_count);
        let tasks = service_tasks.clone();
        let activity = service_activity.clone();
        async move {
            let response =
                handle_request(&gateway, request, &request_count, &tasks, &activity).await;
            Ok::<_, Infallible>(response)
        }
    });

    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(gateway.inner.config.handshake_timeout())
        .max_buf_size(gateway.inner.config.http_header_bytes().get());
    let idle_timeout = gateway.inner.config.relay_idle_timeout();
    let cancellation_tasks = tasks.clone();
    let protocol_activity = activity.clone();
    let protocol = async move {
        let connection_result = builder
            .serve_connection(
                TokioIo::new(TrackedIo::new(stream, protocol_activity)),
                service,
            )
            .with_upgrades()
            .await;
        let task_result = tasks.finish().await;
        connection_result.map_err(|source| GatewayError::HttpConnection { source })?;
        task_result
    };
    tokio::pin!(protocol);
    tokio::select! {
        result = &mut protocol => result,
        () = activity.wait_until_idle(idle_timeout) => {
            cancellation_tasks.abort();
            Err(GatewayError::RelayTimedOut)
        }
    }
}

async fn handle_request<R>(
    gateway: &NetworkGateway<R>,
    request: Request<Incoming>,
    request_count: &AtomicUsize,
    tasks: &ProtocolTasks,
    activity: &HttpActivity,
) -> Response<ProxyBody>
where
    R: NetworkResolver,
{
    let number = request_count
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if number > gateway.inner.config.max_requests_per_connection().get() {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "request limit exceeded\n",
            true,
        );
    }
    if request.method() == Method::CONNECT {
        return match handle_connect(gateway, request, tasks, activity).await {
            Ok(response) => response,
            Err(error) => response_for_error(&error),
        };
    }
    match forward(gateway, request, tasks, activity).await {
        Ok(response) => response,
        Err(error) => response_for_error(&error),
    }
}

async fn forward<R>(
    gateway: &NetworkGateway<R>,
    request: Request<Incoming>,
    tasks: &ProtocolTasks,
    activity: &HttpActivity,
) -> Result<Response<ProxyBody>, GatewayError>
where
    R: NetworkResolver,
{
    let authority = ordinary_authority(request.uri())?;
    validate_host_header(request.headers(), &authority)?;
    let upstream = gateway.inner.connect(&authority).await?;
    let budget = TransferBudget::new(gateway.inner.config.relay_byte_limit());
    let (mut parts, incoming) = request.into_parts();
    sanitize_request_headers(&mut parts.headers, &authority)?;
    parts.uri = origin_form(&parts.uri)?;
    parts.version = Version::HTTP_11;
    let request = Request::from_parts(
        parts,
        body::guarded(
            incoming,
            gateway.inner.config.relay_idle_timeout(),
            Arc::clone(&budget),
        ),
    );

    let mut client = hyper::client::conn::http1::Builder::new();
    client.max_buf_size(gateway.inner.config.http_header_bytes().get());
    let (mut sender, connection) = timeout(
        gateway.inner.config.handshake_timeout(),
        client.handshake(TokioIo::new(TrackedIo::new(upstream, activity.clone()))),
    )
    .await
    .map_err(|_| GatewayError::HandshakeTimedOut)?
    .map_err(|source| GatewayError::HttpConnection { source })?;
    tasks.spawn(async move {
        connection
            .await
            .map_err(|source| GatewayError::HttpConnection { source })
    });
    activity.arm();
    let response = timeout(
        gateway.inner.config.response_header_timeout(),
        sender.send_request(request),
    )
    .await
    .map_err(|_| GatewayError::ResponseHeaderTimedOut {
        host: authority.host().to_string(),
        port: authority.port(),
    })?
    .map_err(|source| GatewayError::HttpConnection { source })?;
    let (mut parts, incoming) = response.into_parts();
    remove_response_hop_by_hop_headers(&mut parts.headers)?;
    Ok(Response::from_parts(
        parts,
        body::guarded(incoming, gateway.inner.config.relay_idle_timeout(), budget),
    ))
}

async fn handle_connect<R>(
    gateway: &NetworkGateway<R>,
    mut request: Request<Incoming>,
    tasks: &ProtocolTasks,
    activity: &HttpActivity,
) -> Result<Response<ProxyBody>, GatewayError>
where
    R: NetworkResolver,
{
    reject_connect_body(request.headers())?;
    let authority = request
        .uri()
        .authority()
        .ok_or(GatewayError::InvalidHttpRequest {
            reason: "CONNECT requires authority-form target",
        })
        .and_then(|value| Authority::parse(value.as_str(), None))?;
    let upstream = gateway.inner.connect(&authority).await?;
    let on_upgrade = hyper::upgrade::on(&mut request);
    let idle_timeout = gateway.inner.config.relay_idle_timeout();
    let byte_limit = gateway.inner.config.relay_byte_limit();
    let upstream = TrackedIo::new(upstream, activity.clone());
    activity.arm();
    tasks.spawn(async move {
        let upgraded = on_upgrade
            .await
            .map_err(|source| GatewayError::HttpUpgrade { source })?;
        crate::relay::copy_bidirectional(TokioIo::new(upgraded), upstream, idle_timeout, byte_limit)
            .await
    });
    let mut response = Response::new(body::empty());
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

fn ordinary_authority(uri: &Uri) -> Result<Authority, GatewayError> {
    if uri.scheme_str() != Some("http") {
        return Err(GatewayError::InvalidHttpRequest {
            reason: "ordinary proxy requests require an absolute http URI",
        });
    }
    let authority = uri.authority().ok_or(GatewayError::InvalidHttpRequest {
        reason: "absolute URI is missing an authority",
    })?;
    Authority::parse(authority.as_str(), Some(80))
}

fn origin_form(uri: &Uri) -> Result<Uri, GatewayError> {
    let path = uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(|_| GatewayError::InvalidHttpRequest {
            reason: "request target cannot be converted to origin form",
        })
}

fn reject_connect_body(headers: &HeaderMap) -> Result<(), GatewayError> {
    let has_nonempty_length = headers
        .get(CONTENT_LENGTH)
        .is_some_and(|value| value.as_bytes() != b"0");
    if has_nonempty_length || headers.contains_key(TRANSFER_ENCODING) {
        return Err(GatewayError::InvalidHttpRequest {
            reason: "CONNECT request bodies are not supported",
        });
    }
    Ok(())
}

fn validate_host_header(headers: &HeaderMap, authority: &Authority) -> Result<(), GatewayError> {
    let mut values = headers.get_all(HOST).iter();
    let value = values.next().ok_or(GatewayError::InvalidHttpRequest {
        reason: "ordinary proxy request is missing its Host header",
    })?;
    if values.next().is_some() {
        return Err(GatewayError::InvalidHttpRequest {
            reason: "ordinary proxy request contains multiple Host headers",
        });
    }
    let value = value
        .to_str()
        .map_err(|_| GatewayError::InvalidHttpRequest {
            reason: "ordinary proxy request has an invalid Host header",
        })?;
    let host = Authority::parse(value, Some(80))?;
    if !authority.same_endpoint(&host) {
        return Err(GatewayError::InvalidHttpRequest {
            reason: "Host header does not match the absolute request target",
        });
    }
    Ok(())
}

fn sanitize_request_headers(
    headers: &mut HeaderMap,
    authority: &Authority,
) -> Result<(), GatewayError> {
    remove_request_hop_by_hop_headers(headers)?;
    let value = if authority.port() == 80 {
        authority.host().to_string()
    } else if authority.host().contains(':') {
        format!("[{}]:{}", authority.host(), authority.port())
    } else {
        format!("{}:{}", authority.host(), authority.port())
    };
    let value = HeaderValue::from_str(&value).map_err(|_| GatewayError::InvalidHttpRequest {
        reason: "authority cannot be represented as a Host header",
    })?;
    headers.insert(HOST, value);
    Ok(())
}

fn remove_request_hop_by_hop_headers(headers: &mut HeaderMap) -> Result<(), GatewayError> {
    let nominated: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| GatewayError::InvalidHttpRequest {
                    reason: "Connection header contains non-ASCII data",
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .map(|name| {
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| GatewayError::InvalidHttpRequest {
                reason: "Connection header contains an invalid field name",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    remove_hop_by_hop_headers(headers, nominated);
    Ok(())
}

fn remove_response_hop_by_hop_headers(headers: &mut HeaderMap) -> Result<(), GatewayError> {
    let nominated: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map_err(|_| GatewayError::InvalidHttpResponse {
                    reason: "Connection header contains non-ASCII data",
                })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .map(|name| {
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| GatewayError::InvalidHttpResponse {
                reason: "Connection header contains an invalid field name",
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    remove_hop_by_hop_headers(headers, nominated);
    Ok(())
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap, nominated: Vec<HeaderName>) {
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        KEEP_ALIVE,
        PROXY_CONNECTION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
    ] {
        headers.remove(name);
    }
}

fn response_for_error(error: &GatewayError) -> Response<ProxyBody> {
    let (status, message) = match error {
        GatewayError::InvalidHttpRequest { .. } | GatewayError::InvalidAuthority { .. } => {
            (StatusCode::BAD_REQUEST, "invalid proxy request\n")
        }
        GatewayError::PolicyDenied { .. }
        | GatewayError::ExternallyEnforced { .. }
        | GatewayError::UnsupportedPolicy { .. }
        | GatewayError::PolicyEvaluation { .. }
        | GatewayError::InvalidResolvedTarget { .. } => {
            (StatusCode::FORBIDDEN, "destination denied\n")
        }
        GatewayError::DnsTimedOut { .. }
        | GatewayError::ConnectTimedOut { .. }
        | GatewayError::ResponseHeaderTimedOut { .. } => {
            (StatusCode::GATEWAY_TIMEOUT, "upstream timed out\n")
        }
        GatewayError::ConnectionLimitReached => {
            (StatusCode::TOO_MANY_REQUESTS, "connection limit exceeded\n")
        }
        GatewayError::RelayByteLimitExceeded { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, "transfer limit exceeded\n")
        }
        GatewayError::InvalidHttpResponse { .. } => {
            (StatusCode::BAD_GATEWAY, "invalid upstream response\n")
        }
        _ => (StatusCode::BAD_GATEWAY, "upstream failed\n"),
    };
    error_response(status, message, false)
}

fn error_response(status: StatusCode, message: &'static str, close: bool) -> Response<ProxyBody> {
    let mut response = Response::new(body::text(message));
    *response.status_mut() = status;
    if close {
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

impl ProtocolTasks {
    fn new() -> Self {
        Self {
            inner: Arc::new(ProtocolTasksInner {
                handles: Mutex::new(Vec::new()),
            }),
        }
    }

    fn spawn<F>(&self, future: F)
    where
        F: Future<Output = Result<(), GatewayError>> + Send + 'static,
    {
        let handle = tokio::spawn(future);
        self.inner
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle);
    }

    async fn finish(self) -> Result<(), GatewayError> {
        let handles = {
            let mut guard = self
                .inner
                .handles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        for handle in handles {
            handle
                .await
                .map_err(|source| GatewayError::ProtocolTask { source })??;
        }
        Ok(())
    }

    fn abort(&self) {
        let mut handles = self
            .inner
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for handle in handles.drain(..) {
            handle.abort();
        }
    }
}

impl HttpActivity {
    fn new() -> Self {
        Self {
            inner: Arc::new(HttpActivityInner {
                armed: AtomicBool::new(false),
                last_transfer: Mutex::new(Instant::now()),
                changed: Notify::new(),
            }),
        }
    }

    fn arm(&self) {
        if !self.inner.armed.swap(true, Ordering::AcqRel) {
            self.record();
        }
    }

    fn record(&self) {
        *self
            .inner
            .last_transfer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        self.inner.changed.notify_one();
    }

    async fn wait_until_idle(&self, idle_timeout: std::time::Duration) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.inner.armed.load(Ordering::Acquire) {
                changed.await;
                continue;
            }
            let deadline = *self
                .inner
                .last_transfer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                + idle_timeout;
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    let current_deadline = *self
                        .inner
                        .last_transfer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        + idle_timeout;
                    if current_deadline <= Instant::now() {
                        return;
                    }
                },
                () = &mut changed => {}
            }
        }
    }
}

impl<T> TrackedIo<T> {
    fn new(inner: T, activity: HttpActivity) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for TrackedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > filled {
            self.activity.record();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for TrackedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(context, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.record();
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(context, buffers);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.record();
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl Drop for ProtocolTasksInner {
    fn drop(&mut self) {
        let handles = self
            .handles
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for handle in handles.drain(..) {
            handle.abort();
        }
    }
}
