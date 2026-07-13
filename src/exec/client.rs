use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::blocking::{Client, multipart};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use tracing::debug;

use crate::exec::classifier::classify_outcome;
use crate::exec::validation::validate_json_schema;
use crate::model::{
    AppSettings, AuthStyle, Blocker, BodyTemplate, ExecutionResult, KeyValueField, RenderedHeader,
    RenderedRequest, RequestDraft, ResponseSnapshot,
};
use crate::util::{extract_slot_names, looks_like_slot_value, replace_slots};

const BLOCKED_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "cookie",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-for",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
];

pub fn build_http_client(settings: &AppSettings) -> Result<Client> {
    Client::builder()
        // Requests generated from imported material must never inherit a user or
        // machine proxy. A proxy would resolve and route the authority outside
        // the policy-checked connection path below.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .timeout(Duration::from_secs(settings.timeout_secs))
        // Do not retain idle connections across executions. Each execution then
        // opens a fresh connection using the address set pinned by this client's
        // PolicyDnsResolver.
        .pool_max_idle_per_host(0)
        .dns_resolver(Arc::new(PolicyDnsResolver::new()))
        .build()
        .map_err(anyhow::Error::from)
}

type DnsLookup = dyn Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync;
type DnsResult = std::result::Result<Addrs, Box<dyn std::error::Error + Send + Sync>>;

struct HostPin {
    addresses: OnceLock<Arc<[SocketAddr]>>,
    lookup_lock: Mutex<()>,
}

impl HostPin {
    fn new() -> Self {
        Self {
            addresses: OnceLock::new(),
            lookup_lock: Mutex::new(()),
        }
    }
}

/// Resolves each hostname once per client, validates the complete answer set,
/// and pins that exact set for the client's lifetime. reqwest keeps the original
/// URL authority for HTTP Host and TLS SNI while connecting only to addresses
/// returned by this resolver.
struct PolicyDnsResolver {
    state: Arc<PolicyDnsState>,
}

struct PolicyDnsState {
    pinned: Mutex<HashMap<String, Arc<HostPin>>>,
    lookup: Arc<DnsLookup>,
}

impl PolicyDnsResolver {
    fn new() -> Self {
        Self::with_lookup(|host| (host, 0).to_socket_addrs().map(Iterator::collect))
    }

    fn with_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    {
        Self {
            state: Arc::new(PolicyDnsState {
                pinned: Mutex::new(HashMap::new()),
                lookup: Arc::new(lookup),
            }),
        }
    }

    #[cfg(test)]
    fn pinned_addresses(&self, host: &str) -> io::Result<Arc<[SocketAddr]>> {
        self.state.pinned_addresses(host)
    }
}

impl PolicyDnsState {
    fn cached_addresses(&self, host: &str) -> io::Result<Option<Arc<[SocketAddr]>>> {
        let cache_key = canonical_dns_name(host);
        let pinned = self
            .pinned
            .lock()
            .map_err(|_| io::Error::other("DNS policy cache is unavailable"))?;
        Ok(pinned
            .get(&cache_key)
            .and_then(|host_pin| host_pin.addresses.get())
            .map(Arc::clone))
    }

    fn pinned_addresses(&self, host: &str) -> io::Result<Arc<[SocketAddr]>> {
        let cache_key = canonical_dns_name(host);
        let host_pin = {
            let mut pinned = self
                .pinned
                .lock()
                .map_err(|_| io::Error::other("DNS policy cache is unavailable"))?;
            Arc::clone(
                pinned
                    .entry(cache_key)
                    .or_insert_with(|| Arc::new(HostPin::new())),
            )
        };

        if let Some(addresses) = host_pin.addresses.get() {
            return Ok(Arc::clone(addresses));
        }

        // Only a successfully validated answer is cached. A lookup failure is
        // fail-closed for that request but may be retried on a later request.
        // The per-host lock ensures concurrent first requests cannot race two
        // different successful DNS answers into the cache.
        let _lookup_guard = host_pin
            .lookup_lock
            .lock()
            .map_err(|_| io::Error::other("DNS policy cache is unavailable"))?;
        if let Some(addresses) = host_pin.addresses.get() {
            return Ok(Arc::clone(addresses));
        }

        let addresses =
            Arc::<[SocketAddr]>::from(lookup_and_validate_host(host, self.lookup.as_ref())?);
        host_pin
            .addresses
            .set(Arc::clone(&addresses))
            .map_err(|_| io::Error::other("DNS policy cache could not pin an address set"))?;
        Ok(addresses)
    }
}

impl Resolve for PolicyDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        match self.state.cached_addresses(&host) {
            Ok(Some(addresses)) => Box::pin(std::future::ready(dns_result(Ok(addresses)))),
            Err(error) => Box::pin(std::future::ready(dns_result(Err(error)))),
            Ok(None) => {
                let (future, completion) = ThreadedDnsResolution::pending();
                let state = Arc::clone(&self.state);
                match std::thread::Builder::new()
                    .name("firstcall-dns".to_string())
                    .spawn(move || {
                        completion.complete(dns_result(state.pinned_addresses(&host)));
                    }) {
                    Ok(_) => Box::pin(future),
                    Err(_) => Box::pin(std::future::ready(dns_result(Err(io::Error::other(
                        "DNS resolver worker could not start",
                    ))))),
                }
            }
        }
    }
}

fn dns_result(result: io::Result<Arc<[SocketAddr]>>) -> DnsResult {
    result
        .map(|addresses| Box::new(PinnedAddrs::new(addresses)) as Addrs)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
}

struct PinnedAddrs {
    addresses: Arc<[SocketAddr]>,
    index: usize,
}

impl PinnedAddrs {
    fn new(addresses: Arc<[SocketAddr]>) -> Self {
        Self {
            addresses,
            index: 0,
        }
    }
}

impl Iterator for PinnedAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let address = self.addresses.get(self.index).copied();
        self.index = self.index.saturating_add(1);
        address
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.addresses.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for PinnedAddrs {}

struct ThreadedDnsResolution {
    shared: Arc<Mutex<ThreadedDnsState>>,
}

struct ThreadedDnsCompletion {
    shared: Arc<Mutex<ThreadedDnsState>>,
}

struct ThreadedDnsState {
    result: Option<DnsResult>,
    waker: Option<Waker>,
}

impl ThreadedDnsResolution {
    fn pending() -> (Self, ThreadedDnsCompletion) {
        let shared = Arc::new(Mutex::new(ThreadedDnsState {
            result: None,
            waker: None,
        }));
        (
            Self {
                shared: Arc::clone(&shared),
            },
            ThreadedDnsCompletion { shared },
        )
    }
}

impl Future for ThreadedDnsResolution {
    type Output = DnsResult;

    fn poll(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut shared = match self.shared.lock() {
            Ok(shared) => shared,
            Err(_) => {
                return Poll::Ready(dns_result(Err(io::Error::other(
                    "DNS resolver worker state is unavailable",
                ))));
            }
        };
        if let Some(result) = shared.result.take() {
            Poll::Ready(result)
        } else {
            shared.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

impl ThreadedDnsCompletion {
    fn complete(self, result: DnsResult) {
        let waker = {
            let mut shared = match self.shared.lock() {
                Ok(shared) => shared,
                Err(poisoned) => poisoned.into_inner(),
            };
            shared.result = Some(result);
            shared.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

fn canonical_dns_name(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn lookup_and_validate_host(host: &str, lookup: &DnsLookup) -> io::Result<Vec<SocketAddr>> {
    let addresses =
        lookup(host).map_err(|error| io::Error::new(error.kind(), "DNS resolution failed"))?;
    validate_resolved_addresses(addresses)
}

fn validate_resolved_addresses(addresses: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS resolution returned no addresses",
        ));
    }

    // Validate the whole answer before returning any address. This prevents an
    // allowed first answer from masking a disallowed later CNAME/A/AAAA result.
    for address in &addresses {
        if disallowed_ip(address.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "DNS resolution returned a disallowed {} address class",
                    if address.is_ipv4() { "IPv4" } else { "IPv6" }
                ),
            ));
        }
    }

    Ok(addresses)
}

pub fn execute_request(
    draft: &RequestDraft,
    settings: &AppSettings,
    client: &Client,
) -> ExecutionResult {
    match perform_request(draft, settings, client) {
        Ok(result) => result,
        Err(error) => ExecutionResult {
            rendered_request: RenderedRequest {
                method: draft.method.clone(),
                url: draft.endpoint_summary(),
                headers: Vec::new(),
                body_preview: None,
            },
            response_snapshot: Some(ResponseSnapshot {
                status: None,
                headers: Vec::new(),
                body_preview: String::new(),
                body_truncated: false,
                bytes_read: 0,
                elapsed_ms: 0,
                validation_errors: Vec::new(),
                transport_error: Some(error.to_string()),
            }),
            outcome: crate::model::Outcome::Failure,
            blocker: Some(Blocker::UnknownFailure),
            notes: error.to_string(),
        },
    }
}

fn perform_request(
    draft: &RequestDraft,
    settings: &AppSettings,
    client: &Client,
) -> Result<ExecutionResult> {
    if let Some(reason) = &draft.unsupported_reason {
        return Ok(blocked_result(
            draft,
            Blocker::UnsupportedInput,
            reason.clone(),
        ));
    }

    let prepared = prepare_request(draft)?;
    let rendered_request = RenderedRequest {
        method: prepared.method.clone(),
        url: prepared.url.clone(),
        headers: prepared
            .headers
            .iter()
            .map(|(key, value)| RenderedHeader {
                key: key.clone(),
                value: value.clone(),
            })
            .collect(),
        body_preview: prepared.body_preview.clone(),
    };

    let method: reqwest::Method = prepared.method.parse().context("Unsupported HTTP method")?;
    let mut builder = client.request(method, &prepared.url);

    let header_map = to_header_map(&prepared.headers)?;
    builder = builder.headers(header_map);

    builder = match prepared.body {
        PreparedBody::None => builder,
        PreparedBody::Text { text } => builder.body(text),
        PreparedBody::Multipart { fields } => {
            let mut form = multipart::Form::new();
            for (key, value) in fields {
                form = form.text(key, value.expose_secret().to_string());
            }
            builder.multipart(form)
        }
    };

    let started = Instant::now();
    let response = builder.send();

    let response_snapshot = match response {
        Ok(response) => response_to_snapshot(response, started, settings, draft),
        Err(error) => ResponseSnapshot {
            status: None,
            headers: Vec::new(),
            body_preview: String::new(),
            body_truncated: false,
            bytes_read: 0,
            elapsed_ms: started.elapsed().as_millis(),
            validation_errors: Vec::new(),
            transport_error: Some(format_transport_error(error)),
        },
    };

    let notes = if response_snapshot.validation_errors.is_empty() {
        "Request executed".to_string()
    } else {
        format!(
            "Request executed with {} validation issue(s)",
            response_snapshot.validation_errors.len()
        )
    };
    let (outcome, blocker) = classify_outcome(
        None,
        Some(&response_snapshot),
        draft.unsupported_reason.as_deref(),
        settings,
    );
    Ok(ExecutionResult {
        rendered_request,
        response_snapshot: Some(response_snapshot),
        outcome,
        blocker,
        notes,
    })
}

fn blocked_result(draft: &RequestDraft, blocker: Blocker, notes: String) -> ExecutionResult {
    ExecutionResult {
        rendered_request: RenderedRequest {
            method: draft.method.clone(),
            url: draft.endpoint_summary(),
            headers: Vec::new(),
            body_preview: None,
        },
        response_snapshot: None,
        outcome: crate::model::Outcome::Failure,
        blocker: Some(blocker),
        notes,
    }
}

struct PreparedRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body_preview: Option<String>,
    body: PreparedBody,
}

enum PreparedBody {
    None,
    Text { text: String },
    Multipart { fields: Vec<(String, SecretString)> },
}

fn prepare_request(draft: &RequestDraft) -> Result<PreparedRequest> {
    let base_url = draft
        .base_url
        .as_deref()
        .context("Base URL is required before running the request")?;
    let slot_values = collect_slot_values(draft)?;

    let encoded_path_values = encode_path_slot_values(&draft.path, &slot_values)?;
    let (rendered_path, missing_path) = replace_slots(&draft.path, &encoded_path_values);
    if !missing_path.is_empty() {
        anyhow::bail!("Missing required path values: {}", missing_path.join(", "));
    }

    let mut url = build_url(base_url, &rendered_path)?;
    for item in &draft.query {
        let value = render_value(
            &item.value,
            &slot_values,
            &format!("query parameter {}", item.key),
        )?;
        url.query_pairs_mut().append_pair(&item.key, &value);
    }

    let mut headers = Vec::<(String, String)>::new();
    for header in &draft.headers {
        let value = render_value(
            &header.value,
            &slot_values,
            &format!("header {}", header.key),
        )?;
        headers.push((header.key.clone(), value));
    }

    let auth_headers = apply_auth(&draft.auth, &slot_values, &mut url)?;
    headers.extend(auth_headers);

    let body = match &draft.body {
        BodyTemplate::None => PreparedBody::None,
        BodyTemplate::Json { template } => {
            let rendered = render_value(template, &slot_values, "JSON body")?;
            serde_json::from_str::<Value>(&rendered)
                .context("JSON body is invalid after slot substitution")?;
            ensure_content_type(&mut headers, "application/json");
            PreparedBody::Text { text: rendered }
        }
        BodyTemplate::Text { text } => PreparedBody::Text {
            text: render_value(text, &slot_values, "text body")?,
        },
        BodyTemplate::Form { fields } => {
            let encoded = encode_fields(fields, &slot_values)?;
            ensure_content_type(&mut headers, "application/x-www-form-urlencoded");
            PreparedBody::Text { text: encoded }
        }
        BodyTemplate::Multipart { fields } => PreparedBody::Multipart {
            fields: render_secret_fields(fields, &slot_values)?,
        },
    };

    ensure_request_policy(draft, &url, &headers)?;

    let body_preview = match &body {
        PreparedBody::None => None,
        PreparedBody::Text { text } => Some(text.clone()),
        PreparedBody::Multipart { fields } => Some(
            fields
                .iter()
                .map(|(key, value)| format!("{key}={}", value.expose_secret()))
                .collect::<Vec<_>>()
                .join("&"),
        ),
    };

    Ok(PreparedRequest {
        method: draft.method.clone(),
        url: url.to_string(),
        headers,
        body_preview,
        body,
    })
}

fn collect_slot_values(draft: &RequestDraft) -> Result<HashMap<String, String>> {
    let mut values = HashMap::new();
    for slot in &draft.slots {
        let current = slot.current_value.clone().unwrap_or_default();
        if slot.required && current.trim().is_empty() {
            anyhow::bail!("Missing required slot: {}", slot.name);
        }
        if !current.trim().is_empty() {
            values.insert(slot.name.clone(), current);
        }
    }
    Ok(values)
}

fn encode_path_slot_values(
    path_template: &str,
    values: &HashMap<String, String>,
) -> Result<HashMap<String, String>> {
    let path_slot_names = extract_slot_names(path_template);
    values
        .iter()
        .map(|(key, value)| {
            let value = if path_slot_names.contains(key) {
                encode_path_slot_value(value)?
            } else {
                value.clone()
            };
            Ok((key.clone(), value))
        })
        .collect()
}

fn encode_path_slot_value(value: &str) -> Result<String> {
    if path_slot_decodes_to_structural_value(value) {
        anyhow::bail!("Path slot value must not decode to a slash, backslash, or dot segment");
    }
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    Ok(encoded)
}

fn path_slot_decodes_to_structural_value(value: &str) -> bool {
    let mut candidate = value.as_bytes().to_vec();
    let max_rounds = candidate.len().saturating_add(1);
    for _ in 0..max_rounds {
        if candidate.contains(&b'/')
            || candidate.contains(&b'\\')
            || candidate.as_slice() == b"."
            || candidate.as_slice() == b".."
        {
            return true;
        }
        let decoded = percent_decode_once(&candidate);
        if decoded == candidate {
            return false;
        }
        candidate = decoded;
    }
    true
}

fn percent_decode_once(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%'
            && index + 2 < value.len()
            && let (Some(high), Some(low)) =
                (hex_value(value[index + 1]), hex_value(value[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(value[index]);
            index += 1;
        }
    }
    decoded
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn ensure_request_policy(
    draft: &RequestDraft,
    url: &url::Url,
    headers: &[(String, String)],
) -> Result<()> {
    for (header, _) in headers {
        if BLOCKED_REQUEST_HEADERS
            .iter()
            .any(|blocked| header.eq_ignore_ascii_case(blocked))
        {
            anyhow::bail!("Request header is blocked by policy: {header}");
        }
    }

    if !matches!(draft.method.to_ascii_uppercase().as_str(), "GET" | "HEAD") {
        return Ok(());
    }
    if url
        .query_pairs()
        .any(|(key, _)| key.eq_ignore_ascii_case("_method"))
    {
        anyhow::bail!("GET/HEAD requests must not contain a _method query parameter");
    }
    if matches!(
        &draft.body,
        BodyTemplate::Form { fields } | BodyTemplate::Multipart { fields }
            if fields.iter().any(|field| field.key.eq_ignore_ascii_case("_method"))
    ) {
        anyhow::bail!("GET/HEAD requests must not contain a _method form field");
    }
    Ok(())
}

fn render_value(template: &str, values: &HashMap<String, String>, label: &str) -> Result<String> {
    let (rendered, missing) = replace_slots(template, values);
    if !missing.is_empty() {
        anyhow::bail!("Missing values for {label}: {}", missing.join(", "));
    }
    if looks_like_slot_value(&rendered) {
        anyhow::bail!("Unresolved placeholder remains in {label}");
    }
    Ok(rendered)
}

fn encode_fields(fields: &[KeyValueField], values: &HashMap<String, String>) -> Result<String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for field in fields {
        serializer.append_pair(
            &field.key,
            &render_value(&field.value, values, &format!("body field {}", field.key))?,
        );
    }
    Ok(serializer.finish())
}

fn render_secret_fields(
    fields: &[KeyValueField],
    values: &HashMap<String, String>,
) -> Result<Vec<(String, SecretString)>> {
    let mut rendered = Vec::new();
    for field in fields {
        let value = render_value(
            &field.value,
            values,
            &format!("multipart field {}", field.key),
        )?;
        rendered.push((field.key.clone(), SecretString::new(value.into())));
    }
    Ok(rendered)
}

fn apply_auth(
    auth: &AuthStyle,
    values: &HashMap<String, String>,
    url: &mut url::Url,
) -> Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    match auth {
        AuthStyle::None => {}
        AuthStyle::Bearer {
            token_slot,
            header_name,
        } => {
            let token = values
                .get(token_slot)
                .with_context(|| format!("Missing auth slot {token_slot}"))?;
            headers.push((header_name.clone(), format!("Bearer {token}")));
        }
        AuthStyle::Basic {
            username_slot,
            password_slot,
        } => {
            let username = values
                .get(username_slot)
                .with_context(|| format!("Missing auth slot {username_slot}"))?;
            let password = values
                .get(password_slot)
                .with_context(|| format!("Missing auth slot {password_slot}"))?;
            let raw = format!("{username}:{password}");
            headers.push((
                "Authorization".to_string(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(raw)
                ),
            ));
        }
        AuthStyle::HeaderApiKey {
            header_name,
            slot_name,
        } => {
            let value = values
                .get(slot_name)
                .with_context(|| format!("Missing auth slot {slot_name}"))?;
            headers.push((header_name.clone(), value.clone()));
        }
        AuthStyle::QueryApiKey {
            param_name,
            slot_name,
        } => {
            let value = values
                .get(slot_name)
                .with_context(|| format!("Missing auth slot {slot_name}"))?;
            url.query_pairs_mut().append_pair(param_name, value);
        }
    }
    Ok(headers)
}

fn ensure_content_type(headers: &mut Vec<(String, String)>, value: &str) {
    if headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("content-type"))
    {
        return;
    }
    headers.push(("Content-Type".to_string(), value.to_string()));
}

fn build_url(base_url: &str, path: &str) -> Result<url::Url> {
    if path.starts_with("http://") || path.starts_with("https://") {
        anyhow::bail!("Request path must not override the verified base URL");
    }
    let base = url::Url::parse(base_url).context("Base URL must be an absolute URL")?;
    validate_http_url(&base, "Base URL")?;
    if base.query().is_some() || base.fragment().is_some() {
        anyhow::bail!("Base URL must not contain a query or fragment");
    }
    let normalized = if path.starts_with('/') {
        format!("{}{}", base_url.trim_end_matches('/'), path)
    } else {
        format!("{}/{}", base_url.trim_end_matches('/'), path)
    };
    let parsed =
        url::Url::parse(&normalized).with_context(|| format!("Malformed URL: {normalized}"))?;
    validate_http_url(&parsed, "Rendered request URL")?;
    if parsed.origin() != base.origin() {
        anyhow::bail!("Rendered request URL must keep the verified origin");
    }
    Ok(parsed)
}

fn validate_http_url(url: &url::Url, label: &str) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("{label} must use http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{label} must not contain user information");
    }
    if url.fragment().is_some() {
        anyhow::bail!("{label} must not contain a fragment");
    }
    match url.host() {
        Some(url::Host::Ipv4(address)) if disallowed_ipv4(address) => {
            anyhow::bail!("{label} targets a disallowed IPv4 address class");
        }
        Some(url::Host::Ipv6(address)) if disallowed_ipv6(address) => {
            anyhow::bail!("{label} targets a disallowed IPv6 address class");
        }
        Some(_) => {}
        None => anyhow::bail!("{label} must include a host"),
    }
    Ok(())
}

fn disallowed_ipv4(address: std::net::Ipv4Addr) -> bool {
    address.is_unspecified() || address.is_link_local() || address.is_multicast()
}

fn disallowed_ipv6(address: std::net::Ipv6Addr) -> bool {
    address.is_unspecified()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || address.to_ipv4_mapped().is_some_and(disallowed_ipv4)
}

fn disallowed_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => disallowed_ipv4(address),
        IpAddr::V6(address) => disallowed_ipv6(address),
    }
}

fn to_header_map(headers: &[(String, String)]) -> Result<HeaderMap> {
    let mut map = HeaderMap::new();
    for (key, value) in headers {
        let name = HeaderName::from_bytes(key.as_bytes())
            .with_context(|| format!("Invalid header name: {key}"))?;
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("Invalid value for header {key}"))?;
        map.insert(name, value);
    }
    Ok(map)
}

fn response_to_snapshot(
    mut response: reqwest::blocking::Response,
    started: Instant,
    settings: &AppSettings,
    draft: &RequestDraft,
) -> ResponseSnapshot {
    let status = response.status().as_u16();
    let headers: Vec<RenderedHeader> = response
        .headers()
        .iter()
        .map(|(key, value)| RenderedHeader {
            key: key.as_str().to_string(),
            value: value.to_str().unwrap_or("<binary>").to_string(),
        })
        .collect();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let hard_limit = settings.response_body_limit_bytes.max(1);
    let mut bytes = Vec::with_capacity(hard_limit.min(64 * 1024) + 1);
    let read_result = response
        .by_ref()
        .take((hard_limit as u64).saturating_add(1))
        .read_to_end(&mut bytes);
    if let Err(error) = read_result {
        return ResponseSnapshot {
            status: Some(status),
            headers,
            body_preview: String::new(),
            body_truncated: false,
            bytes_read: 0,
            elapsed_ms: started.elapsed().as_millis(),
            validation_errors: Vec::new(),
            transport_error: Some(error.to_string()),
        };
    }
    let bytes_read = bytes.len();
    let body_truncated = bytes_read > hard_limit;
    if body_truncated {
        bytes.truncate(hard_limit);
    }

    let preview_limit = settings
        .response_preview_limit_bytes
        .min(hard_limit)
        .min(bytes.len());
    let preview_bytes = &bytes[..preview_limit];
    let body_text = String::from_utf8_lossy(preview_bytes).to_string();
    let body_preview = if content_type.contains("json") {
        pretty_json(&body_text).unwrap_or(body_text)
    } else {
        body_text
    };

    let mut validation_errors = Vec::new();
    if body_truncated {
        validation_errors.push(format!(
            "Response body exceeded the configured hard limit of {hard_limit} bytes"
        ));
    } else if let Some(schema) = draft.response_schema.as_ref() {
        if !content_type.contains("json") {
            validation_errors
                .push("Response schema expected JSON but Content-Type was not JSON".to_string());
        } else {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(body) => {
                    validation_errors.extend(validate_json_schema(&schema.schema, &body).errors);
                }
                Err(_) => validation_errors.push(
                    "Response schema expected JSON but the response body was malformed".to_string(),
                ),
            }
        }
    }

    debug!("HTTP response status={status}");
    ResponseSnapshot {
        status: Some(status),
        headers,
        body_preview,
        body_truncated,
        bytes_read,
        elapsed_ms: started.elapsed().as_millis(),
        validation_errors,
        transport_error: None,
    }
}

fn pretty_json(text: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(text).ok()?;
    serde_json::to_string_pretty(&value).ok()
}

fn format_transport_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    use reqwest::blocking::Client;
    use reqwest::dns::{Name, Resolve};

    use super::{
        PolicyDnsResolver, build_http_client, format_transport_error, prepare_request,
        validate_resolved_addresses,
    };
    use crate::model::{
        AppSettings, AuthStyle, BodyTemplate, Confidence, FieldConfidence, RequestDraft,
        RuntimeSlot, SlotLocation,
    };

    #[test]
    fn prepares_url_and_body() {
        let draft = RequestDraft {
            operation_id: "x".to_string(),
            name: "Test".to_string(),
            method: "POST".to_string(),
            base_url: Some("https://api.example.com".to_string()),
            path: "/v1/customers/{{customer_id}}".to_string(),
            headers: Vec::new(),
            query: Vec::new(),
            body: BodyTemplate::Json {
                template: "{\"id\":\"{{customer_id}}\"}".to_string(),
            },
            auth: AuthStyle::None,
            slots: vec![RuntimeSlot {
                name: "customer_id".to_string(),
                location: SlotLocation::Path,
                required: true,
                current_value: Some("cus_123".to_string()),
                description: String::new(),
                confidence: Confidence::High,
            }],
            evidence: Vec::new(),
            confidence: FieldConfidence {
                overall: Confidence::High,
                notes: String::new(),
            },
            response_schema: None,
            unsupported_reason: None,
            source_kinds: Vec::new(),
        };
        let prepared = prepare_request(&draft).expect("request should prepare");
        assert!(prepared.url.ends_with("/v1/customers/cus_123"));
    }

    #[test]
    fn builds_http_client() {
        let client: Client =
            build_http_client(&AppSettings::default()).expect("client should build");
        let _ = client;
    }

    #[test]
    fn dns_policy_validates_the_complete_answer_set_before_connecting() {
        let addresses = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 20)), 0),
        ];

        let error = validate_resolved_addresses(addresses)
            .expect_err("a disallowed answer must reject the entire DNS result");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("disallowed IPv4"));
        assert!(!error.to_string().contains("169.254.10.20"));
    }

    #[test]
    fn dns_policy_keeps_local_first_loopback_and_private_addresses() {
        let addresses = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)), 0),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        ];

        let validated = validate_resolved_addresses(addresses.clone())
            .expect("local-first address classes remain permitted");

        assert_eq!(validated, addresses);
    }

    #[test]
    fn dns_policy_applies_ipv4_rules_to_mapped_ipv6_answers() {
        let mapped_link_local = Ipv4Addr::new(169, 254, 10, 20).to_ipv6_mapped();
        let addresses = vec![SocketAddr::new(IpAddr::V6(mapped_link_local), 0)];

        let error = validate_resolved_addresses(addresses)
            .expect_err("mapped link-local IPv4 must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("disallowed IPv6"));
    }

    #[test]
    fn dns_policy_keeps_mapped_loopback_private_and_ipv6_ula_addresses() {
        let addresses = vec![
            SocketAddr::new(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 0),
            SocketAddr::new(
                IpAddr::V6(Ipv4Addr::new(10, 20, 30, 40).to_ipv6_mapped()),
                0,
            ),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), 0),
        ];

        let validated = validate_resolved_addresses(addresses.clone())
            .expect("local-first mapped and private IPv6 addresses remain permitted");

        assert_eq!(validated, addresses);
    }

    #[test]
    fn dns_policy_pins_first_validated_set_when_lookup_source_changes() {
        let first = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0)];
        let changed = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            0,
        )];
        let source = Arc::new(Mutex::new(first.clone()));
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let resolver = PolicyDnsResolver::with_lookup({
            let source = Arc::clone(&source);
            let lookup_count = Arc::clone(&lookup_count);
            move |_| {
                lookup_count.fetch_add(1, Ordering::SeqCst);
                Ok(source.lock().expect("source lock").clone())
            }
        });

        let initially_pinned = resolver
            .pinned_addresses("EXAMPLE.test.")
            .expect("first lookup");
        *source.lock().expect("source lock") = changed;
        let still_pinned = resolver
            .pinned_addresses("example.test")
            .expect("cached lookup");

        assert_eq!(initially_pinned.as_ref(), first.as_slice());
        assert_eq!(still_pinned.as_ref(), first.as_slice());
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dns_policy_concurrent_first_lookup_creates_one_pin() {
        let addresses = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 0)];
        let lookup_count = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(PolicyDnsResolver::with_lookup({
            let addresses = addresses.clone();
            let lookup_count = Arc::clone(&lookup_count);
            move |_| {
                lookup_count.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                Ok(addresses.clone())
            }
        }));

        let workers = (0..8)
            .map(|_| {
                let resolver = Arc::clone(&resolver);
                thread::spawn(move || resolver.pinned_addresses("race.test").expect("lookup"))
            })
            .collect::<Vec<_>>();

        for worker in workers {
            assert_eq!(
                worker.join().expect("worker").as_ref(),
                addresses.as_slice()
            );
        }
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dns_policy_dispatches_blocking_system_lookup_off_the_runtime_thread() {
        let (lookup_started_tx, lookup_started_rx) = mpsc::channel();
        let (resolve_returned_tx, resolve_returned_rx) = mpsc::channel();
        let release_lookup = Arc::new((Mutex::new(false), Condvar::new()));
        let resolver = Arc::new(PolicyDnsResolver::with_lookup({
            let release_lookup = Arc::clone(&release_lookup);
            move |_| {
                lookup_started_tx.send(()).expect("lookup started");
                let (released, condition) = &*release_lookup;
                let mut released = released.lock().expect("release lock");
                while !*released {
                    released = condition.wait(released).expect("release wait");
                }
                Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])
            }
        }));
        let resolve_thread = thread::spawn(move || {
            let name: Name = "slow.test".parse().expect("DNS name");
            let future = resolver.resolve(name);
            resolve_returned_tx.send(()).expect("resolve returned");
            drop(future);
        });

        lookup_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("lookup worker must start");
        let returned_while_lookup_blocked = resolve_returned_rx
            .recv_timeout(Duration::from_millis(250))
            .is_ok();
        {
            let (released, condition) = &*release_lookup;
            *released.lock().expect("release lock") = true;
            condition.notify_all();
        }
        resolve_thread.join().expect("resolve thread");

        assert!(
            returned_while_lookup_blocked,
            "Resolve::resolve must not block reqwest's single runtime thread"
        );
    }

    #[test]
    fn dns_policy_pinned_addresses_drive_connections_without_pool_reuse() {
        fn read_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    return Ok(request);
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    return Ok(request);
                }
            }
        }

        fn write_response(stream: &mut TcpStream, close: bool) {
            let connection = if close { "close" } else { "keep-alive" };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {connection}\r\n\r\nok"
            )
            .expect("response");
            stream.flush().expect("flush");
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut first_stream, _) = listener.accept().expect("first connection");
            let first_request = read_request(&mut first_stream).expect("first request");
            write_response(&mut first_stream, false);
            first_stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");

            match read_request(&mut first_stream) {
                Ok(request) if !request.is_empty() => {
                    write_response(&mut first_stream, true);
                    (1_usize, first_request)
                }
                Ok(_) | Err(_) => {
                    let (mut second_stream, _) = listener.accept().expect("second connection");
                    let _ = read_request(&mut second_stream).expect("second request");
                    write_response(&mut second_stream, true);
                    (2_usize, first_request)
                }
            }
        });

        let lookup_count = Arc::new(AtomicUsize::new(0));
        let resolver = PolicyDnsResolver::with_lookup({
            let lookup_count = Arc::clone(&lookup_count);
            move |host| {
                assert_eq!(host, "pinned.test");
                lookup_count.fetch_add(1, Ordering::SeqCst);
                Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])
            }
        });
        let client = Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(resolver))
            .build()
            .expect("client");
        let url = format!("http://pinned.test:{}/health", address.port());

        assert_eq!(
            client
                .get(&url)
                .send()
                .expect("first response")
                .text()
                .unwrap(),
            "ok"
        );
        assert_eq!(
            client
                .get(&url)
                .send()
                .expect("second response")
                .text()
                .unwrap(),
            "ok"
        );

        let (connection_count, first_request) = server.join().expect("server");
        let first_request = String::from_utf8_lossy(&first_request);
        assert_eq!(
            connection_count, 2,
            "HTTP connection pooling must stay disabled"
        );
        assert!(first_request.starts_with("GET /health HTTP/1.1\r\n"));
        assert!(first_request.contains(&format!("host: pinned.test:{}", address.port())));
        assert_eq!(lookup_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dns_policy_sanitizes_lookup_and_transport_error_details() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolver = PolicyDnsResolver::with_lookup({
            let attempts = Arc::clone(&attempts);
            move |_| {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(std::io::Error::other(
                        "internal resolver detail 169.254.169.254",
                    ))
                } else {
                    Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)])
                }
            }
        });
        let dns_error = resolver
            .pinned_addresses("safe.example")
            .expect_err("lookup must fail");
        assert_eq!(dns_error.to_string(), "DNS resolution failed");
        assert!(!dns_error.to_string().contains("169.254.169.254"));
        assert_eq!(
            resolver
                .pinned_addresses("safe.example")
                .expect("a failed lookup is retryable")
                .as_ref(),
            &[SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)]
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).expect("request");
            stream
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("response");
            stream.flush().expect("flush");
        });
        let secret = "transport_secret_marker";
        let response = Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .get(format!("http://{address}/?api_key={secret}"))
            .send()
            .expect("response");
        let error = response.error_for_status().expect_err("status error");
        assert!(error.url().is_some_and(|url| url.as_str().contains(secret)));
        let safe_error = format_transport_error(error);
        assert!(!safe_error.contains(secret));
        server.join().expect("server");
    }
}
