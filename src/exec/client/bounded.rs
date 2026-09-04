//! Bounded execution for machine consumers. Shares request/auth preparation with the GUI.
use std::io::Read;

use anyhow::{Result, bail};
use reqwest::blocking::{Client, multipart};
use secrecy::ExposeSecret;

use super::{PreparedBody, prepare_request, to_header_map};
use crate::model::RequestDraft;

pub struct BoundedResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

pub fn execute_request_bounded(
    draft: &RequestDraft,
    client: &Client,
    expected_origin: &str,
    expected_path: &str,
    limit: usize,
) -> Result<BoundedResponse> {
    let prepared = prepare_request(draft)?;
    let url = url::Url::parse(&prepared.url)?;
    if url.origin().ascii_serialization() != expected_origin
        || url.path() != expected_path
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("Prepared request exceeds the package URL boundary");
    }
    let mut request = client
        .request(prepared.method.parse()?, url)
        .headers(to_header_map(&prepared.headers)?);
    request = match prepared.body {
        PreparedBody::None => request,
        PreparedBody::Text { text } => request.body(text),
        PreparedBody::Multipart { fields } => {
            let mut form = multipart::Form::new();
            for (key, value) in fields {
                form = form.text(key, value.expose_secret().to_string());
            }
            request.multipart(form)
        }
    };
    let response = request
        .send()
        .map_err(|_| anyhow::anyhow!("HTTP request failed or timed out"))?;
    let status = response.status().as_u16();
    // A redirect can escape the declared path or forward credentials. The caller's client
    // disables redirects; this also makes that boundary explicit in the result.
    if response.status().is_redirection() {
        bail!("Redirect blocked: the tool may only call its declared endpoint");
    }
    if draft.method != "HEAD"
        && response
            .content_length()
            .is_some_and(|length| length > limit as u64)
    {
        bail!("Response too large: limit is {limit} bytes; no partial response returned");
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let mut body = Vec::new();
    response
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| anyhow::anyhow!("Could not read HTTP response"))?;
    if body.len() > limit {
        bail!("Response too large: limit is {limit} bytes; no partial response returned");
    }
    Ok(BoundedResponse {
        status,
        content_type,
        body,
    })
}
