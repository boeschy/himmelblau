/*
   Unix Azure Entra ID implementation
   Sign-in for Entra ID domains federated to Okta Identity Engine.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
//! Entra ID sign-in for domains federated to Okta Identity Engine.
//!
//! The browser flow is replayed without a browser: an authorization-code
//! request with `domain_hint` makes Entra ID redirect to the Okta-hosted
//! sign-in page, whose `stateToken` drives the Okta IDX API (password, then an
//! Okta Verify push or one-time code). Okta's WS-Federation or SAML response is
//! posted back to Entra ID, and the resulting code is redeemed through
//! libhimmelblau's PKCE flow. Each sign-in uses its own cookie jar, so Okta
//! sessions are never shared between users or sign-ins.

use super::interface::AuthRequest;
use crate::i18n::{tr, tr_fmt};
use himmelblau::auth::{BrokerClientApplication, UserToken as UnixUserToken};
use himmelblau::AuthorizationCodePkceFlow;
use regex::Regex;
use reqwest::{header, Client, Response, Url};
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const OKTA_IDX_CONTENT_TYPE: &str = "application/ion+json; okta-version=1.0.0";
const OKTA_FORM_CONTENT_TYPE: &str = "application/json; okta-version=1.0.0";
const MAX_IDX_STEPS: usize = 12;
const MAX_REDIRECTS: usize = 10;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Okta Verify push challenges expire after five minutes.
const PUSH_TIMEOUT_SECS: u32 = 300;
const DEFAULT_PUSH_REFRESH_MS: u64 = 4000;
/// Device Registration Service, the resource of device enrollment tokens.
const DRS_SCOPE: &str = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9/.default";
/// Redirect URI of the Microsoft Authentication Broker client used by
/// libhimmelblau for device registration.
const BROKER_DRS_REDIRECT_URI: &str = "ms-aadj-redir://auth/drs";

/// The second factor of an Okta-federated sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OktaFactor {
    Push,
    Code,
}

/// Map the configured mfa_method (Entra name or Okta method type) to a factor.
pub(crate) fn preferred_factor(mfa_method: Option<&str>) -> Option<OktaFactor> {
    match mfa_method?.trim() {
        "PhoneAppNotification" | "CompanionAppsNotification" | "push" => Some(OktaFactor::Push),
        "PhoneAppOTP" | "otp" | "totp" => Some(OktaFactor::Code),
        _ => None,
    }
}

/// The next step of an IDX transaction.
#[derive(Debug, PartialEq, Eq)]
enum IdxAction {
    /// Post `body` (without the state handle) to `href`.
    Submit {
        href: String,
        accepts: Option<String>,
        body: SecretJson,
        submits_password: bool,
    },
    /// Wait for the user to approve a push, polling `href`.
    AwaitPush {
        href: String,
        accepts: Option<String>,
        refresh_ms: u64,
        correct_answer: Option<String>,
    },
    /// Ask for a one-time code and post it as `credentials.<credential_field>`.
    AwaitCode {
        href: String,
        accepts: Option<String>,
        credential_field: String,
    },
    /// Authentication finished; `href` establishes the Okta session.
    Success { href: String },
}

/// A JSON request body that may contain the password or a one-time code.
#[derive(PartialEq, Eq)]
struct SecretJson(Value);

impl fmt::Debug for SecretJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        erase(&mut self.0);
    }
}

fn erase(value: &mut Value) {
    match value {
        Value::String(s) => zeroize::Zeroize::zeroize(s),
        Value::Array(a) => a.iter_mut().for_each(erase),
        Value::Object(o) => o.values_mut().for_each(erase),
        _ => {}
    }
}

/// What the IDX decision may use from the caller.
#[derive(Clone, Copy)]
struct IdxContext<'a> {
    username: &'a str,
    password: Option<&'a str>,
    password_submitted: bool,
    preference: Option<OktaFactor>,
}

/// Extract the IDX `stateToken` from an Okta-hosted sign-in page.
fn extract_state_token(html: &str) -> Option<String> {
    let mut rest = html;
    while let Some(pos) = rest.find("stateToken") {
        rest = &rest[pos + "stateToken".len()..];
        let after = rest.trim_start_matches(['"', '\'']);
        let after = after.trim_start();
        let Some(after) = after.strip_prefix('=').or_else(|| after.strip_prefix(':')) else {
            continue;
        };
        let after = after.trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '\'' || *c == '"') else {
            continue;
        };
        if let Some(token) = decode_js_string(&after[quote.len_utf8()..], quote) {
            if !token.is_empty() {
                return Some(token);
            }
        }
    }
    None
}

/// Decode a JavaScript string literal body up to the closing `quote`.
fn decode_js_string(input: &str, quote: char) -> Option<String> {
    let mut out = String::new();
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == quote {
            return Some(out);
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'x' => {
                let hex: String = chars.by_ref().take(2).collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            'u' => {
                let hex: String = chars.by_ref().take(4).collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            'n' => out.push('\n'),
            other => out.push(other),
        }
    }
    None
}

/// The first error message of an IDX response, if any.
fn idx_error_message(resp: &Value) -> Option<String> {
    resp["messages"]["value"]
        .as_array()?
        .iter()
        .filter(|m| m["class"].as_str().is_none_or(|c| c == "ERROR"))
        .find_map(|m| m["message"].as_str().map(str::to_string))
}

fn remediations(resp: &Value) -> Vec<&Value> {
    resp["remediation"]["value"]
        .as_array()
        .map(|values| values.iter().collect())
        .unwrap_or_default()
}

fn remediation<'a>(resp: &'a Value, name: &str) -> Option<&'a Value> {
    remediations(resp)
        .into_iter()
        .find(|r| r["name"].as_str() == Some(name))
}

fn href(rem: &Value) -> Result<String, String> {
    rem["href"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "Okta remediation has no href".to_string())
}

fn accepts(rem: &Value) -> Option<String> {
    rem["accepts"].as_str().map(str::to_string)
}

fn has_field(rem: &Value, name: &str) -> bool {
    rem["value"]
        .as_array()
        .is_some_and(|fields| fields.iter().any(|f| f["name"].as_str() == Some(name)))
}

/// The authenticator the current challenge belongs to.
fn current_authenticator(resp: &Value) -> &Value {
    let enrollment = &resp["currentAuthenticatorEnrollment"]["value"];
    if enrollment.is_object() {
        enrollment
    } else {
        &resp["currentAuthenticator"]["value"]
    }
}

/// Okta Verify expects its one-time code as `totp`; other one-time code
/// authenticators use `passcode`, matching Okta Auth JS.
fn code_credential_field(resp: &Value) -> String {
    let field = match current_authenticator(resp)["key"].as_str() {
        Some("okta_verify") => "totp",
        _ => "passcode",
    };
    field.to_string()
}

fn is_password_challenge(resp: &Value) -> bool {
    let current = current_authenticator(resp);
    current["type"].as_str() == Some("password") || current["key"].as_str() == Some("okta_password")
}

/// An authenticator choice of a select or verification-data remediation.
#[derive(Debug, PartialEq, Eq)]
struct AuthenticatorOption {
    id: String,
    method_types: Vec<String>,
}

fn method_types(form_fields: &[Value]) -> Vec<String> {
    form_fields
        .iter()
        .filter(|f| f["name"].as_str() == Some("methodType"))
        .flat_map(|f| match f["value"].as_str() {
            Some(value) => vec![value.to_string()],
            None => f["options"]
                .as_array()
                .map(|options| {
                    options
                        .iter()
                        .filter_map(|o| o["value"].as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect()
}

fn form_option(form_fields: &[Value]) -> Option<AuthenticatorOption> {
    let id = form_fields
        .iter()
        .find(|f| f["name"].as_str() == Some("id"))
        .and_then(|f| f["value"].as_str())?;
    Some(AuthenticatorOption {
        id: id.to_string(),
        method_types: method_types(form_fields),
    })
}

fn authenticator_field(rem: &Value) -> Option<&Value> {
    rem["value"]
        .as_array()?
        .iter()
        .find(|f| f["name"].as_str() == Some("authenticator"))
}

/// Options of a `select-authenticator-authenticate` remediation.
fn select_options(rem: &Value) -> Vec<AuthenticatorOption> {
    authenticator_field(rem)
        .and_then(|field| field["options"].as_array())
        .map(|options| {
            options
                .iter()
                .filter_map(|o| o["value"]["form"]["value"].as_array())
                .filter_map(|fields| form_option(fields))
                .collect()
        })
        .unwrap_or_default()
}

/// The single option of an `authenticator-verification-data` remediation.
fn verification_option(rem: &Value) -> Option<AuthenticatorOption> {
    authenticator_field(rem)
        .and_then(|field| field["form"]["value"].as_array())
        .and_then(|fields| form_option(fields))
}

fn code_method(option: &AuthenticatorOption) -> Option<&str> {
    ["totp", "otp"]
        .into_iter()
        .find(|m| option.method_types.iter().any(|t| t == m))
}

/// Choose an authenticator and method for the second factor. FastPass and
/// other device-bound methods cannot be completed without a browser.
fn choose_factor(
    options: &[AuthenticatorOption],
    preference: Option<OktaFactor>,
) -> Option<(String, String)> {
    let push = options
        .iter()
        .find(|o| o.method_types.iter().any(|t| t == "push"))
        .map(|o| (o.id.clone(), "push".to_string()));
    let code = options
        .iter()
        .find_map(|o| code_method(o).map(|m| (o.id.clone(), m.to_string())));
    match preference {
        Some(OktaFactor::Code) => code.or(push),
        _ => push.or(code),
    }
}

/// Decide the next IDX step for `resp`.
fn next_action(resp: &Value, ctx: &IdxContext) -> Result<IdxAction, String> {
    if let Some(href) = resp["success"]["href"].as_str() {
        return Ok(IdxAction::Success {
            href: href.to_string(),
        });
    }
    let failure = |default: &str| idx_error_message(resp).unwrap_or_else(|| default.to_string());

    if let Some(rem) = remediation(resp, "challenge-poll") {
        let answer = &current_authenticator(resp)["contextualData"]["correctAnswer"];
        let correct_answer = answer
            .as_str()
            .map(str::to_string)
            .or_else(|| answer.as_u64().map(|n| n.to_string()));
        return Ok(IdxAction::AwaitPush {
            href: href(rem)?,
            accepts: accepts(rem),
            refresh_ms: rem["refresh"].as_u64().unwrap_or(DEFAULT_PUSH_REFRESH_MS),
            correct_answer,
        });
    }

    if let Some(rem) = remediation(resp, "identify") {
        if ctx.password_submitted {
            return Err(failure("Okta did not accept the user name or password"));
        }
        let mut body = json!({ "identifier": ctx.username });
        let mut submits_password = false;
        if has_field(rem, "credentials") {
            let password = ctx.password.ok_or("Okta requires a password")?;
            body["credentials"] = json!({ "passcode": password });
            submits_password = true;
        }
        return Ok(IdxAction::Submit {
            href: href(rem)?,
            accepts: accepts(rem),
            body: SecretJson(body),
            submits_password,
        });
    }

    if let Some(rem) = remediation(resp, "challenge-authenticator") {
        if !is_password_challenge(resp) {
            return Ok(IdxAction::AwaitCode {
                href: href(rem)?,
                accepts: accepts(rem),
                credential_field: code_credential_field(resp),
            });
        }
        if ctx.password_submitted {
            return Err(failure("Okta did not accept the password"));
        }
        let password = ctx.password.ok_or("Okta requires a password")?;
        return Ok(IdxAction::Submit {
            href: href(rem)?,
            accepts: accepts(rem),
            body: SecretJson(json!({ "credentials": { "passcode": password } })),
            submits_password: true,
        });
    }

    if let Some(rem) = remediation(resp, "select-authenticator-authenticate") {
        let options = select_options(rem);
        let password_option = options
            .iter()
            .find(|o| o.method_types.iter().any(|t| t == "password"));
        let choice = match password_option {
            Some(option) if !ctx.password_submitted => {
                Some((option.id.clone(), "password".to_string()))
            }
            _ => choose_factor(&options, ctx.preference),
        };
        let (id, method_type) = choice.ok_or_else(|| {
            "No supported Okta authenticator is available. \
             Enroll Okta Verify for push notifications or one-time codes."
                .to_string()
        })?;
        return Ok(IdxAction::Submit {
            href: href(rem)?,
            accepts: accepts(rem),
            body: SecretJson(json!({ "authenticator": { "id": id, "methodType": method_type } })),
            submits_password: false,
        });
    }

    if let Some(rem) = remediation(resp, "authenticator-verification-data") {
        let option = verification_option(rem)
            .ok_or_else(|| "Okta verification data has no authenticator".to_string())?;
        let (id, method_type) = choose_factor(std::slice::from_ref(&option), ctx.preference)
            .ok_or_else(|| {
                "The selected Okta authenticator supports neither push nor one-time codes"
                    .to_string()
            })?;
        return Ok(IdxAction::Submit {
            href: href(rem)?,
            accepts: accepts(rem),
            body: SecretJson(json!({ "authenticator": { "id": id, "methodType": method_type } })),
            submits_password: false,
        });
    }

    let names: Vec<&str> = remediations(resp)
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    Err(failure(&format!(
        "Okta requested an unsupported sign-in step: {}",
        names.join(", ")
    )))
}

fn with_state_handle(mut body: SecretJson, state_handle: &str) -> SecretJson {
    if let Value::Object(ref mut map) = body.0 {
        map.insert(
            "stateHandle".to_string(),
            Value::String(state_handle.to_string()),
        );
    }
    body
}

/// Decode the HTML character references used in attribute values.
fn decode_html_entities(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let decoded = rest.find(';').filter(|end| *end <= 10).and_then(|end| {
            let entity = &rest[1..end];
            let c = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            }?;
            Some((c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn html_attribute(tag: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"(?is)\s{}\s*=\s*(?:"([^"]*)"|'([^']*)')"#,
        regex::escape(name)
    ))
    .ok()?;
    let captures = re.captures(tag)?;
    captures
        .get(1)
        .or_else(|| captures.get(2))
        .map(|m| decode_html_entities(m.as_str()))
}

/// A sign-in response form that the identity provider would auto-post.
#[derive(Debug, PartialEq, Eq)]
struct PostForm {
    action: String,
    fields: Vec<(String, String)>,
}

impl PostForm {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Find the WS-Federation (`wresult`) or SAML (`SAMLResponse`) form.
fn parse_sign_in_form(html: &str) -> Option<PostForm> {
    let form_re = Regex::new(r"(?is)<form\b[^>]*>.*?</form>").ok()?;
    let form_tag_re = Regex::new(r"(?is)^<form\b[^>]*>").ok()?;
    let input_re = Regex::new(r"(?is)<input\b[^>]*>").ok()?;
    for form in form_re.find_iter(html) {
        let form = form.as_str();
        let Some(tag) = form_tag_re.find(form) else {
            continue;
        };
        let Some(action) = html_attribute(tag.as_str(), "action") else {
            continue;
        };
        let fields: Vec<(String, String)> = input_re
            .find_iter(form)
            .filter_map(|input| {
                let input = input.as_str();
                Some((
                    html_attribute(input, "name")?,
                    html_attribute(input, "value").unwrap_or_default(),
                ))
            })
            .collect();
        let form = PostForm { action, fields };
        let ws_fed = form.field("wresult").is_some_and(|v| !v.is_empty());
        let saml = form.field("SAMLResponse").is_some_and(|v| !v.is_empty());
        if ws_fed || saml {
            return Some(form);
        }
    }
    None
}

/// The `$Config` object of an Entra ID sign-in page.
fn parse_entra_config(html: &str) -> Option<Value> {
    let start = html.find("$Config=")? + "$Config=".len();
    serde_json::Deserializer::from_str(&html[start..])
        .into_iter::<Value>()
        .next()?
        .ok()
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn https_url(value: &str) -> Option<Url> {
    Url::parse(value).ok().filter(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

/// Ask Entra ID where `account_id` signs in. Returns the identity provider
/// sign-in URL if the domain is federated to something other than AD FS,
/// which libhimmelblau already supports.
pub(crate) async fn federated_idp_url(
    authority_host: &str,
    account_id: &str,
    timeout: Duration,
) -> Result<Option<Url>, String> {
    let mut url = Url::parse(&format!("https://{}/GetUserRealm.srf", authority_host))
        .map_err(|e| format!("Invalid authority host: {e}"))?;
    url.query_pairs_mut().append_pair("login", account_id);
    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
    let realm: Value = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("User realm request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Invalid user realm response: {e}"))?;
    if realm["NameSpaceType"].as_str() != Some("Federated") {
        return Ok(None);
    }
    let Some(auth_url) = realm["AuthURL"].as_str().and_then(https_url) else {
        return Ok(None);
    };
    let is_adfs = auth_url
        .path_segments()
        .is_some_and(|mut segments| segments.any(|s| s.eq_ignore_ascii_case("adfs")));
    Ok((!is_adfs).then_some(auth_url))
}

/// The outcome of one step of an Okta-federated sign-in.
pub(crate) enum FederationStep {
    /// Show this prompt to the user.
    Prompt(AuthRequest),
    /// A push approval is still pending.
    Wait,
    /// Entra ID issued a token for the device enrollment resource.
    Token(Box<UnixUserToken>),
    /// The sign-in failed with this user-visible message.
    Denied(String),
}

enum Progress {
    Finished(String),
    Push {
        pending: Pending,
        correct_answer: Option<String>,
        refresh_ms: u64,
    },
    Code {
        pending: Pending,
        rejected: Option<String>,
    },
}

struct Pending {
    state_handle: Zeroizing<String>,
    href: String,
    accepts: Option<String>,
    credential_field: String,
    max_poll_attempts: u32,
}

/// An Okta-federated sign-in for one PAM session. It holds the password and
/// the Okta session, so it is never serialized or logged.
pub struct OktaFederationSession {
    client: Client,
    entra_origin: Url,
    idp_origin: Url,
    username: String,
    password: Option<Zeroizing<String>>,
    preference: Option<OktaFactor>,
    pkce: Option<AuthorizationCodePkceFlow>,
    pending: Option<Pending>,
}

impl fmt::Debug for OktaFederationSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OktaFederationSession")
            .field(
                "idp_origin",
                &self.idp_origin.origin().ascii_serialization(),
            )
            .finish_non_exhaustive()
    }
}

impl OktaFederationSession {
    pub(crate) fn new(
        authority_host: &str,
        idp_url: &Url,
        username: &str,
        mfa_method: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let entra_origin = https_url(&format!("https://{}/", authority_host))
            .ok_or_else(|| format!("Invalid authority host: {authority_host}"))?;
        let client = Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
        Ok(OktaFederationSession {
            client,
            entra_origin,
            idp_origin: idp_url.clone(),
            username: username.to_string(),
            password: None,
            preference: preferred_factor(mfa_method),
            pkce: None,
            pending: None,
        })
    }

    fn allowed(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && (same_origin(&self.entra_origin, url) || same_origin(&self.idp_origin, url))
    }

    async fn read_body(response: Response) -> Result<String, String> {
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| format!("Failed reading response: {e}"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
                return Err("Response exceeded the 2 MiB limit".to_string());
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|e| format!("Response was not UTF-8: {e}"))
    }

    fn location(&self, response: &Response, current: &Url) -> Result<String, String> {
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or("Redirect did not include a location")?;
        // The authorization response targets a custom-scheme redirect URI.
        if location.starts_with(BROKER_DRS_REDIRECT_URI) {
            return Ok(location.to_string());
        }
        current
            .join(location)
            .map(|url| url.to_string())
            .map_err(|e| format!("Invalid redirect: {e}"))
    }

    /// GET `url` and follow redirects between Entra ID and the identity
    /// provider until a page is returned.
    async fn get_page(&self, url: Url) -> Result<(Url, String), String> {
        let mut url = url;
        for _ in 0..=MAX_REDIRECTS {
            if !self.allowed(&url) {
                return Err(format!(
                    "Refusing to follow a redirect to {}",
                    url.host_str().unwrap_or("an unknown host")
                ));
            }
            let response = self
                .client
                .get(url.clone())
                .header(header::ACCEPT, "text/html")
                .send()
                .await
                .map_err(|e| format!("Request failed: {e}"))?;
            let status = response.status();
            if status.is_redirection() {
                let location = self.location(&response, &url)?;
                url = Url::parse(&location).map_err(|e| format!("Invalid redirect: {e}"))?;
                continue;
            }
            if !status.is_success() {
                return Err(format!("Sign-in page returned HTTP status {status}"));
            }
            return Ok((url, Self::read_body(response).await?));
        }
        Err("Too many redirects".to_string())
    }

    async fn idx_post(
        &self,
        href: &str,
        accepts: Option<&str>,
        body: &SecretJson,
    ) -> Result<Value, String> {
        let url = Url::parse(href).map_err(|e| format!("Invalid Okta endpoint: {e}"))?;
        if url.scheme() != "https" || !same_origin(&self.idp_origin, &url) {
            return Err("Okta returned an untrusted endpoint".to_string());
        }
        let payload = serde_json::to_vec(&body.0)
            .map_err(|e| format!("Failed encoding the Okta request: {e}"))?;
        let response = self
            .client
            .post(url)
            .header(
                header::CONTENT_TYPE,
                accepts.unwrap_or(OKTA_FORM_CONTENT_TYPE),
            )
            .header(header::ACCEPT, OKTA_IDX_CONTENT_TYPE)
            .body(payload)
            .send()
            .await
            .map_err(|e| format!("Okta request failed: {e}"))?;
        let status = response.status();
        let text = Self::read_body(response).await?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| format!("Okta request failed with HTTP status {status}"))?;
        if !status.is_success()
            && value.get("remediation").is_none()
            && value.get("success").is_none()
        {
            return Err(idx_error_message(&value)
                .or_else(|| value["errorSummary"].as_str().map(str::to_string))
                .unwrap_or_else(|| format!("Okta request failed with HTTP status {status}")));
        }
        Ok(value)
    }

    /// Run IDX steps that need no user interaction.
    async fn drive(&self, resp: Value, ctx: IdxContext<'_>) -> Result<Progress, String> {
        let mut resp = resp;
        let mut ctx = ctx;
        let mut state_handle: Option<String> = None;
        for _ in 0..MAX_IDX_STEPS {
            if let Some(handle) = resp["stateHandle"].as_str() {
                state_handle = Some(handle.to_string());
            }
            let handle = state_handle
                .clone()
                .ok_or("Okta response has no state handle")?;
            let rejected = idx_error_message(&resp);
            match next_action(&resp, &ctx)? {
                IdxAction::Success { href } => {
                    let url = Url::parse(&href).map_err(|e| format!("Invalid Okta URL: {e}"))?;
                    let (_, html) = self.get_page(url).await?;
                    return Ok(Progress::Finished(html));
                }
                IdxAction::AwaitPush {
                    href,
                    accepts,
                    refresh_ms,
                    correct_answer,
                } => {
                    let interval_ms = u32::try_from(refresh_ms.max(1000)).unwrap_or(u32::MAX);
                    return Ok(Progress::Push {
                        pending: Pending {
                            state_handle: Zeroizing::new(handle),
                            href,
                            accepts,
                            credential_field: String::new(),
                            max_poll_attempts: PUSH_TIMEOUT_SECS.saturating_mul(1000) / interval_ms,
                        },
                        correct_answer,
                        refresh_ms,
                    });
                }
                IdxAction::AwaitCode {
                    href,
                    accepts,
                    credential_field,
                } => {
                    return Ok(Progress::Code {
                        pending: Pending {
                            state_handle: Zeroizing::new(handle),
                            href,
                            accepts,
                            credential_field,
                            max_poll_attempts: 0,
                        },
                        rejected,
                    });
                }
                IdxAction::Submit {
                    href,
                    accepts,
                    body,
                    submits_password,
                } => {
                    let body = with_state_handle(body, &handle);
                    resp = self.idx_post(&href, accepts.as_deref(), &body).await?;
                    ctx.password_submitted |= submits_password;
                }
            }
        }
        Err("The Okta sign-in did not complete".to_string())
    }

    /// Turn IDX progress into the next PAM step.
    async fn advance(
        &mut self,
        broker: &Mutex<BrokerClientApplication>,
        progress: Result<Progress, String>,
    ) -> FederationStep {
        match progress {
            Ok(Progress::Finished(html)) => {
                self.pending = None;
                match self.finish(broker, &html).await {
                    Ok(token) => FederationStep::Token(Box::new(token)),
                    Err(e) => {
                        error!("Okta-federated sign-in failed at Entra ID: {}", e);
                        FederationStep::Denied(tr(
                            "Authentication failed. Please contact your administrator.",
                        ))
                    }
                }
            }
            Ok(Progress::Push {
                pending,
                correct_answer,
                refresh_ms,
            }) => {
                self.pending = Some(pending);
                let msg = match correct_answer {
                    Some(answer) => tr_fmt(
                        "Open your Okta Verify app and tap {number} to approve the sign-in request.",
                        &[("number", answer)],
                    ),
                    None => tr("Approve the sign-in request in your Okta Verify app."),
                };
                FederationStep::Prompt(AuthRequest::MFAPoll {
                    enrollment: None,
                    msg,
                    polling_interval: u32::try_from(refresh_ms / 1000).unwrap_or(5).max(1),
                    show_push_hint: true,
                })
            }
            Ok(Progress::Code { pending, rejected }) => {
                self.pending = Some(pending);
                let prompt = tr("Enter the code displayed in your Okta Verify app: ");
                FederationStep::Prompt(AuthRequest::Input {
                    enrollment: None,
                    msg: match rejected {
                        Some(rejected) => format!("{rejected}\n{prompt}"),
                        None => prompt,
                    },
                    echo_on: false,
                })
            }
            Err(e) => {
                self.pending = None;
                warn!("Okta-federated sign-in failed: {}", e);
                FederationStep::Denied(e)
            }
        }
    }

    /// Start the sign-in with the user's password.
    pub(crate) async fn start(
        &mut self,
        broker: &Mutex<BrokerClientApplication>,
        password: &str,
    ) -> FederationStep {
        self.password = Some(Zeroizing::new(password.to_string()));
        let progress = self.start_internal(broker, password).await;
        self.advance(broker, progress).await
    }

    async fn start_internal(
        &mut self,
        broker: &Mutex<BrokerClientApplication>,
        password: &str,
    ) -> Result<Progress, String> {
        let pkce = broker
            .lock()
            .await
            .initiate_authorization_code_pkce_flow(vec![DRS_SCOPE], BROKER_DRS_REDIRECT_URI)
            .map_err(|e| format!("Failed to start the Entra ID sign-in: {e:?}"))?;
        let mut url =
            Url::parse(pkce.auth_url()).map_err(|e| format!("Invalid Entra ID URL: {e}"))?;
        let domain = self
            .username
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_string())
            .unwrap_or_default();
        url.query_pairs_mut()
            .append_pair("login_hint", &self.username)
            .append_pair("domain_hint", &domain);
        self.pkce = Some(pkce);

        let (page_url, html) = self.get_page(url).await?;
        if !same_origin(&self.idp_origin, &page_url) {
            return Err(
                "Entra ID did not forward the sign-in to the federated identity provider"
                    .to_string(),
            );
        }
        let state_token = extract_state_token(&html)
            .ok_or("The identity provider sign-in page is not an Okta Identity Engine page")?;
        let introspect = self
            .idp_origin
            .join("/idp/idx/introspect")
            .map_err(|e| format!("Invalid Okta URL: {e}"))?;
        let resp = self
            .idx_post(
                introspect.as_str(),
                Some(OKTA_IDX_CONTENT_TYPE),
                &SecretJson(json!({ "stateToken": state_token })),
            )
            .await?;
        let ctx = IdxContext {
            username: &self.username,
            password: Some(password),
            password_submitted: false,
            preference: self.preference,
        };
        self.drive(resp, ctx).await
    }

    /// Poll a pending push approval.
    pub(crate) async fn poll(
        &mut self,
        broker: &Mutex<BrokerClientApplication>,
        poll_attempt: u32,
    ) -> FederationStep {
        let progress = match self.pending.as_ref() {
            Some(pending) if pending.credential_field.is_empty() => {
                if poll_attempt > pending.max_poll_attempts {
                    return FederationStep::Denied(tr(
                        "Authentication timed out. Please try again.",
                    ));
                }
                let body = with_state_handle(SecretJson(json!({})), &pending.state_handle);
                match self
                    .idx_post(&pending.href, pending.accepts.as_deref(), &body)
                    .await
                {
                    // A rejected push must not silently trigger a new one.
                    Ok(resp) => match idx_error_message(&resp) {
                        Some(msg) => Err(msg),
                        None => self.drive(resp, self.continue_context()).await,
                    },
                    Err(e) => Err(e),
                }
            }
            _ => Err("No Okta push approval is pending".to_string()),
        };
        match progress {
            Ok(Progress::Push { pending, .. }) => {
                self.pending = Some(pending);
                FederationStep::Wait
            }
            Ok(Progress::Code { .. }) => {
                self.pending = None;
                FederationStep::Denied(tr(
                    "Okta requested a different verification method. Please sign in again.",
                ))
            }
            other => self.advance(broker, other).await,
        }
    }

    /// Submit a one-time code.
    pub(crate) async fn submit_code(
        &mut self,
        broker: &Mutex<BrokerClientApplication>,
        code: &str,
    ) -> FederationStep {
        let progress = match self.pending.as_ref() {
            Some(pending) if !pending.credential_field.is_empty() => {
                let mut credentials = serde_json::Map::new();
                credentials.insert(
                    pending.credential_field.clone(),
                    Value::String(code.trim().to_string()),
                );
                let body = with_state_handle(
                    SecretJson(json!({ "credentials": Value::Object(credentials) })),
                    &pending.state_handle,
                );
                match self
                    .idx_post(&pending.href, pending.accepts.as_deref(), &body)
                    .await
                {
                    Ok(resp) => self.drive(resp, self.continue_context()).await,
                    Err(e) => Err(e),
                }
            }
            _ => Err("No Okta code challenge is pending".to_string()),
        };
        match progress {
            Ok(Progress::Push { .. }) => {
                self.pending = None;
                FederationStep::Denied(tr(
                    "Okta requested a different verification method. Please sign in again.",
                ))
            }
            other => self.advance(broker, other).await,
        }
    }

    /// The password the sign-in was started with.
    pub(crate) fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|p| p.as_str())
    }

    fn continue_context(&self) -> IdxContext<'_> {
        IdxContext {
            username: &self.username,
            password: None,
            password_submitted: true,
            preference: self.preference,
        }
    }

    /// Post Okta's sign-in response to Entra ID and redeem the resulting
    /// authorization code.
    async fn finish(
        &self,
        broker: &Mutex<BrokerClientApplication>,
        html: &str,
    ) -> Result<UnixUserToken, String> {
        let pkce = self
            .pkce
            .as_ref()
            .ok_or("The Entra ID sign-in was not started")?;
        let form = parse_sign_in_form(html)
            .ok_or("The identity provider did not return a WS-Federation or SAML response")?;
        let mut url = self
            .entra_origin
            .join(&form.action)
            .map_err(|e| format!("Invalid sign-in form action: {e}"))?;
        let mut fields = form.fields;

        for _ in 0..=MAX_REDIRECTS {
            if url.scheme() != "https" || !same_origin(&self.entra_origin, &url) {
                return Err("The sign-in response targets an untrusted host".to_string());
            }
            let request = if fields.is_empty() {
                self.client.get(url.clone())
            } else {
                self.client.post(url.clone()).form(&fields)
            };
            let response = request
                .send()
                .await
                .map_err(|e| format!("Request to Entra ID failed: {e}"))?;
            let status = response.status();
            if status.is_redirection() {
                let location = self.location(&response, &url)?;
                if location.starts_with(BROKER_DRS_REDIRECT_URI) {
                    let token = broker
                        .lock()
                        .await
                        .acquire_token_by_authorization_code_pkce_flow(pkce, &location)
                        .await
                        .map_err(|e| format!("Failed to redeem the authorization code: {e:?}"))?;
                    let spn = token
                        .spn()
                        .map_err(|e| format!("Token has no user principal name: {e:?}"))?;
                    if !spn.eq_ignore_ascii_case(&self.username) {
                        return Err("The authenticating user did not match".to_string());
                    }
                    return Ok(token);
                }
                url = Url::parse(&location).map_err(|e| format!("Invalid redirect: {e}"))?;
                fields = vec![];
                continue;
            }
            let html = Self::read_body(response).await?;
            if !status.is_success() {
                return Err(format!("Entra ID returned HTTP status {status}"));
            }
            let config = parse_entra_config(&html).ok_or("Unexpected Entra ID response")?;
            if config["pgid"].as_str() != Some("KmsiInterrupt") {
                return Err(format!(
                    "Entra ID requested additional sign-in steps ({}). Configure the federated \
                     domain so that Entra ID accepts the multi-factor authentication performed \
                     by Okta (federatedIdpMfaBehavior).",
                    config["pgid"].as_str().unwrap_or("unknown")
                ));
            }
            // "Stay signed in?" interrupt
            let field = |name: &str| {
                config[name]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{name} is missing from the Entra ID response"))
            };
            url = self
                .entra_origin
                .join(&field("urlPost")?)
                .map_err(|e| format!("Invalid Entra ID URL: {e}"))?;
            fields = vec![
                ("LoginOptions".to_string(), "1".to_string()),
                ("ctx".to_string(), field("sCtx")?),
                ("flowToken".to_string(), field("sFT")?),
                ("canary".to_string(), field("canary")?),
            ];
        }
        Err("Too many redirects from Entra ID".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(password_submitted: bool, preference: Option<OktaFactor>) -> IdxContext<'a> {
        IdxContext {
            username: "user@contoso.com",
            password: Some("secret"),
            password_submitted,
            preference,
        }
    }

    fn rem(name: &str, fields: Value) -> Value {
        json!({
            "name": name,
            "href": format!("https://contoso.okta.com/idp/idx/{name}"),
            "method": "POST",
            "accepts": OKTA_FORM_CONTENT_TYPE,
            "value": fields,
        })
    }

    fn resp(remediations: Vec<Value>) -> Value {
        json!({
            "version": "1.0.0",
            "stateHandle": "state",
            "remediation": { "type": "array", "value": remediations },
        })
    }

    fn select_authenticator() -> Value {
        rem(
            "select-authenticator-authenticate",
            json!([{
                "name": "authenticator",
                "type": "object",
                "options": [
                    { "label": "Okta Verify", "value": { "form": { "value": [
                        { "name": "id", "value": "aut-ov", "mutable": false },
                        { "name": "methodType", "options": [
                            { "label": "Enter a code", "value": "totp" },
                            { "label": "Get a push notification", "value": "push" },
                            { "label": "FastPass", "value": "signed_nonce" }
                        ] }
                    ] } } },
                    { "label": "Password", "value": { "form": { "value": [
                        { "name": "id", "value": "aut-pw", "mutable": false },
                        { "name": "methodType", "value": "password", "mutable": false }
                    ] } } }
                ]
            }, { "name": "stateHandle", "value": "state" }]),
        )
    }

    fn submit_body(action: IdxAction) -> (Value, bool) {
        match action {
            IdxAction::Submit {
                body,
                submits_password,
                ..
            } => (body.0.clone(), submits_password),
            other => panic!("expected a submission, got {other:?}"),
        }
    }

    #[test]
    fn extracts_escaped_state_token() {
        let html = r#"<script>var stateToken = '02abc\x2Ddef\u002Dghi';</script>"#;
        assert_eq!(extract_state_token(html).unwrap(), "02abc-def-ghi");
        let json = r#"{"redirectUri":"x","stateToken":"02json\x2Dtoken"}"#;
        assert_eq!(extract_state_token(json).unwrap(), "02json-token");
        assert_eq!(extract_state_token("<html>no token</html>"), None);
        assert_eq!(extract_state_token("stateToken: null"), None);
        assert_eq!(extract_state_token("var stateToken = '';"), None);
    }

    #[test]
    fn identify_with_password_field_submits_both() {
        let response = resp(vec![rem(
            "identify",
            json!([
                { "name": "identifier" },
                { "name": "credentials", "form": { "value": [{ "name": "passcode" }] } },
                { "name": "stateHandle", "value": "state" }
            ]),
        )]);
        let (body, submits_password) =
            submit_body(next_action(&response, &ctx(false, None)).unwrap());
        assert!(submits_password);
        assert_eq!(body["identifier"], "user@contoso.com");
        assert_eq!(body["credentials"]["passcode"], "secret");
    }

    #[test]
    fn identifier_first_submits_only_identifier() {
        let response = resp(vec![rem(
            "identify",
            json!([{ "name": "identifier" }, { "name": "stateHandle", "value": "state" }]),
        )]);
        let (body, submits_password) =
            submit_body(next_action(&response, &ctx(false, None)).unwrap());
        assert!(!submits_password);
        assert!(body.get("credentials").is_none());
    }

    #[test]
    fn repeated_identify_after_password_is_a_failure() {
        let mut response = resp(vec![rem("identify", json!([{ "name": "identifier" }]))]);
        response["messages"] = json!({ "type": "array", "value": [
            { "message": "Unable to sign in", "class": "ERROR" }
        ] });
        assert_eq!(
            next_action(&response, &ctx(true, None)).unwrap_err(),
            "Unable to sign in"
        );
    }

    #[test]
    fn selects_password_then_preferred_factor() {
        let response = resp(vec![select_authenticator()]);
        let (body, _) = submit_body(next_action(&response, &ctx(false, None)).unwrap());
        assert_eq!(body["authenticator"]["id"], "aut-pw");

        let (body, _) = submit_body(next_action(&response, &ctx(true, None)).unwrap());
        assert_eq!(body["authenticator"]["id"], "aut-ov");
        assert_eq!(body["authenticator"]["methodType"], "push");

        let (body, _) =
            submit_body(next_action(&response, &ctx(true, Some(OktaFactor::Code))).unwrap());
        assert_eq!(body["authenticator"]["methodType"], "totp");
    }

    #[test]
    fn rejects_when_only_fastpass_is_available() {
        let response = resp(vec![rem(
            "select-authenticator-authenticate",
            json!([{ "name": "authenticator", "options": [
                { "value": { "form": { "value": [
                    { "name": "id", "value": "aut-ov" },
                    { "name": "methodType", "value": "signed_nonce" }
                ] } } }
            ] }]),
        )]);
        assert!(next_action(&response, &ctx(true, None)).is_err());
    }

    #[test]
    fn password_challenge_submits_password_once() {
        let mut response = resp(vec![rem(
            "challenge-authenticator",
            json!([{ "name": "credentials" }]),
        )]);
        response["currentAuthenticatorEnrollment"] =
            json!({ "type": "object", "value": { "type": "password", "key": "okta_password" } });
        let (body, submits_password) =
            submit_body(next_action(&response, &ctx(false, None)).unwrap());
        assert!(submits_password);
        assert_eq!(body["credentials"]["passcode"], "secret");
        assert!(next_action(&response, &ctx(true, None)).is_err());
    }

    #[test]
    fn code_challenge_uses_authenticator_specific_field() {
        let mut response = resp(vec![rem(
            "challenge-authenticator",
            json!([{ "name": "credentials" }]),
        )]);
        response["currentAuthenticatorEnrollment"] =
            json!({ "type": "object", "value": { "type": "app", "key": "okta_verify" } });
        assert_eq!(
            next_action(&response, &ctx(true, None)).unwrap(),
            IdxAction::AwaitCode {
                href: "https://contoso.okta.com/idp/idx/challenge-authenticator".to_string(),
                accepts: Some(OKTA_FORM_CONTENT_TYPE.to_string()),
                credential_field: "totp".to_string(),
            }
        );
        response["currentAuthenticatorEnrollment"] =
            json!({ "type": "object", "value": { "type": "app", "key": "google_otp" } });
        match next_action(&response, &ctx(true, None)).unwrap() {
            IdxAction::AwaitCode {
                credential_field, ..
            } => assert_eq!(credential_field, "passcode"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn verification_data_selects_method() {
        let response = resp(vec![rem(
            "authenticator-verification-data",
            json!([{ "name": "authenticator", "form": { "value": [
                { "name": "id", "value": "aut-ov" },
                { "name": "methodType", "options": [{ "value": "push" }, { "value": "totp" }] }
            ] } }]),
        )]);
        let (body, _) =
            submit_body(next_action(&response, &ctx(true, Some(OktaFactor::Code))).unwrap());
        assert_eq!(body["authenticator"]["methodType"], "totp");
    }

    #[test]
    fn challenge_poll_awaits_push_with_number() {
        let mut response = resp(vec![{
            let mut poll = rem("challenge-poll", json!([]));
            poll["refresh"] = json!(5000);
            poll
        }]);
        response["currentAuthenticator"] = json!({ "type": "object", "value": {
            "type": "app",
            "contextualData": { "correctAnswer": 42 }
        } });
        assert_eq!(
            next_action(&response, &ctx(true, None)).unwrap(),
            IdxAction::AwaitPush {
                href: "https://contoso.okta.com/idp/idx/challenge-poll".to_string(),
                accepts: Some(OKTA_FORM_CONTENT_TYPE.to_string()),
                refresh_ms: 5000,
                correct_answer: Some("42".to_string()),
            }
        );
    }

    #[test]
    fn success_redirect_finishes() {
        let response = json!({ "success": {
            "name": "success-redirect",
            "href": "https://contoso.okta.com/login/token/redirect?stateToken=x"
        } });
        assert_eq!(
            next_action(&response, &ctx(true, None)).unwrap(),
            IdxAction::Success {
                href: "https://contoso.okta.com/login/token/redirect?stateToken=x".to_string()
            }
        );
    }

    #[test]
    fn unsupported_remediation_is_reported() {
        let response = resp(vec![rem("enroll-authenticator", json!([]))]);
        assert!(next_action(&response, &ctx(true, None))
            .unwrap_err()
            .contains("enroll-authenticator"));
    }

    #[test]
    fn maps_configured_methods() {
        assert_eq!(
            preferred_factor(Some("PhoneAppOTP")),
            Some(OktaFactor::Code)
        );
        assert_eq!(preferred_factor(Some("push")), Some(OktaFactor::Push));
        assert_eq!(preferred_factor(Some("OneWaySMS")), None);
        assert_eq!(preferred_factor(None), None);
    }

    #[test]
    fn parses_ws_federation_form() {
        let html = r#"<html><body onload="document.forms[0].submit()">
            <form method="POST" name="hiddenform" action="https://login.microsoftonline.com/login.srf">
            <input type="hidden" name="wa" value="wsignin1.0"/>
            <input type="hidden" name="wresult" value="&lt;t:RequestSecurityTokenResponse&gt;&#x41;&amp;&#66;&lt;/t:RequestSecurityTokenResponse&gt;"/>
            <input type="hidden" name='wctx' value='LoginOptions=3&amp;estsredirect=2'/>
            </form></body></html>"#;
        let form = parse_sign_in_form(html).unwrap();
        assert_eq!(form.action, "https://login.microsoftonline.com/login.srf");
        assert_eq!(form.field("wa"), Some("wsignin1.0"));
        assert_eq!(
            form.field("wresult"),
            Some("<t:RequestSecurityTokenResponse>A&B</t:RequestSecurityTokenResponse>")
        );
        assert_eq!(form.field("wctx"), Some("LoginOptions=3&estsredirect=2"));
    }

    #[test]
    fn parses_saml_form_and_ignores_others() {
        let html = r#"<form action="/other"><input name="q" value="x"></form>
            <form method="post" action="https://login.microsoftonline.com/login.srf">
            <input type="hidden" name="SAMLResponse" value="PHNhbWw+"/>
            <input type="hidden" name="RelayState" value="relay"/></form>"#;
        let form = parse_sign_in_form(html).unwrap();
        assert_eq!(form.field("SAMLResponse"), Some("PHNhbWw+"));
        assert_eq!(form.field("RelayState"), Some("relay"));
        assert!(
            parse_sign_in_form(r#"<form action="/x"><input name="a" value="b"></form>"#).is_none()
        );
    }

    #[test]
    fn decodes_html_entities() {
        assert_eq!(decode_html_entities("a&amp;b&lt;&#x3E;&#62;"), "a&b<>>");
        assert_eq!(
            decode_html_entities("broken & text &unknown;"),
            "broken & text &unknown;"
        );
    }

    #[test]
    fn parses_entra_config() {
        let html = r#"<script>//<![CDATA[
$Config={"pgid":"KmsiInterrupt","sCtx":"ctx","sFT":"ft","canary":"c","urlPost":"/kmsi"};
//]]></script>"#;
        let config = parse_entra_config(html).unwrap();
        assert_eq!(config["pgid"], "KmsiInterrupt");
        assert_eq!(config["urlPost"], "/kmsi");
        assert!(parse_entra_config("<html></html>").is_none());
    }

    #[test]
    fn only_trusted_origins_are_followed() {
        let session = OktaFederationSession::new(
            "login.microsoftonline.com",
            &Url::parse("https://contoso.okta.com/app/office365/x/sso/wsfed/passive").unwrap(),
            "user@contoso.com",
            None,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(session.allowed(&Url::parse("https://login.microsoftonline.com/x").unwrap()));
        assert!(session.allowed(&Url::parse("https://contoso.okta.com/login").unwrap()));
        assert!(!session.allowed(&Url::parse("https://attacker.example/").unwrap()));
        assert!(!session.allowed(&Url::parse("http://contoso.okta.com/login").unwrap()));
        assert!(!format!("{session:?}").contains("user@"));
    }
}
