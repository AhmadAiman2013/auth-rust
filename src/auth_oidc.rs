use std::{sync::Arc};
use std::sync::OnceLock;
use anyhow::{Context, Result};
use actix_session::Session;
use actix_web::{cookie::{Cookie}, get, post, web, Error, HttpRequest, HttpResponse};
use actix_web::cookie::time::Duration;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use openidconnect::{AccessTokenHash, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge, Scope, TokenResponse, core::CoreResponseType, RefreshToken};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

type OidcClient = openidconnect::Client<
    openidconnect::EmptyAdditionalClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    openidconnect::StandardTokenResponse<
        openidconnect::IdTokenFields<
            openidconnect::EmptyAdditionalClaims,
            openidconnect::EmptyExtraTokenFields,
            openidconnect::core::CoreGenderClaim,
            openidconnect::core::CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::StandardTokenIntrospectionResponse<
        openidconnect::EmptyExtraTokenFields,
        openidconnect::core::CoreTokenType,
    >,
    openidconnect::core::CoreRevocableToken,
    openidconnect::StandardErrorResponse<openidconnect::RevocationErrorResponseType>,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;

#[derive(Clone)]
pub struct AppState {
    pub oidc_client: Arc<OidcClient>,
    pub refresh_locks: Arc<DashMap<String, Arc<Mutex<()>>>>
}

impl AppState {
    pub fn new(oidc_client: Arc<OidcClient>) -> Self {
        AppState {
            oidc_client,
            refresh_locks: Arc::new(DashMap::new()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct UserInfo {
    sub: String,
    name: Option<String>,
    email: Option<String>,
}

#[get("/auth/verify")]
pub async fn verify(
    data: web::Data<AppState>,
    session: Session,
    req: HttpRequest) -> Result<HttpResponse, Error> {
    let stored_csrf: Option<String> = session.get("web_csrf")?;

    // Compare CSRF token from "x-csrf" header to the stored one
    if let Some(header_csrf) = req.headers().get("x-csrf") {
        if let Ok(header_csrf_str) = header_csrf.to_str() {
            if stored_csrf.as_deref() != Some(header_csrf_str) {
                log::warn!(
                    "CSRF token mismatch: stored={:?}, header={:?}",
                    stored_csrf,
                    header_csrf_str
                );
                return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error" : "csrf token doesnt match"
                })));
            }
        }
    }

    let user_info: Option<UserInfo> = session.get("user_info")?;

    if let Some(user) = &user_info {
        // only expired users need to acquire the lock
        let user_id = user.sub.clone();
        let lock = data
            .refresh_locks
            .entry(user_id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();

        let _guard = lock.lock().await; // Acquire the lock for this user

        if let Err(e) = refresh_token(&session, &data.oidc_client).await {
            let expiry_str: Option<String> = session.get("expiry_id_token")?;
            let token_is_valid = expiry_str
                .and_then(|s| s.parse::<DateTime<Utc>>().ok())
                .map_or(false, |expiry| {
                    Utc::now() + chrono::Duration::minutes(5) < expiry
                });

            if !token_is_valid {
                log::error!("Token refresh failed and token is invalid/expired: {}", e);
                session.purge();
                return Ok(HttpResponse::Unauthorized()
                    .insert_header(("WWW-Authenticate", "Bearer"))
                    .finish());
            }
        } else {
            log::info!("Token refresh failed but token is valid (concurrent request)");
        }
    } else {
        log::warn!("No user_info found in session for path: {}", req.path());
        return Ok(HttpResponse::Unauthorized()
            .insert_header(("WWW-Authenticate", "Bearer"))
            .finish());
    }


    let user = user_info.unwrap();
    log::info!("Authentication successful for user: {}", user.sub);
    Ok(HttpResponse::Ok()
        .insert_header(("x-user-id", user.sub.clone()))
        .insert_header(("x-user-email", user.email.clone().unwrap_or_default()))
        .insert_header(("x-user-name", user.name.clone().unwrap_or_default()))
        .finish())

}

pub async fn refresh_token(
    session: &Session,
    client: &OidcClient
) -> Result<()> {
    // step 1: check if expiry_id_token is present
    let expiry_id_token: Option<String> = session.get("expiry_id_token")
        .context("Failed to read expiry_id_token from session")?;

    let expiry_id_token = expiry_id_token
        .ok_or_else(|| anyhow::anyhow!("No expiry_id_token found in session"))?;

    log::info!("Found expiry_id_token in session: {}", expiry_id_token);

    // step 2: parse expiry time
    let expiry_time: DateTime<Utc> = expiry_id_token
        .parse::<DateTime<Utc>>()
        .context("Failed to parse expiry_id_token as DateTime<Utc>")?;

    log::info!("Id token expiry time: {}", expiry_time);

    let now  = Utc::now();
    let buffer = chrono::Duration::minutes(5);

    if now + buffer < expiry_time {
        log::info!("Id token is still valid, no refresh needed");
        return Ok(());
    }

    log::info!("token is expired or about to expire, attempting refresh");

    // Step 3: get refresh token
    let refresh_token: Option<String> = session.get("refresh_token")
        .context("Failed to read refresh_token from session")?;

    let refresh_token = refresh_token
        .ok_or_else(|| anyhow::anyhow!("No refresh_token found in session"))?;

    log::info!("Found refresh_token in session");

    // Step 4 : perform token refresh
    let refresh_token = RefreshToken::new(refresh_token);

    let http_client = get_http_client();

    let token_response = client
        .exchange_refresh_token(&refresh_token)
        .context("Failed to create refresh token")?
        .request_async(&*http_client)
        .await
        .context("Failed to request new tokens using refresh token")?;

    log::info!("Token refresh successful");

    // Step 5: update session with new tokens and expiry
    let new_access_token = token_response.access_token().secret().to_string();
    session.insert("access_token", new_access_token)
        .context("Failed to store new access_token in session")?;

    log::info!("Stored new access_token in session");

    if let Some(new_refresh_token) = token_response.refresh_token() {
        session.insert("refresh_token", new_refresh_token.secret())
            .context("Failed to store new refresh_token in session")?;
        log::info!("Stored new refresh_token in session");
    }

    if let Some(expiry_id_token) = token_response.expires_in() {
        let expiry_time = Utc::now() + chrono::Duration::from_std(expiry_id_token)
            .unwrap_or(chrono::Duration::seconds(3600)); // default to 1 hour if conversion fails
        session.insert("expiry_id_token", expiry_time.to_string())
            .context("Failed to store new expiry_id_token in session")?;
        log::info!("Stored new expiry_id_token in session: {}", expiry_time);
    }

    log::info!("Token refresh process completed successfully");
    Ok(())
}


#[get("/auth/csrf")]
pub async fn csrf(session: Session) -> Result<HttpResponse, Error> {
    let new_csrf = CsrfToken::new_random();
    match session.insert("web_csrf", new_csrf.secret().to_string()) {
        Ok(_) => log::info!("✓ Successfully stored web_csrf"),
        Err(e) => {
            log::error!("✗ Failed to store web_csrf: {}", e);
            return Ok(HttpResponse::InternalServerError()
            .json(serde_json::json!({
                "error": "Failed to store CSRF token"
            })));
        }
    }
    
    let cookie = Cookie::build("web_csrf", new_csrf.clone().secret().to_string())
        .secure(false)
        .path("/")
        .http_only(false)
        .max_age(Duration::days(1))
        .same_site(actix_web::cookie::SameSite::Lax)
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({
            "message": "sent csrf cookie"
        })))

}

#[get("/auth/login")]
pub async fn login(
    data: web::Data<AppState>,
    session: Session,
    req: HttpRequest,
) -> Result<HttpResponse, Error> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    if let Some(redirect_url) = get_redirect_url(&req) {
        log::info!("Storing redirect URL: {}", redirect_url);
        match session.insert("post_login_redirect", redirect_url.as_str()) {
            Ok(_) => log::info!("✓ Successfully stored post_login_redirect"),
            Err(e) => {
                log::error!("✗ Failed to store post_login_redirect: {}", e);
                return Err(actix_web::error::ErrorInternalServerError(e));
            }
        }
    } else {
        log::warn!("No redirect URL found in headers");
    }

    let (auth_url, csrf_token, nonce) = data
        .oidc_client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new_random(),
            || Nonce::new_random(),
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store and verify each value
    match session.insert("pkce_verifier", pkce_verifier.secret().to_string()) {
        Ok(_) => log::info!("✓ Successfully stored pkce_verifier"),
        Err(e) => {
            log::error!("✗ Failed to store pkce_verifier: {}", e);
            return Err(actix_web::error::ErrorInternalServerError(e));
        }
    }

    match session.insert("csrf_token", csrf_token.secret().to_string()) {
        Ok(_) => log::info!("✓ Successfully stored csrf_token"),
        Err(e) => {
            log::error!("✗ Failed to store csrf_token: {}", e);
            return Err(actix_web::error::ErrorInternalServerError(e));
        }
    }

    match session.insert("nonce", nonce.secret().to_string()) {
        Ok(_) => log::info!("✓ Successfully stored nonce"),
        Err(e) => {
            log::error!("✗ Failed to store nonce: {}", e);
            return Err(actix_web::error::ErrorInternalServerError(e));
        }
    }

    session.renew();

    log::info!("Redirecting to: {}", auth_url);
    log::info!("CSRF token stored: {}", csrf_token.secret());

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

#[derive(Deserialize)]
struct AuthCallbackQuery {
    code: String,
    state: String,
}

#[get("/auth/callback")]
pub async fn callback(
    query: web::Query<AuthCallbackQuery>,
    data: web::Data<AppState>,
    session: Session,
) -> Result<HttpResponse, Error> {
    let stored_csrf: Option<String> = session.get("csrf_token")?;
    let stored_pkce: Option<String> = session.get("pkce_verifier")?;
    let stored_nonce: Option<String> = session.get("nonce")?;

    if stored_csrf.as_ref() != Some(&query.state) {
        log::error!("CSRF token mismatch");
        log::info!("Expected: {:?}, Received: {:?}", stored_csrf, query.state);
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Csrf token mismatch"
        })));
    }

    let pkce_verifier = match stored_pkce {
        Some(v) => openidconnect::PkceCodeVerifier::new(v),
        None => {
            log::error!("PKCE verifier not found in session");
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "PKCE verifier not found"
            })));
        }
    };

    let token_response = data
        .oidc_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .map_err(|e| {
            log::error!("OIDC configuration error: {:?}", e);
            actix_web::error::ErrorInternalServerError("OIDC configuration error")
        })?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&*get_http_client())
        .await
        .map_err(|e| {
            log::error!("Token exchange failed: {:?}", e);
            actix_web::error::ErrorInternalServerError("Token exchange failed")
        })?;

    // Get user info from ID token
    let id_token = token_response
        .id_token()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("No ID token received"))?;

    let id_token_verifier = data.oidc_client.id_token_verifier();

    let nonce_verifier = stored_nonce
        .map(|n| Nonce::new(n))
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Nonce not found"))?;

    let claims = id_token
        .claims(&id_token_verifier, &nonce_verifier)
        .map_err(|e| {
            log::error!("Token verification failed: {:?}", e);
            actix_web::error::ErrorInternalServerError("Token verification failed")
        })?;

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let signing_alg = id_token.signing_alg().map_err(|e| {
            log::error!("Failed to get signing algorithm: {:?}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signing algorithm")
        })?;
        let signing_key = id_token.signing_key(&id_token_verifier).map_err(|e| {
            log::error!("Failed to get signing key: {:?}", e);
            actix_web::error::ErrorInternalServerError("Failed to get signing key")
        })?;

        let actual_access_token_hash =
            AccessTokenHash::from_token(token_response.access_token(), signing_alg, signing_key)
                .map_err(|e| {
                    log::error!("Failed to compute access token hash: {:?}", e);
                    actix_web::error::ErrorInternalServerError(
                        "Failed to compute access token hash",
                    )
                })?;

        if actual_access_token_hash != *expected_access_token_hash {
            log::error!("Invalid access token");
            return Err(actix_web::error::ErrorInternalServerError(
                "Invalid access token",
            ));
        }
    }

    // Extract user info
    let user_info = UserInfo {
        sub: claims.subject().to_string(),
        name: claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.to_string()),
        email: claims.email().map(|e| e.to_string()),
    };

    log::info!("User authenticated: {}", user_info.sub);

    let token_expiry = claims.expiration();

    // TESTING override expiry to 1 minute from now
    // let test_expiry = Utc::now() + chrono::Duration::minutes(7);
    // log::warn!("Overriding token expiry for testing purposes: {}", test_expiry);


    // Store user info and tokens in session
    session.insert("user_info", &user_info)?;
    session.insert("access_token", token_response.access_token().secret())?;
    session.insert("expiry_id_token", token_expiry)?;
    session.insert("refresh_token", token_response.refresh_token().map(|t| t.secret()))?;


    // Get post-login redirect URL
    let redirect_url = session
        .get::<String>("post_login_redirect")?
        .unwrap_or_else(|| "/".to_string());

    // Clean up temporary session data
    session.remove("pkce_verifier");
    session.remove("nonce");
    session.remove("post_login_redirect");
    session.remove("csrf_token");

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

#[post("/auth/logout")]
async fn logout(session: Session) -> Result<HttpResponse, Error> {
    log::info!("user logged out");
    session.purge();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Logged out successfully"
    })))
}

// pub static HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
//     reqwest::ClientBuilder::new()
//         .redirect(reqwest::redirect::Policy::none())
//         .build()
//         .expect("Failed to build HTTP client")
// });

pub static HTTP_CLIENT: OnceLock<Client> = OnceLock::new();

pub fn get_http_client() -> &'static Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP client")
    })
}

fn get_redirect_url(req: &HttpRequest) -> Option<String> {
    // Production (behind traefik): Reconstruct from forwarded headers
    if let Some(host) = req.headers().get("X-Forwarded-Host") {
        let proto = req
            .headers()
            .get("X-Forwarded-Proto")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("https");

        let host = host.to_str().ok()?;

        let uri = req
            .headers()
            .get("X-Forwarded-Uri")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("/");

        return Some(format!("{}://{}{}", proto, host, uri));
    }

    // Local (no proxy): Use Referer header
    if let Some(referer) = req.headers().get("referer") {
        if let Ok(url) = referer.to_str() {
            return Some(url.to_string());
        }
    }

    None
}
