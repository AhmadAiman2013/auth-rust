mod auth_oidc;

use actix_cors::Cors;
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use actix_web::{cookie::{time::Duration, Key}, middleware::Logger, web, App, HttpServer};
use openidconnect::{
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
    core::{CoreClient, CoreProviderMetadata},
};
use redis::Client;
use std::{sync::Arc, vec};

use crate::auth_oidc::{callback, csrf, get_http_client, login, logout, verify, AppState};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    dotenv::dotenv().ok();
    // Configuration - In production, use environment variables
    let issuer_url = std::env::var("ISSUER_URL")
        .expect("ISSUER URL MUST BE SET");
    let client_id = std::env::var("CLIENT_ID")
        .expect("OIDC_CLIENT_ID must be set");
    let client_secret = std::env::var("CLIENT_SECRET")
        .expect("OIDC_CLIENT_SECRET must be set");
    let redirect_url = std::env::var("REDIRECT_URL")
        .expect("REDIRECT URL must be set");
    let redis_url = std::env::var("REDIS_URL")
        .expect("REDIS_URL must be set");
    let secret_key = std::env::var("SECRET_KEY")
        .expect("SECRET_KEY must be set");
    
    assert_eq!(secret_key.len(), 64, "SESSION_KEY must be exactly 64 characters");

    let key = Key::from(secret_key.as_bytes());
    
    
    log::info!("Discovering OIDC provider metadata...");
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(issuer_url).expect("Invalid issuer URL"),
        &*get_http_client(),
    )
    .await
    .expect("Failed to discover provider metadata");
    
    let oidc_client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.clone()).expect("Invalid redirect URL"));
    
    
    log::info!("Connecting to Redis at {}...", redis_url);

    // Test the connection first
    let redis_client = Client::open(redis_url.as_str())
    .expect("Failed to create Redis client");
    
    redis_client.get_connection()
    .expect("Failed to connect to Redis - check your password!");

    log::info!("Redis connection successful!");
    let redis_store = RedisSessionStore::new(&redis_url)
        .await
        .expect("Failed to connect to Redis");
    
    
    let oidc_client = Arc::new(oidc_client);
    
    let state = AppState::new(oidc_client);
    
    
    log::info!("Starting auth service at http://localhost:8080");

    const SECS_IN_WEEK: i64 = 60 * 60 * 24 * 7;
   
    
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:5173")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE","OPTIONS"])
            .allowed_headers(vec![actix_web::http::header::AUTHORIZATION, actix_web::http::header::CONTENT_TYPE, actix_web::http::header::HeaderName::from_static("x-csrf")])
            .expose_headers(vec!["x-user-id", "x-user-name", "x-user-email"])
            .supports_credentials()
            .max_age(3600);
        
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(
                    redis_store.clone(),
                    key.clone(),
                )
                .session_lifecycle(
                    PersistentSession::default().session_ttl(Duration::seconds(SECS_IN_WEEK))
                )
                .cookie_name("rust_oidc_session".to_string())
                .cookie_secure(false) // Set to true in production with HTTPS
                .cookie_http_only(true)
                .cookie_same_site(actix_web::cookie::SameSite::Lax)
                .cookie_path("/".to_string())
                .build(),
            )
            .wrap(cors)
            .service(verify)
            .service(csrf)
            .service(login)
            .service(callback)
            .service(logout)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
