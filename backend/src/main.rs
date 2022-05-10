/*
 *  Author & Copyright: Ruben Fiszel 2021
 * This file and its contents are licensed under the AGPLv3 License
 * LICENSE for a copy of the license.
 */

use argon2::Argon2;
use axum::{
    extract::extractor_middleware, handler::Handler, routing::get, AddExtensionLayer, Router,
};
use git_version::git_version;
use hyper::Response;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::{MakeSpan, OnResponse, TraceLayer};
use tracing::{field, metadata::LevelFilter, Span};
use tracing_subscriber::{filter::filter_fn, prelude::*, EnvFilter};
extern crate magic_crypt;

extern crate dotenv;
use dotenv::dotenv;

mod audit;
mod db;
mod error;
mod granular_acls;
mod groups;
mod jobs;
mod parser;
mod pipenv;
mod resources;
mod schedule;
mod scripts;
mod static_assets;
mod users;
mod utils;
mod variables;
mod worker;
mod worker_ping;

use error::Error;

use crate::{db::UserDB, utils::rd_string};

const GIT_VERSION: &str = git_version!(args = ["--tag", "--always"], fallback = "unknown-version");
const DEFAULT_NUM_WORKERS: usize = 3;
const DEFAULT_TIMEOUT: i32 = 300;

#[derive(Clone)]
struct MyOnResponse {}

impl<B> OnResponse<B> for MyOnResponse {
    fn on_response(
        self,
        response: &Response<B>,
        latency: std::time::Duration,
        _span: &tracing::Span,
    ) {
        tracing::info!(
            latency = %latency.as_millis(),
            status = ?response.status(),
            "finished processed request")
    }
}

#[derive(Clone)]
struct MyMakeSpan {}

impl<B> MakeSpan<B> for MyMakeSpan {
    fn make_span(&mut self, request: &hyper::Request<B>) -> Span {
        tracing::info_span!(
            "request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
            username = field::Empty,
        )
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    // initialize tracing

    let ts_base = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .flatten_event(true)
                .with_span_list(false)
                .with_current_span(true)
                .with_filter(LevelFilter::INFO)
                .with_filter(filter_fn(|meta| meta.target().starts_with("delightool"))),
        )
        .with(
            EnvFilter::default()
                .add_directive("delightool".parse()?)
                .add_directive("runtime=trace".parse()?)
                .add_directive("tokio=trace".parse()?),
        );

    if std::env::var("TOKIO_CONSOLE")
        .map(|x| x == "true")
        .unwrap_or(false)
    {
        let console_layer = console_subscriber::spawn();
        ts_base.with(console_layer).init();
    } else {
        ts_base.init();
    }

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| Error::BadConfig("DATABASE_URL env var is missing".to_string()))?;

    let timeout = std::env::var("TIMEOUT")
        .ok()
        .and_then(|x| x.parse::<i32>().ok())
        .unwrap_or(DEFAULT_TIMEOUT);

    let num_worker = std::env::var("NUM_WORKERS")
        .ok()
        .and_then(|x| x.parse::<i32>().ok())
        .unwrap_or(DEFAULT_NUM_WORKERS as i32);

    let variables_key = std::env::var("VARIABLES_KEY").unwrap_or_else(|_| "changeme".to_owned());

    let app_password = std::env::var("APP_USER_PASSWORD").unwrap_or_else(|_| "changeme".to_owned());

    let db = db::connect(&database_url).await?;

    db::migrate(&db).await?;
    db::setup_app_user(&db, &app_password).await?;

    let user_db = UserDB::new(db.clone());

    let auth_cache = Arc::new(users::AuthCache::new(db.clone()));
    let argon2 = Arc::new(Argon2::default());

    let mc = Arc::new(magic_crypt::new_magic_crypt!(variables_key, 256));

    let middleware_stack = ServiceBuilder::new()
        .layer(
            TraceLayer::new_for_http()
                .on_response(MyOnResponse {})
                .make_span_with(MyMakeSpan {})
                .on_request(()),
        )
        .layer(AddExtensionLayer::new(db.clone()))
        .layer(AddExtensionLayer::new(user_db))
        .layer(AddExtensionLayer::new(auth_cache.clone()))
        .layer(CookieManagerLayer::new());
    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .nest(
            "/api",
            Router::new()
                // `POST /users` goes to `create_user`
                .nest("/scripts", scripts::make_service())
                .nest("/jobs", jobs::make_service())
                .nest(
                    "/users",
                    users::make_service().layer(AddExtensionLayer::new(argon2.clone())),
                )
                .nest(
                    "/variables",
                    variables::make_service().layer(AddExtensionLayer::new(mc.clone())),
                )
                .nest("/resources", resources::make_service())
                .nest("/pipenv", pipenv::make_service())
                .nest("/schedules", schedule::make_service())
                .nest("/groups", groups::make_service())
                .nest("/audit", audit::make_service())
                .nest("/workers", worker_ping::make_service())
                .nest("/acls", granular_acls::make_service())
                .route_layer(extractor_middleware::<users::Authed>())
                .route_layer(extractor_middleware::<users::Tokened>())
                .nest(
                    "/users",
                    users::make_unauthed_service().layer(AddExtensionLayer::new(argon2)),
                )
                .route("/version", get(git_v))
                .route("/openapi.yaml", get(openapi)),
        )
        .fallback(static_assets::static_handler.into_service())
        .layer(middleware_stack);

    let instance_name = rd_string(5);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    tracing::info!(addr = %addr.to_string(), instance = %instance_name, "server started listening");
    let server = axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal());

    let mutex = Arc::new(Mutex::new(0));

    let sources: external_ip::Sources = external_ip::get_http_sources();
    let consensus = external_ip::ConsensusBuilder::new()
        .add_sources(sources)
        .build();

    let ip = consensus
        .get_consensus()
        .await
        .map(|x| x.to_string())
        .unwrap_or_else(|| "Unretrievable ip".to_string());

    for i in 1..(num_worker + 1) {
        let db1 = db.clone();
        let mc1 = mc.clone();
        let instance_name = instance_name.clone();
        let worker_name = format!("dt-worker-{}-{}", &instance_name, rd_string(5));
        let m1 = mutex.clone();
        let ip = ip.clone();
        tokio::spawn(async move {
            tracing::info!(addr = %addr.to_string(), worker = %worker_name, "starting worker");
            worker::run_worker(
                &db1,
                mc1,
                timeout,
                &instance_name,
                worker_name,
                i as u64,
                num_worker as u64,
                m1,
                &ip,
            )
            .await
        });
    }

    let db1 = db.clone();
    let db2 = db.clone();

    tokio::spawn(async move { auth_cache.monitor().await });
    tokio::spawn(async move { worker::restart_zombie_jobs(&db1, timeout).await });
    tokio::spawn(async move { users::delete_expired_tokens_perdiodically(&db2).await });

    server.await?;
    Ok(())
}

async fn git_v() -> &'static str {
    GIT_VERSION
}

async fn openapi() -> &'static str {
    include_str!("../openapi.yaml")
}

pub async fn shutdown_signal() {
    use std::io;
    use tokio::signal::unix::SignalKind;

    async fn terminate() -> io::Result<()> {
        tokio::signal::unix::signal(SignalKind::terminate())?
            .recv()
            .await;
        Ok(())
    }

    tokio::select! {
        _ = terminate() => {},
        _ = tokio::signal::ctrl_c() => {},
    }
    println!("signal received, starting graceful shutdown")
}
