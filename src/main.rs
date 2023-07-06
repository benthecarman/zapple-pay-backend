use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode, Uri};
use axum::routing::{get, post};
use axum::{http, Extension, Router};
use bitcoin::hashes::hex::ToHex;
use clap::Parser;
use nostr::key::XOnlyPublicKey;
use sled::Db;
use tokio::sync::watch;
use tokio::sync::watch::Sender;
use tower_http::cors::{Any, CorsLayer};

use crate::config::*;
use crate::routes::*;

mod config;
mod db;
mod routes;
mod subscriber;

#[derive(Clone)]
pub struct State {
    db: Db,
    pubkeys: Arc<Mutex<Sender<Vec<String>>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = Config::parse();

    // Create the database if it doesn't exist
    if let Some(parent_dir) = PathBuf::from(&config.db_path).parent() {
        std::fs::create_dir_all(parent_dir)?;
    };

    // DB management
    let db = sled::open(&config.db_path)?;

    let mut start = vec![];
    db.scan_prefix("").for_each(|res| {
        res.map(|(k, _)| {
            let xonly = XOnlyPublicKey::from_slice(&k).unwrap();
            start.push(xonly.to_hex());
        })
        .unwrap();
    });

    let (tx, rx) = watch::channel(start);

    let tx_shared = Arc::new(Mutex::new(tx));

    let state = State {
        db,
        pubkeys: tx_shared.clone(),
    };

    let addr: std::net::SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .expect("Failed to parse bind/port for webserver");

    println!("Webserver running on http://{}", addr);

    let server_router = Router::new()
        .route("/set-user", post(set_user_config))
        .route("/get-user/:npub", get(get_user_config))
        .fallback(fallback)
        .layer(Extension(state.clone()))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(vec![http::header::CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST]),
        );

    let server = axum::Server::bind(&addr).serve(server_router.into_make_service());

    tokio::spawn(subscriber::start_subscription(state.db, rx));

    let graceful = server.with_graceful_shutdown(async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to create Ctrl+C shutdown signal");
    });

    // Await the server to receive the shutdown signal
    if let Err(e) = graceful.await {
        eprintln!("shutdown error: {}", e);
    }

    Ok(())
}

async fn fallback(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("No route for {}", uri))
}
