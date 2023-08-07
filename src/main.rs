#![allow(clippy::too_many_arguments)]

use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode, Uri};
use axum::routing::{get, post};
use axum::{http, Extension, Router};
use bitcoin::hashes::hex::ToHex;
use clap::Parser;
use nostr::key::{SecretKey, XOnlyPublicKey};
use nostr::Keys;
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, to_string};
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
    pub server_keys: Keys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config: Config = Config::parse();

    // Create the datadir if it doesn't exist
    let path = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(path.clone())?;

    let db_path = {
        let mut path = path.clone();
        path.push("sled.db");
        path
    };

    // DB management
    let db = sled::open(&db_path)?;

    let keys_path = {
        let mut path = path.clone();
        path.push("keys.json");
        path
    };

    let keys = get_keys(keys_path);

    let mut start = vec![];
    db.scan_prefix("").for_each(|res| {
        res.map(|(k, _)| {
            if let Ok(str) = String::from_utf8(k.to_vec()) {
                // take first 64 chars
                let pubkey_str = str.chars().take(64).collect::<String>();

                let xonly = XOnlyPublicKey::from_str(&pubkey_str)
                    .map_err(|e| {
                        println!("Failed to parse pubkey ({pubkey_str}) from db: {e}");
                    })
                    .ok();

                if let Some(xonly) = xonly {
                    start.push(xonly.to_hex());
                }
            }
        })
        .unwrap();
    });

    let (tx, rx) = watch::channel(start);

    let tx_shared = Arc::new(Mutex::new(tx));

    let state = State {
        db,
        pubkeys: tx_shared.clone(),
        server_keys: keys.server_keys(),
    };

    let addr: std::net::SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .expect("Failed to parse bind/port for webserver");

    println!("Webserver running on http://{}", addr);

    let server_router = Router::new()
        .route("/set-user", post(set_user_config))
        .route("/delete-user/:npub/:emoji", get(delete_user_config))
        .route("/delete-user/:npub", get(delete_user_configs))
        .route("/count", get(count))
        .route("/get-user/:npub/:emoji", get(get_user_config))
        .route("/get-user/:npub", get(get_user_configs))
        .fallback(fallback)
        .layer(Extension(state.clone()))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_headers(vec![http::header::CONTENT_TYPE])
                .allow_methods([Method::GET, Method::POST]),
        );

    let server = axum::Server::bind(&addr).serve(server_router.into_make_service());

    // restart nostr connections every hour
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * 60)).await;
            let tx = tx_shared.lock().unwrap();
            tx.send_if_modified(|_| true);
        }
    });

    tokio::spawn(subscriber::start_subscription(
        state.db,
        rx,
        keys.server_keys(),
    ));

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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ZapplePayKeys {
    server_key: SecretKey,
}

impl ZapplePayKeys {
    fn generate() -> Self {
        let server_key = Keys::generate();

        ZapplePayKeys {
            server_key: server_key.secret_key().unwrap(),
        }
    }

    fn server_keys(&self) -> Keys {
        Keys::new(self.server_key)
    }
}

fn get_keys(path: PathBuf) -> ZapplePayKeys {
    match File::open(&path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            from_reader(reader).expect("Could not parse JSON")
        }
        Err(_) => {
            let keys = ZapplePayKeys::generate();
            let json_str = to_string(&keys).expect("Could not serialize data");

            let mut file = File::create(path).expect("Could not create file");
            file.write_all(json_str.as_bytes())
                .expect("Could not write to file");

            keys
        }
    }
}
