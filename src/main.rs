#![allow(clippy::too_many_arguments)]

use crate::config::*;
use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::zap_config::ZapConfig;
use crate::models::MIGRATIONS;
use crate::routes::*;
use axum::http::{Method, StatusCode, Uri};
use axum::routing::{get, post};
use axum::{http, Extension, Router};
use bitcoin::hashes::hex::ToHex;
use clap::Parser;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use diesel_migrations::MigrationHarness;
use lnurl::lnurl::LnUrl;
use log::{error, info};
use nostr::key::{SecretKey, XOnlyPublicKey};
use nostr::{Keys, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, to_string};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch::Sender;
use tokio::sync::{watch, Mutex};
use tower_http::cors::{Any, CorsLayer};

mod config;
mod listener;
mod models;
mod profile_handler;
mod routes;
mod subscription_handler;

#[derive(Clone)]
pub struct State {
    db_pool: Pool<ConnectionManager<PgConnection>>,
    pubkey_channel: Arc<Mutex<Sender<Vec<String>>>>,
    secret_channel: Arc<Mutex<Sender<Vec<XOnlyPublicKey>>>>,
    pub server_keys: Keys,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::try_init()?;
    let config: Config = Config::parse();

    // Create the datadir if it doesn't exist
    let path = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(path.clone())?;

    // DB management
    let manager = ConnectionManager::<PgConnection>::new(&config.pg_url);
    let db_pool = Pool::builder()
        .max_size(16)
        .test_on_check_out(true)
        .build(manager)
        .expect("Could not build connection pool");

    // run migrations
    let mut connection = db_pool.get()?;
    connection
        .run_pending_migrations(MIGRATIONS)
        .expect("migrations could not run");

    let keys_path = {
        let mut path = path.clone();
        path.push("keys.json");
        path
    };

    let keys = get_keys(keys_path);

    let mut pubkeys = User::get_all_npubs(&mut connection)?
        .into_iter()
        .map(|u| u.to_hex())
        .collect::<Vec<_>>();
    pubkeys.sort();

    let mut secrets = ZapConfig::get_nwc_secrets(&mut connection)?;
    let subscription_secrets = SubscriptionConfig::get_nwc_secrets(&mut connection)?;
    secrets.extend(subscription_secrets);
    secrets.sort();
    secrets.dedup();
    drop(connection);

    // convert to pubkeys and hex
    let secrets = secrets
        .into_iter()
        .map(|s| s.x_only_public_key(SECP256K1).0)
        .collect::<Vec<_>>();

    let (pubkey_sender, pubkey_receiver) = watch::channel(pubkeys);
    let pubkey_channel = Arc::new(Mutex::new(pubkey_sender));

    let (secret_sender, secret_receiver) = watch::channel(secrets);
    let secret_channel = Arc::new(Mutex::new(secret_sender));

    let state = State {
        db_pool,
        pubkey_channel: pubkey_channel.clone(),
        secret_channel,
        server_keys: keys.server_keys(),
    };

    let addr: std::net::SocketAddr = format!("{}:{}", config.bind, config.port)
        .parse()
        .expect("Failed to parse bind/port for webserver");

    info!("Webserver running on http://{addr}");

    let server_router = Router::new()
        .route("/set-user", post(set_user_config))
        .route("/create-subscription", post(create_user_subscription))
        .route(
            "/delete-subscription/:npub/:to_npub",
            get(delete_user_subscription),
        )
        .route("/delete-user/:npub/:emoji", get(delete_user_config))
        .route("/delete-user/:npub", get(delete_user_configs))
        .route("/count", get(count))
        .route("/relays", get(relays))
        .route("/get-user/:npub/:emoji", get(get_user_config))
        .route("/get-user/:npub", get(get_user_configs))
        .route("/get-subscriptions/:npub", get(get_user_subscriptions))
        .route(
            "/get-subscriptions/:npub/:to_npub",
            get(get_user_subscription),
        )
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
            let tx = pubkey_channel.lock().await;
            tx.send_if_modified(|_| true);
        }
    });

    let lnurl_cache = Arc::new(Mutex::new(HashMap::new()));
    let pay_cache = Arc::new(Mutex::new(HashMap::new()));

    let relays = config.relay.clone();
    let db_pool = state.db_pool.clone();
    let server_keys = keys.server_keys();
    let l_cache = lnurl_cache.clone();
    let p_cache = pay_cache.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = listener::start_listener(
                relays.clone(),
                db_pool.clone(),
                pubkey_receiver.clone(),
                secret_receiver.clone(),
                server_keys.clone(),
                l_cache.clone(),
                p_cache.clone(),
            )
            .await
            {
                error!("listener error: {e}")
            }
        }
    });

    tokio::spawn(async move {
        loop {
            if let Err(e) = subscription_handler::start_subscription_handler(
                keys.server_keys(),
                config.relay.clone(),
                state.db_pool.clone(),
                lnurl_cache.clone(),
                pay_cache.clone(),
            )
            .await
            {
                error!("subscription handler error: {e}")
            }
        }
    });

    let graceful = server.with_graceful_shutdown(async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to create Ctrl+C shutdown signal");
    });

    // Await the server to receive the shutdown signal
    if let Err(e) = graceful.await {
        error!("shutdown error: {}", e);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LnUrlCacheResult {
    /// Successful result, contains the lnurl and the timestamp we got it
    LnUrl((LnUrl, u64)),
    /// Successful result, contains both lnurls and the timestamp we got it
    MultipleLnUrl((LnUrl, LnUrl, u64)),
    /// Failed result, contains the timestamp of the last metadata event
    Timestamp(u64),
}
