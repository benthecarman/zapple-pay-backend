use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::wallet_auth::WalletAuth;
use crate::models::zap_config::ZapConfig;
use crate::models::zap_event::ZapEvent;
use crate::nip49::{NIP49Budget, SubscriptionPeriod, NIP49URI};
use crate::utils::map_emoji;
use crate::{utils, State, DEFAULT_AUTH_RELAY};
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use diesel::{Connection, PgConnection};
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use log::*;
use nostr::hashes::hex::ToHex;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::NostrWalletConnectURI;
use nostr::prelude::Method;
#[cfg(not(test))]
use nostr::prelude::ToBech32;
use nostr::{Keys, Url, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;

pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, String) {
    error!("Error: {:?}", err);
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{err}"))
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserConfigs {
    zaps: Vec<SetUserConfig>,
    subscriptions: Vec<CreateUserSubscription>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SetUserConfig {
    pub npub: XOnlyPublicKey,
    pub amount_sats: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nwc: Option<NostrWalletConnectURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<XOnlyPublicKey>,
    pub emoji: Option<String>,
    pub donations: Option<Vec<DonationConfig>>,
}

impl SetUserConfig {
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.amount_sats == 0 {
            return Err(anyhow::anyhow!("Invalid amount"));
        }

        if self.nwc.is_some() == self.auth_id.is_some() {
            return Err(anyhow::anyhow!("Can only have nwc or auth_id"));
        }

        // verify donations have a valid lnurl / lightning address / npub
        if self
            .donations
            .as_ref()
            .map_or(false, |d| d.iter().any(|d| !d.is_valid()))
        {
            return Err(anyhow::anyhow!("Invalid lnurl in donation"));
        }

        Ok(())
    }

    pub fn emoji(&self) -> String {
        self.emoji
            .clone()
            .map(|e| map_emoji(&e).unwrap_or(&e).trim().to_string())
            .unwrap_or("⚡".to_string())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DonationConfig {
    pub amount_sats: u64,
    pub lnurl: Option<String>,
    pub npub: Option<XOnlyPublicKey>,
}

impl DonationConfig {
    pub fn is_valid(&self) -> bool {
        match (self.lnurl.as_ref(), self.npub.as_ref()) {
            (Some(lnurl), None) => {
                LnUrl::from_str(lnurl).is_ok() || LightningAddress::from_str(lnurl).is_ok()
            }
            (None, Some(_)) => true, // valid by parser
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateUserSubscription {
    pub npub: XOnlyPublicKey,
    pub to_npub: XOnlyPublicKey,
    pub amount_sats: u64,
    pub time_period: SubscriptionPeriod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nwc: Option<NostrWalletConnectURI>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<XOnlyPublicKey>,
}

impl CreateUserSubscription {
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.amount_sats == 0 {
            return Err(anyhow::anyhow!("Invalid amount"));
        }

        if self.nwc.is_some() == self.auth_id.is_some() {
            return Err(anyhow::anyhow!("Can only have nwc or auth_id"));
        }

        if self.npub == self.to_npub {
            return Err(anyhow::anyhow!("Cannot subscribe to yourself"));
        }

        Ok(())
    }
}

#[cfg(not(test))]
async fn send_config_dm(
    keys: Keys,
    npub: XOnlyPublicKey,
    emoji: String,
    amt: u64,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client
        .add_relay("wss://nostr.mutinywallet.com", None)
        .await?;
    client.connect().await;

    let sats = if amt == 1 { "sat" } else { "sats" };
    let content = format!("You have configured Zapple Pay to zap {amt} {sats} anytime you react to a note with a {emoji} emoji!");

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {}", event_id);
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_subscription_dm(
    keys: Keys,
    npub: XOnlyPublicKey,
    to_npub: XOnlyPublicKey,
    period: SubscriptionPeriod,
    amt: u64,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client
        .add_relay("wss://nostr.mutinywallet.com", None)
        .await?;
    client.connect().await;

    let sats = if amt == 1 { "sat" } else { "sats" };
    let content = format!(
        "You have subscribed to {} by zapping them {amt} {sats} every {period}!",
        to_npub.to_bech32().expect("bech32")
    );

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_deleted_config_dm(
    keys: Keys,
    npub: XOnlyPublicKey,
    emoji: String,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client
        .add_relay("wss://nostr.mutinywallet.com", None)
        .await?;
    client.connect().await;

    let content =
        format!("You have deleted your Zapple Pay config for reactions with a {emoji} emoji!");

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_deleted_subscription_dm(
    keys: Keys,
    npub: XOnlyPublicKey,
    to_npub: XOnlyPublicKey,
) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client
        .add_relay("wss://nostr.mutinywallet.com", None)
        .await?;
    client.connect().await;

    let content = format!(
        "You have canceled your subscription to {}",
        to_npub.to_bech32().expect("bech32")
    );

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

#[cfg(not(test))]
async fn send_deleted_user_dm(keys: Keys, npub: XOnlyPublicKey) -> anyhow::Result<()> {
    let client = nostr_sdk::Client::new(&keys);
    client
        .add_relay("wss://nostr.mutinywallet.com", None)
        .await?;
    client.connect().await;

    let content = String::from("You have deleted your Zapple Pay account.");

    let event_id = client.send_direct_msg(npub, content, None).await?;
    debug!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

pub(crate) async fn set_user_config_impl(
    payload: SetUserConfig,
    state: &State,
) -> anyhow::Result<UserConfigs> {
    payload.verify()?;

    let emoji_str = payload.emoji();

    if emoji_str.is_empty() {
        return Err(anyhow::anyhow!("Invalid emoji"));
    }

    let npub = payload.npub;
    let amt = payload.amount_sats;
    let secret_key_pk = match payload.nwc.as_ref() {
        Some(nwc) => nwc.secret.x_only_public_key(SECP256K1).0,
        None => payload.auth_id.unwrap(),
    };
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_user(&mut conn, payload)?;
    drop(conn);

    let npub_hex = npub.to_hex();
    info!("New user: {npub_hex} {emoji_str} {amt}!");
    // notify new pubkey
    let keys = state.pubkey_channel.lock().await;
    keys.send_if_modified(|current| {
        if current.contains(&npub_hex) {
            false
        } else {
            current.push(npub_hex);
            true
        }
    });

    // notify new secret key
    let secrets = state.secret_channel.lock().await;
    secrets.send_if_modified(|current| {
        if current.contains(&secret_key_pk) {
            false
        } else {
            current.push(secret_key_pk);
            true
        }
    });

    #[cfg(not(test))]
    {
        let keys = state.server_keys.clone();
        tokio::spawn(send_config_dm(keys, npub, emoji_str, amt));
    }

    get_user_configs_impl(npub, state)
}

pub async fn set_user_config(
    Extension(state): Extension<State>,
    Json(payload): Json<SetUserConfig>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    match set_user_config_impl(payload, &state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) async fn create_user_subscription_impl(
    payload: CreateUserSubscription,
    state: &State,
) -> anyhow::Result<UserConfigs> {
    payload.verify()?;

    let npub = payload.npub;
    let to_npub = payload.to_npub;
    let amt = payload.amount_sats;
    let period = payload.time_period;
    let secret_key_pk = match payload.nwc.as_ref() {
        Some(nwc) => nwc.secret.x_only_public_key(SECP256K1).0,
        None => payload.auth_id.unwrap(),
    };
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_subscription(&mut conn, payload)?;
    drop(conn);

    // notify new secret key
    let secrets = state.secret_channel.lock().await;
    secrets.send_if_modified(|current| {
        if current.contains(&secret_key_pk) {
            false
        } else {
            current.push(secret_key_pk);
            true
        }
    });

    let npub_hex = npub.to_hex();
    let to_npub_hex = to_npub.to_hex();
    info!("New subscription: {npub_hex} -> {to_npub_hex} {amt} every {period}!");

    #[cfg(not(test))]
    {
        let keys = state.server_keys.clone();
        tokio::spawn(send_subscription_dm(keys, npub, to_npub, period, amt));
    }

    get_user_configs_impl(npub, state)
}

pub async fn create_user_subscription(
    Extension(state): Extension<State>,
    Json(payload): Json<CreateUserSubscription>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    match create_user_subscription_impl(payload, &state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_config_impl(
    npub: XOnlyPublicKey,
    emoji: String,
    state: &State,
) -> anyhow::Result<Option<SetUserConfig>> {
    let mut conn = state.db_pool.get()?;
    crate::models::get_user_zap_config(&mut conn, npub, &emoji).map(|user| {
        user.map(|user| {
            let donations = user
                .donations
                .into_iter()
                .map(|donation| DonationConfig {
                    amount_sats: donation.amount as u64,
                    npub: donation.npub(),
                    lnurl: donation.lnurl,
                })
                .collect::<Vec<DonationConfig>>();

            let donations = if donations.is_empty() {
                None
            } else {
                Some(donations)
            };

            SetUserConfig {
                npub,
                amount_sats: user.zap_config.amount as u64,
                nwc: None, // don't return the nwc
                auth_id: None,
                emoji: Some(user.zap_config.emoji),
                donations,
            }
        })
    })
}

pub async fn get_user_config(
    Path((npub, emoji)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<SetUserConfig>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    match get_user_config_impl(npub, emoji, &state) {
        Ok(Some(res)) => Ok(Json(res)),
        Ok(None) => Err((StatusCode::NOT_FOUND, String::from("{\"status\":\"ERROR\",\"reason\":\"The user you're searching for could not be found.\"}"))),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_configs_impl(
    npub: XOnlyPublicKey,
    state: &State,
) -> anyhow::Result<UserConfigs> {
    let mut conn = state.db_pool.get()?;
    let zaps = crate::models::get_user_zap_configs(&mut conn, npub).map(|configs| {
        configs
            .into_iter()
            .map(|user| {
                let donations = user
                    .donations
                    .into_iter()
                    .map(|donation| DonationConfig {
                        amount_sats: donation.amount as u64,
                        npub: donation.npub(),
                        lnurl: donation.lnurl,
                    })
                    .collect::<Vec<DonationConfig>>();

                let donations = if donations.is_empty() {
                    None
                } else {
                    Some(donations)
                };

                SetUserConfig {
                    npub,
                    amount_sats: user.zap_config.amount as u64,
                    nwc: None, // don't return the nwc
                    auth_id: None,
                    emoji: Some(user.zap_config.emoji),
                    donations,
                }
            })
            .collect()
    })?;

    let subscriptions = SubscriptionConfig::get_by_pubkey(&mut conn, &npub)?
        .into_iter()
        .map(|c| CreateUserSubscription {
            npub,
            to_npub: c.to_npub(),
            amount_sats: c.amount as u64,
            time_period: c.time_period(),
            nwc: None,
            auth_id: None,
        })
        .collect();

    Ok(UserConfigs {
        zaps,
        subscriptions,
    })
}

pub async fn get_user_configs(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    match get_user_configs_impl(npub, &state) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_subscriptions_impl(
    conn: &mut PgConnection,
    npub: XOnlyPublicKey,
) -> anyhow::Result<Vec<CreateUserSubscription>> {
    let configs = SubscriptionConfig::get_by_pubkey(conn, &npub)?;
    let res = configs
        .into_iter()
        .map(|c| CreateUserSubscription {
            npub,
            to_npub: c.to_npub(),
            amount_sats: c.amount as u64,
            time_period: c.time_period(),
            nwc: None,
            auth_id: None,
        })
        .collect();

    Ok(res)
}

pub async fn get_user_subscriptions(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<Vec<CreateUserSubscription>>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;
    match get_user_subscriptions_impl(&mut conn, npub) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_subscription_impl(
    conn: &mut PgConnection,
    npub: XOnlyPublicKey,
    to_npub: XOnlyPublicKey,
) -> anyhow::Result<Option<CreateUserSubscription>> {
    let c = SubscriptionConfig::get_by_pubkey_and_to_npub(conn, &npub, &to_npub)?;

    Ok(c.map(|c| CreateUserSubscription {
        npub,
        to_npub: c.to_npub(),
        amount_sats: c.amount as u64,
        time_period: c.time_period(),
        nwc: None,
        auth_id: None,
    }))
}

pub async fn get_user_subscription(
    Path((npub, to_npub)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<CreateUserSubscription>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    let to_npub = XOnlyPublicKey::from_str(&to_npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid to_npub\"}"),
        )
    })?;
    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match get_user_subscription_impl(&mut conn, npub, to_npub) {
        Ok(Some(res)) => Ok(Json(res)),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Subscription not found.\"}"),
        )),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_config(
    Path((npub, emoji)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_user_config(&mut conn, npub, &emoji) {
        Ok(_) => {
            #[cfg(not(test))]
            {
                let keys = state.server_keys.clone();
                tokio::spawn(send_deleted_config_dm(keys, npub, emoji));
            }

            get_user_configs_impl(npub, &state)
                .map(Json)
                .map_err(handle_anyhow_error)
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_configs(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_user(&mut conn, npub) {
        Ok(_) => {
            #[cfg(not(test))]
            {
                let keys = state.server_keys.clone();
                tokio::spawn(send_deleted_user_dm(keys, npub));
            }

            get_user_configs_impl(npub, &state)
                .map(Json)
                .map_err(handle_anyhow_error)
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_subscription(
    Path((npub, to_npub)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<UserConfigs>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;
    let to_npub = XOnlyPublicKey::from_str(&to_npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid to_npub\"}"),
        )
    })?;

    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;

    match crate::models::delete_user_subscription(&mut conn, npub, to_npub) {
        Ok(_) => {
            #[cfg(not(test))]
            {
                let keys = state.server_keys.clone();
                tokio::spawn(send_deleted_subscription_dm(keys, npub, to_npub));
            }

            get_user_configs_impl(npub, &state)
                .map(Json)
                .map_err(handle_anyhow_error)
        }
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn wallet_auth_impl(
    state: &State,
    budget: Option<NIP49Budget>,
) -> anyhow::Result<NIP49URI> {
    let auth = {
        let mut conn = state.db_pool.get()?;
        WalletAuth::create(&mut conn, state.xpriv)?
    };

    let public_key = auth.pubkey();
    let secret = utils::calculate_nwa_secret(state.xpriv, public_key);

    let uri = NIP49URI {
        public_key,
        relay_url: Url::parse(DEFAULT_AUTH_RELAY)?,
        secret,
        required_commands: vec![Method::PayInvoice],
        optional_commands: vec![],
        budget,
        identity: Some(state.server_keys.public_key()),
    };

    // notify new auth key
    let auths = state.auth_channel.lock().await;
    auths.send_if_modified(|current| {
        // public_key should be unique, don't need to check for duplicates
        current.push(public_key);
        true
    });

    Ok(uri)
}

pub async fn wallet_auth(
    Extension(state): Extension<State>,
    payload: Option<Query<NIP49Budget>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let budget = payload.map(|p| p.0);
    match wallet_auth_impl(&state, budget).await {
        Ok(uri) => Ok(Json(json!({"id": uri.public_key.to_hex(), "uri": uri}))),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    users: i64,
    zap_configs: i64,
    subscription_configs: i64,
    zap_count: i64,
    unconfirmed_count: i64,
    zap_total: i64,
}

pub async fn count_impl(state: &State) -> anyhow::Result<Counts> {
    let mut conn = state.db_pool.get()?;

    conn.transaction(|conn| {
        let users = User::get_user_count(conn)?;
        let zap_configs = ZapConfig::get_config_count(conn)?;
        let subscription_configs = SubscriptionConfig::get_config_count(conn)?;
        let zap_count = ZapEvent::get_zap_count(conn)?;
        let unconfirmed_count = ZapEvent::get_unconfirmed_zap_count(conn)?;
        let zap_total = ZapEvent::get_zap_total(conn)?;

        Ok(Counts {
            users,
            zap_configs,
            subscription_configs,
            zap_count,
            unconfirmed_count,
            zap_total,
        })
    })
}

pub async fn count(
    Extension(state): Extension<State>,
) -> Result<Json<Counts>, (StatusCode, String)> {
    match count_impl(&state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn relays_impl(state: &State) -> anyhow::Result<HashMap<Url, usize>> {
    let mut conn = state.db_pool.get()?;
    let mut zap = ZapConfig::get_nwc_relays(&mut conn)?;
    let subs = SubscriptionConfig::get_nwc_relays(&mut conn)?;

    for (key, count) in subs {
        *zap.entry(key).or_insert(0) += count;
    }

    Ok(zap)
}

pub async fn relays(
    Extension(state): Extension<State>,
) -> Result<Json<HashMap<Url, usize>>, (StatusCode, String)> {
    match relays_impl(&state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn migrate_emojis(
    Extension(state): Extension<State>,
) -> Result<Json<usize>, (StatusCode, String)> {
    let mut conn = state.db_pool.get().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Could not get db connection\"}"),
        )
    })?;
    match ZapConfig::migrate_emojis(&mut conn) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[cfg(test)]
mod test {
    use crate::models::MIGRATIONS;
    use crate::routes::*;
    use crate::State;
    use bitcoin::util::bip32::ExtendedPrivKey;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::{PgConnection, RunQueryDsl};
    use diesel_migrations::MigrationHarness;
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex};

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";
    const PUBKEY2: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const NWC: &str = "nostr+walletconnect://246be70a7e4966f138e9e48401f33c32a1c428bbfb7aab42e3946beb8bc15e7c?relay=wss%3A%2F%2Fnostr.mutinywallet.com%2F&secret=23ea701003500d852ba2756460099217f839e1fbc9665e493b56bd2d5912e31b";

    fn init_state() -> State {
        dotenv::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let manager = ConnectionManager::<PgConnection>::new(url);
        let db_pool = Pool::builder()
            .max_size(16)
            .test_on_check_out(true)
            .build(manager)
            .expect("Could not build connection pool");

        // run migrations
        let mut connection = db_pool.get().unwrap();
        connection
            .run_pending_migrations(MIGRATIONS)
            .expect("migrations could not run");

        let (tx, _) = watch::channel(vec![]);
        let pubkey_channel = Arc::new(Mutex::new(tx));
        let (tx, _) = watch::channel(vec![]);
        let secret_channel = Arc::new(Mutex::new(tx));
        let (tx, _) = watch::channel(vec![]);
        let auth_channel = Arc::new(Mutex::new(tx));
        let server_keys = Keys::generate();
        let xpriv = ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &[]).unwrap();

        State {
            db_pool,
            pubkey_channel,
            secret_channel,
            auth_channel,
            server_keys,
            xpriv,
        }
    }

    fn clear_database(state: &State) {
        let conn = &mut state.db_pool.get().unwrap();

        conn.transaction::<_, anyhow::Error, _>(|conn| {
            diesel::delete(crate::models::schema::zap_events::table).execute(conn)?;
            diesel::delete(crate::models::schema::donations::table).execute(conn)?;
            diesel::delete(crate::models::schema::subscription_configs::table).execute(conn)?;
            diesel::delete(crate::models::schema::zap_configs::table).execute(conn)?;
            diesel::delete(crate::models::schema::users::table).execute(conn)?;
            Ok(())
        })
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_config() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: Some(nwc),
            auth_id: None,
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        let configs = configs.zaps;

        assert_eq!(current.zaps, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].emoji(), "⚡");
        assert!(configs[0].donations.is_none());

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_config_with_auth() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();

        let uri = wallet_auth_impl(&state, None).await.unwrap();

        // set dummy pubkey
        WalletAuth::add_user_data(
            &mut state.db_pool.get().unwrap(),
            uri.public_key,
            npub,
            None,
        )
        .unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: None,
            auth_id: Some(uri.public_key),
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();
        assert_eq!(current.zaps.len(), 1);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_config_overwrite_with_auth() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();

        // set using nwc first
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: Some(nwc),
            auth_id: None,
            emoji: None,
            donations: None,
        };
        let current = set_user_config_impl(payload, &state).await.unwrap();
        assert_eq!(current.zaps.len(), 1);

        let uri = wallet_auth_impl(&state, None).await.unwrap();

        // set dummy pubkey
        WalletAuth::add_user_data(
            &mut state.db_pool.get().unwrap(),
            uri.public_key,
            npub,
            None,
        )
        .unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: None,
            auth_id: Some(uri.public_key),
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();
        assert_eq!(current.zaps.len(), 1);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_config_emojis() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let emojis = ["⚡️", "🤙", "👍", "❤️", "🫂"];

        for emoji in emojis {
            let payload = SetUserConfig {
                npub,
                amount_sats: 21,
                nwc: Some(nwc.clone()),
                auth_id: None,
                emoji: Some(emoji.to_string()),
                donations: None,
            };

            set_user_config_impl(payload, &state).await.unwrap();
        }

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_create_subscription() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let to_npub = XOnlyPublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current.subscriptions, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Day);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_delete_zap_config() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let emoji = "⚡";

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: Some(nwc),
            auth_id: None,
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).await.unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        let configs = configs.zaps;

        assert_eq!(current.zaps, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].emoji(), emoji);
        assert!(configs[0].donations.is_none());

        let mut conn = state.db_pool.get().unwrap();
        crate::models::delete_user_config(&mut conn, npub, emoji).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        assert_eq!(configs.zaps.len(), 0);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_delete_subscription() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let to_npub = XOnlyPublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Hour,
            nwc: Some(nwc),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current.subscriptions, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Hour);

        crate::models::delete_user_subscription(&mut conn, npub, to_npub).unwrap();

        let subs = get_user_subscriptions_impl(&mut conn, npub).unwrap();
        assert_eq!(subs.len(), 0);

        clear_database(&state);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();
        let to_npub = XOnlyPublicKey::from_str(PUBKEY2).unwrap();

        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Year,
            nwc: Some(nwc.clone()),
            auth_id: None,
        };

        let current = create_user_subscription_impl(payload, &state)
            .await
            .unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current.subscriptions, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Year);

        let emojis = ["⚡️", "🤙", "👍", "❤️", "🫂"];

        for emoji in emojis {
            let payload = SetUserConfig {
                npub,
                amount_sats: 21,
                nwc: Some(nwc.clone()),
                auth_id: None,
                emoji: Some(emoji.to_string()),
                donations: None,
            };

            set_user_config_impl(payload, &state).await.unwrap();
        }

        crate::models::delete_user(&mut conn, npub).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        assert_eq!(configs.zaps.len(), 0);
        assert_eq!(configs.subscriptions.len(), 0);

        clear_database(&state);
    }
}
