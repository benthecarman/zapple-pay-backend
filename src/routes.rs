use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::zap_config::ZapConfig;
use crate::models::zap_event::ZapEvent;
use crate::State;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{Datelike, Duration, NaiveDateTime, Timelike, Utc};
use diesel::{Connection, PgConnection};
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use nostr::hashes::hex::ToHex;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::NostrWalletConnectURI;
#[cfg(not(test))]
use nostr::prelude::ToBech32;
use nostr::{Keys, Url, SECP256K1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, String) {
    eprintln!("Error: {:?}", err);
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
    #[serde(skip_serializing_if = "String::is_empty")]
    nwc: String,
    pub emoji: Option<String>,
    pub donations: Option<Vec<DonationConfig>>,
}

impl SetUserConfig {
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.amount_sats == 0 {
            return Err(anyhow::anyhow!("Invalid amount"));
        }

        if NostrWalletConnectURI::from_str(&self.nwc).is_err() {
            return Err(anyhow::anyhow!("Invalid nwc"));
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
        self.emoji.clone().unwrap_or("⚡".to_string())
    }

    pub fn nwc(&self) -> NostrWalletConnectURI {
        NostrWalletConnectURI::from_str(&self.nwc).unwrap()
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

pub const ALL_SUBSCRIPTION_PERIODS: [SubscriptionPeriod; 6] = [
    SubscriptionPeriod::Minute,
    SubscriptionPeriod::Hour,
    SubscriptionPeriod::Day,
    SubscriptionPeriod::Week,
    SubscriptionPeriod::Month,
    SubscriptionPeriod::Year,
];

/// How often a subscription should pay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionPeriod {
    /// Pays at the top of every minute
    Minute,
    /// Pays at the top of every hour
    Hour,
    /// Pays daily at midnight
    Day,
    /// Pays every week on sunday, midnight
    Week,
    /// Pays every month on the first, midnight
    Month,
    /// Pays every year on the January 1st, midnight
    Year,
}

impl SubscriptionPeriod {
    pub fn period_start(&self) -> NaiveDateTime {
        let now = Utc::now();
        match self {
            SubscriptionPeriod::Minute => now
                .date_naive()
                .and_hms_opt(now.hour(), now.minute(), 0)
                .unwrap(),
            SubscriptionPeriod::Hour => now.date_naive().and_hms_opt(now.hour(), 0, 0).unwrap(),
            SubscriptionPeriod::Day => now.date_naive().and_hms_opt(0, 0, 0).unwrap(),
            SubscriptionPeriod::Week => (now
                - Duration::days((now.weekday().num_days_from_sunday()) as i64))
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
            SubscriptionPeriod::Month => now
                .date_naive()
                .with_day(1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            SubscriptionPeriod::Year => NaiveDateTime::new(
                now.date_naive().with_ordinal(1).unwrap(),
                chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
        }
    }
}

impl Serialize for SubscriptionPeriod {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> Deserialize<'a> for SubscriptionPeriod {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SubscriptionPeriod::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl core::fmt::Display for SubscriptionPeriod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SubscriptionPeriod::Minute => write!(f, "minute"),
            SubscriptionPeriod::Hour => write!(f, "hour"),
            SubscriptionPeriod::Day => write!(f, "day"),
            SubscriptionPeriod::Week => write!(f, "week"),
            SubscriptionPeriod::Month => write!(f, "month"),
            SubscriptionPeriod::Year => write!(f, "year"),
        }
    }
}

impl FromStr for SubscriptionPeriod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minute" => Ok(SubscriptionPeriod::Minute),
            "hour" => Ok(SubscriptionPeriod::Hour),
            "day" => Ok(SubscriptionPeriod::Day),
            "week" => Ok(SubscriptionPeriod::Week),
            "month" => Ok(SubscriptionPeriod::Month),
            "year" => Ok(SubscriptionPeriod::Year),
            _ => Err(anyhow::anyhow!("Invalid SubscriptionPeriod")),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateUserSubscription {
    pub npub: XOnlyPublicKey,
    pub to_npub: XOnlyPublicKey,
    pub amount_sats: u64,
    pub time_period: SubscriptionPeriod,
    #[serde(skip_serializing_if = "String::is_empty")]
    nwc: String,
}

impl CreateUserSubscription {
    pub fn verify(&self) -> anyhow::Result<()> {
        if self.amount_sats == 0 {
            return Err(anyhow::anyhow!("Invalid amount"));
        }

        if NostrWalletConnectURI::from_str(&self.nwc).is_err() {
            return Err(anyhow::anyhow!("Invalid nwc"));
        }

        if self.npub == self.to_npub {
            return Err(anyhow::anyhow!("Cannot subscribe to yourself"));
        }

        Ok(())
    }

    pub fn nwc(&self) -> NostrWalletConnectURI {
        NostrWalletConnectURI::from_str(&self.nwc).unwrap()
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
    println!("Sent DM: {}", event_id);
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
    println!("Sent DM: {event_id}");
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
    println!("Sent DM: {event_id}");
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
    println!("Sent DM: {event_id}");
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
    println!("Sent DM: {event_id}");
    client.disconnect().await?;

    Ok(())
}

pub(crate) async fn set_user_config_impl(
    payload: SetUserConfig,
    state: &State,
) -> anyhow::Result<UserConfigs> {
    payload.verify()?;

    let emoji_str = payload.emoji().trim().to_string();

    if emoji_str.is_empty() {
        return Err(anyhow::anyhow!("Invalid emoji"));
    }

    let npub = payload.npub;
    let amt = payload.amount_sats;
    let secret_key_pk = payload.nwc().secret.x_only_public_key(SECP256K1).0;
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_user(&mut conn, payload)?;

    let npub_hex = npub.to_hex();
    println!("New user: {npub_hex} {emoji_str} {amt}!");
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
    let secret_key_pk = payload.nwc().secret.x_only_public_key(SECP256K1).0;
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_subscription(&mut conn, payload)?;

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
    println!("New subscription: {npub_hex} -> {to_npub_hex} {amt} every {period}!");

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
                nwc: "".to_string(), // don't return the nwc
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
                    nwc: "".to_string(), // don't return the nwc
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
            nwc: "".to_string(),
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
            nwc: "".to_string(),
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
        nwc: "".to_string(),
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
    ZapConfig::get_nwc_relays(&mut conn)
}

pub async fn relays(
    Extension(state): Extension<State>,
) -> Result<Json<HashMap<Url, usize>>, (StatusCode, String)> {
    match relays_impl(&state).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[cfg(test)]
mod test {
    use crate::models::MIGRATIONS;
    use crate::routes::*;
    use crate::State;
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
        let server_keys = Keys::generate();

        State {
            db_pool,
            pubkey_channel,
            secret_channel,
            server_keys,
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

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: NWC.to_string(),
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
    async fn test_create_config_emojis() {
        let state = init_state();
        clear_database(&state);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();

        let emojis = ["⚡️", "🤙", "👍", "❤️", "🫂"];

        for emoji in emojis {
            let payload = SetUserConfig {
                npub,
                amount_sats: 21,
                nwc: NWC.to_string(),
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

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Day,
            nwc: NWC.to_string(),
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
        let emoji = "⚡";

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: NWC.to_string(),
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

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Hour,
            nwc: NWC.to_string(),
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

        let payload = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 21,
            time_period: SubscriptionPeriod::Year,
            nwc: NWC.to_string(),
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
                nwc: NWC.to_string(),
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
