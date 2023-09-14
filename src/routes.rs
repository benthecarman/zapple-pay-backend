use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::zap_config::ZapConfig;
use crate::State;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use diesel::{Connection, PgConnection};
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use nostr::hashes::hex::ToHex;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::NostrWalletConnectURI;
#[cfg(not(test))]
use nostr::prelude::ToBech32;
use nostr::Keys;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, String) {
    eprintln!("Error: {:?}", err);
    (StatusCode::BAD_REQUEST, format!("{err}"))
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

        // verify donations have a valid lnurl / lightning address
        if self.donations.as_ref().map_or(false, |d| {
            d.iter().any(|donation| {
                LnUrl::from_str(&donation.lnurl).is_err()
                    && LightningAddress::from_str(&donation.lnurl).is_err()
            })
        }) {
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
    pub lnurl: String,
}

/// How often a subscription should pay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionPeriod {
    /// Pays daily at midnight UTC
    Day,
    /// Pays every week on sunday, midnight UTC
    Week,
    /// Pays every month on the first, midnight UTC
    Month,
    /// Pays every year on the January 1st, midnight UTC
    Year,
    /// Pays every X seconds
    Seconds(u64),
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
            SubscriptionPeriod::Day => write!(f, "day"),
            SubscriptionPeriod::Week => write!(f, "week"),
            SubscriptionPeriod::Month => write!(f, "month"),
            SubscriptionPeriod::Year => write!(f, "year"),
            SubscriptionPeriod::Seconds(s) => write!(f, "{s} seconds"),
        }
    }
}

impl FromStr for SubscriptionPeriod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "day" => Ok(SubscriptionPeriod::Day),
            "week" => Ok(SubscriptionPeriod::Week),
            "month" => Ok(SubscriptionPeriod::Month),
            "year" => Ok(SubscriptionPeriod::Year),
            _ => {
                let s = s.trim_end_matches(" seconds");
                s.parse::<u64>()
                    .map(SubscriptionPeriod::Seconds)
                    .map_err(|_| anyhow::anyhow!("Invalid SubscriptionPeriod"))
            }
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

        match self.time_period {
            SubscriptionPeriod::Seconds(s) if s < 60 => {
                Err(anyhow::anyhow!("Must be at least 60 seconds"))
            }
            _ => Ok(()),
        }?;

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

pub(crate) fn set_user_config_impl(
    payload: SetUserConfig,
    state: &State,
) -> anyhow::Result<Vec<SetUserConfig>> {
    payload.verify()?;

    let emoji_str = payload.emoji().trim().to_string();

    if emoji_str.is_empty() {
        return Err(anyhow::anyhow!("Invalid emoji"));
    }

    let npub = payload.npub;
    let amt = payload.amount_sats;
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_user(&mut conn, &npub, &emoji_str, payload)?;

    let npub_hex = npub.to_hex();
    println!("New user: {npub_hex} {emoji_str} {amt}!");
    // notify new key
    let keys = state.pubkeys.lock().unwrap();
    keys.send_if_modified(|current| {
        if current.contains(&npub_hex) {
            false
        } else {
            current.push(npub_hex);
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
) -> Result<Json<Vec<SetUserConfig>>, (StatusCode, String)> {
    match set_user_config_impl(payload, &state) {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn create_user_subscription_impl(
    payload: CreateUserSubscription,
    state: &State,
) -> anyhow::Result<Vec<CreateUserSubscription>> {
    payload.verify()?;

    let npub = payload.npub;
    let to_npub = payload.to_npub;
    let amt = payload.amount_sats;
    let period = payload.time_period;
    let mut conn = state.db_pool.get()?;
    crate::models::upsert_subscription(&mut conn, payload)?;

    let npub_hex = npub.to_hex();
    let to_npub_hex = to_npub.to_hex();
    println!("New subscription: {npub_hex} -> {to_npub_hex} {amt} every {period}!");
    // notify new key
    // todo use subscription notifier
    let keys = state.pubkeys.lock().unwrap();
    keys.send_if_modified(|current| {
        if current.contains(&npub_hex) {
            false
        } else {
            current.push(npub_hex);
            true
        }
    });

    #[cfg(not(test))]
    {
        let keys = state.server_keys.clone();
        tokio::spawn(send_subscription_dm(keys, npub, to_npub, period, amt));
    }

    get_user_subscriptions_impl(&mut conn, npub)
}

pub async fn create_user_subscription(
    Extension(state): Extension<State>,
    Json(payload): Json<CreateUserSubscription>,
) -> Result<Json<Vec<CreateUserSubscription>>, (StatusCode, String)> {
    match create_user_subscription_impl(payload, &state) {
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
) -> anyhow::Result<Vec<SetUserConfig>> {
    let mut conn = state.db_pool.get()?;
    crate::models::get_user_zap_configs(&mut conn, npub).map(|configs| {
        configs
            .into_iter()
            .map(|user| {
                let donations = user
                    .donations
                    .into_iter()
                    .map(|donation| DonationConfig {
                        amount_sats: donation.amount as u64,
                        lnurl: donation.lnurl.to_string(),
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
    })
}

pub async fn get_user_configs(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<Vec<SetUserConfig>>, (StatusCode, String)> {
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
) -> Result<Json<Vec<SetUserConfig>>, (StatusCode, String)> {
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
        Ok(_) => get_user_configs_impl(npub, &state)
            .map(Json)
            .map_err(handle_anyhow_error),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_configs(
    Path(npub): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<Vec<SetUserConfig>>, (StatusCode, String)> {
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
        Ok(_) => get_user_configs_impl(npub, &state)
            .map(Json)
            .map_err(handle_anyhow_error),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn delete_user_subscription(
    Path((npub, to_npub)): Path<(String, String)>,
    Extension(state): Extension<State>,
) -> Result<Json<Vec<CreateUserSubscription>>, (StatusCode, String)> {
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
        Ok(_) => get_user_subscriptions_impl(&mut conn, npub)
            .map(Json)
            .map_err(handle_anyhow_error),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    users: i64,
    zap_configs: i64,
}

pub async fn count_impl(state: &State) -> anyhow::Result<Counts> {
    let mut conn = state.db_pool.get()?;

    conn.transaction(|conn| {
        let users = User::get_user_count(conn)?;
        let zap_configs = ZapConfig::get_config_count(conn)?;

        Ok(Counts { users, zap_configs })
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

#[cfg(test)]
mod test {
    use crate::models::MIGRATIONS;
    use crate::routes::*;
    use crate::State;
    use diesel::r2d2::{ConnectionManager, Pool};
    use diesel::{PgConnection, RunQueryDsl};
    use diesel_migrations::MigrationHarness;
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";
    const PUBKEY2: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const NWC: &str = "nostr+walletconnect://246be70a7e4966f138e9e48401f33c32a1c428bbfb7aab42e3946beb8bc15e7c?relay=wss%3A%2F%2Fnostr.mutinywallet.com%2F&secret=23ea701003500d852ba2756460099217f839e1fbc9665e493b56bd2d5912e31b";

    fn init_state() -> State {
        let manager = ConnectionManager::<PgConnection>::new(
            "postgres://username:password@localhost/zapple-pay",
        );
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
        let pubkeys = Arc::new(Mutex::new(tx));
        let server_keys = Keys::generate();

        State {
            db_pool,
            pubkeys,
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

        let current = set_user_config_impl(payload, &state).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();

        assert_eq!(current, configs);
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

            set_user_config_impl(payload, &state).unwrap();
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

        let current = create_user_subscription_impl(payload, &state).unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current, configs);
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

        let current = set_user_config_impl(payload, &state).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();

        assert_eq!(current, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].emoji(), emoji);
        assert!(configs[0].donations.is_none());

        let mut conn = state.db_pool.get().unwrap();
        crate::models::delete_user_config(&mut conn, npub, emoji).unwrap();

        let configs = get_user_configs_impl(npub, &state).unwrap();
        assert_eq!(configs.len(), 0);

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
            time_period: SubscriptionPeriod::Seconds(100),
            nwc: NWC.to_string(),
        };

        let current = create_user_subscription_impl(payload, &state).unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].to_npub, to_npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].time_period, SubscriptionPeriod::Seconds(100));

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

        let current = create_user_subscription_impl(payload, &state).unwrap();

        let mut conn = state.db_pool.get().unwrap();
        let configs = get_user_subscriptions_impl(&mut conn, npub).unwrap();

        assert_eq!(current, configs);
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

            set_user_config_impl(payload, &state).unwrap();
        }

        crate::models::delete_user(&mut conn, npub).unwrap();

        let subs = get_user_subscriptions_impl(&mut conn, npub).unwrap();
        assert_eq!(subs.len(), 0);

        let configs = get_user_configs_impl(npub, &state).unwrap();
        assert_eq!(configs.len(), 0);

        clear_database(&state);
    }
}
