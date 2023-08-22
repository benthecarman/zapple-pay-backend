use crate::State;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use lnurl::Error;
use nostr::hashes::hex::ToHex;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::NostrWalletConnectURI;
use nostr::Keys;
use nostr_sdk::Client;
use serde::{Deserialize, Serialize};
use sled::Db;
use std::str::FromStr;
use tokio::spawn;

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
    donations: Option<Vec<DonationConfig>>,
}

impl SetUserConfig {
    pub fn donations(&self) -> Vec<DonationConfig> {
        self.donations.clone().unwrap_or_default()
    }

    pub fn emoji(&self) -> String {
        self.emoji.clone().unwrap_or("⚡".to_string())
    }

    pub fn into_db(self) -> anyhow::Result<crate::db::UserConfig> {
        let donations = self
            .donations
            .unwrap_or_default()
            .into_iter()
            .map(|donation| {
                let lnurl = LnUrl::from_str(&donation.lnurl)
                    .or_else(|_| LightningAddress::from_str(&donation.lnurl).map(|l| l.lnurl()));

                match lnurl {
                    Ok(lnurl) => Ok(crate::db::DonationConfig {
                        amount_sats: donation.amount_sats,
                        lnurl,
                    }),
                    Err(e) => Err(e),
                }
            })
            .collect::<Vec<Result<crate::db::DonationConfig, Error>>>();

        let errors = donations
            .iter()
            .filter_map(|res| match res {
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            })
            .collect::<Vec<String>>();

        if !errors.is_empty() {
            return Err(anyhow::anyhow!("Invalid lnurl: {errors:?}"));
        }

        let donations = donations
            .into_iter()
            .filter_map(|res| match res {
                Ok(donation) => Some(donation),
                Err(_) => None,
            })
            .collect::<Vec<crate::db::DonationConfig>>();

        let nwc = self
            .nwc
            .replace("nostrwalletconnect", "nostr+walletconnect");

        let nwc =
            NostrWalletConnectURI::from_str(&nwc).map_err(|e| anyhow::anyhow!("{e}: {nwc}"))?;

        Ok(crate::db::UserConfig::new(self.amount_sats, nwc, donations))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DonationConfig {
    pub amount_sats: u64,
    pub lnurl: String,
}

async fn send_config_dm(
    keys: Keys,
    npub: XOnlyPublicKey,
    emoji: String,
    amt: u64,
) -> anyhow::Result<()> {
    let client = Client::new(&keys);
    client
        .add_relay("wss://nostr.mutinywallet.com", None)
        .await?;
    client.connect().await;

    let content = format!("You have configured Zapple Pay to zap {} sats anytime you react to a note with a {} emoji!", amt, emoji);

    let event_id = client.send_direct_msg(npub, content, None).await?;
    println!("Sent DM: {}", event_id);
    client.disconnect().await?;

    Ok(())
}

pub(crate) fn set_user_config_impl(
    payload: SetUserConfig,
    state: &State,
) -> anyhow::Result<Vec<SetUserConfig>> {
    let valid = payload.donations().iter().all(|donation| {
        LnUrl::from_str(&donation.lnurl).is_ok()
            || LightningAddress::from_str(&donation.lnurl).is_ok()
    });

    if !valid {
        return Err(anyhow::anyhow!("Invalid lnurl"));
    }

    let emoji_str = payload.emoji().trim().to_string();

    if emoji_str.is_empty() {
        return Err(anyhow::anyhow!("Invalid emoji"));
    }

    let npub = payload.npub;
    match payload.into_db() {
        Ok(config) => {
            let amt = config.amount_sats;
            crate::db::upsert_user(&state.db, npub, &emoji_str, config)?;

            let npub_hex = npub.to_hex();
            println!("New user: {}!", npub_hex);
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

            let keys = state.server_keys.clone();
            spawn(send_config_dm(keys, npub, emoji_str, amt));

            get_user_configs_impl(npub, &state.db)
        }
        Err(e) => Err(e),
    }
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

pub(crate) fn get_user_config_impl(
    npub: XOnlyPublicKey,
    emoji: String,
    db: &Db,
) -> anyhow::Result<Option<SetUserConfig>> {
    crate::db::get_user(db, npub, &emoji, true).map(|user| {
        user.map(|user| {
            let donations = user
                .donations()
                .into_iter()
                .map(|donation| DonationConfig {
                    amount_sats: donation.amount_sats,
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
                amount_sats: user.amount_sats,
                nwc: "".to_string(), // don't return the nwc
                emoji: Some(user.emoji()),
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
    match get_user_config_impl(npub, emoji, &state.db) {
        Ok(Some(res)) => Ok(Json(res)),
        Ok(None) => Err((StatusCode::NOT_FOUND, String::from("{\"status\":\"ERROR\",\"reason\":\"The user you're searching for could not be found.\"}"))),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub(crate) fn get_user_configs_impl(
    npub: XOnlyPublicKey,
    db: &Db,
) -> anyhow::Result<Vec<SetUserConfig>> {
    crate::db::get_user_configs(db, npub).map(|configs| {
        configs
            .into_iter()
            .map(|user| {
                let donations = user
                    .donations()
                    .into_iter()
                    .map(|donation| DonationConfig {
                        amount_sats: donation.amount_sats,
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
                    amount_sats: user.amount_sats,
                    nwc: "".to_string(), // don't return the nwc
                    emoji: Some(user.emoji()),
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
    match get_user_configs_impl(npub, &state.db) {
        Ok(res) => Ok(Json(res)),
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

    match crate::db::delete_user_config(&state.db, npub, &emoji) {
        Ok(_) => get_user_configs_impl(npub, &state.db)
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

    match crate::db::delete_user(&state.db, npub) {
        Ok(_) => get_user_configs_impl(npub, &state.db)
            .map(Json)
            .map_err(handle_anyhow_error),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn count(
    Extension(state): Extension<State>,
) -> Result<Json<usize>, (StatusCode, String)> {
    Ok(Json(state.db.len()))
}

pub async fn migrate(Extension(state): Extension<State>) -> Result<Json<()>, (StatusCode, String)> {
    match crate::db::migrate_jb55_lnurl(&state.db) {
        Ok(_) => Ok(Json(())),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[cfg(test)]
mod test {
    use crate::routes::*;
    use crate::State;
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::secp256k1::rand;
    use bitcoin::secp256k1::rand::Rng;
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";
    const NWC: &str = "nostr+walletconnect://246be70a7e4966f138e9e48401f33c32a1c428bbfb7aab42e3946beb8bc15e7c?relay=wss%3A%2F%2Fnostr.mutinywallet.com%2F&secret=23ea701003500d852ba2756460099217f839e1fbc9665e493b56bd2d5912e31b";

    fn gen_tmp_db_name() -> String {
        let rng = rand::thread_rng();
        let rand_string: String = rng
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(30)
            .collect::<Vec<u8>>()
            .to_hex();
        format!("/tmp/zapple_pay_{}.sled", rand_string)
    }

    fn init_state(db_name: &str) -> State {
        let db = sled::open(db_name).unwrap();

        let (tx, _) = watch::channel(vec![]);
        let pubkeys = Arc::new(Mutex::new(tx));
        let server_keys = Keys::generate();

        State {
            db,
            pubkeys,
            server_keys,
        }
    }

    fn teardown_database(db_name: &str) {
        std::fs::remove_dir_all(db_name).unwrap();
    }

    #[test]
    fn test_create_config() {
        let db_name = gen_tmp_db_name();
        let state = init_state(&db_name);

        let npub = XOnlyPublicKey::from_str(PUBKEY).unwrap();

        let payload = SetUserConfig {
            npub,
            amount_sats: 21,
            nwc: NWC.to_string(),
            emoji: None,
            donations: None,
        };

        let current = set_user_config_impl(payload, &state).unwrap();

        let configs = get_user_configs_impl(npub, &state.db).unwrap();

        assert_eq!(current, configs);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].npub, npub);
        assert_eq!(configs[0].amount_sats, 21);
        assert_eq!(configs[0].emoji(), "⚡");
        assert!(configs[0].donations.is_none());

        teardown_database(&db_name);
    }

    #[test]
    fn test_create_config_emojis() {
        let db_name = gen_tmp_db_name();
        let state = init_state(&db_name);

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

        teardown_database(&db_name);
    }
}
