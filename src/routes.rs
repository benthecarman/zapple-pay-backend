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
use serde::{Deserialize, Serialize};
use sled::Db;
use std::str::FromStr;

pub(crate) fn handle_anyhow_error(err: anyhow::Error) -> (StatusCode, String) {
    eprintln!("Error: {:?}", err);
    (StatusCode::BAD_REQUEST, format!("{err}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetUserConfig {
    pub npub: XOnlyPublicKey,
    pub amount_sats: u64,
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

        Ok(crate::db::UserConfig::new(
            self.amount_sats,
            NostrWalletConnectURI::from_str(&nwc)?,
            donations,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationConfig {
    pub amount_sats: u64,
    pub lnurl: String,
}

pub(crate) fn set_user_config_impl(payload: SetUserConfig, state: &State) -> anyhow::Result<()> {
    let valid = payload
        .donations()
        .iter()
        .all(|donation| LnUrl::from_str(&donation.lnurl).is_ok());

    if !valid {
        return Err(anyhow::anyhow!("Invalid lnurl"));
    }

    let npub = payload.npub;
    let emoji = payload.emoji();
    match payload.into_db() {
        Ok(config) => {
            crate::db::upsert_user(&state.db, npub, &emoji, config)?;

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

            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub async fn set_user_config(
    Extension(state): Extension<State>,
    Json(payload): Json<SetUserConfig>,
) -> Result<Json<()>, (StatusCode, String)> {
    match set_user_config_impl(payload, &state) {
        Ok(_) => Ok(Json(())),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

#[allow(dead_code)]
pub(crate) fn get_user_config_impl(
    npub: XOnlyPublicKey,
    emoji: String,
    db: &Db,
) -> anyhow::Result<Option<SetUserConfig>> {
    crate::db::get_user(db, npub, &emoji).map(|user| {
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
                nwc: user.nwc().to_string(),
                emoji: Some(user.emoji()),
                donations,
            }
        })
    })
}

#[allow(dead_code)]
pub async fn get_user_config(
    Path(npub): Path<String>,
    Path(emoji): Path<String>,
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

pub async fn delete_user_config(
    Path(npub): Path<String>,
    Path(emoji): Path<String>,
    Extension(state): Extension<State>,
) -> Result<Json<()>, (StatusCode, String)> {
    let npub = XOnlyPublicKey::from_str(&npub).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            String::from("{\"status\":\"ERROR\",\"reason\":\"Invalid npub\"}"),
        )
    })?;

    match crate::db::delete_user(&state.db, npub, &emoji) {
        Ok(_) => Ok(Json(())),
        Err(e) => Err(handle_anyhow_error(e)),
    }
}

pub async fn count(
    Extension(state): Extension<State>,
) -> Result<Json<usize>, (StatusCode, String)> {
    Ok(Json(state.db.len()))
}
