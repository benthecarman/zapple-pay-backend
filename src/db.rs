use lnurl::lnurl::LnUrl;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::NostrWalletConnectURI;
use serde::{Deserialize, Serialize};
use sled::Db;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub amount_sats: u64,
    nwc: String,
    emoji: Option<String>,
    donations: Option<Vec<DonationConfig>>,
}

impl UserConfig {
    pub fn new(
        amount_sats: u64,
        nwc: NostrWalletConnectURI,
        donations: Vec<DonationConfig>,
    ) -> Self {
        let donations = if donations.is_empty() {
            None
        } else {
            Some(donations)
        };

        UserConfig {
            amount_sats,
            nwc: nwc.to_string(),
            emoji: None,
            donations,
        }
    }

    pub fn nwc(&self) -> NostrWalletConnectURI {
        NostrWalletConnectURI::from_str(&self.nwc).unwrap()
    }

    pub fn emoji(&self) -> String {
        self.emoji.clone().unwrap_or("⚡".to_string())
    }

    pub fn donations(&self) -> Vec<DonationConfig> {
        self.donations.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationConfig {
    pub amount_sats: u64,
    pub lnurl: LnUrl,
}

fn get_key(npub: XOnlyPublicKey, emoji: &str) -> String {
    format!("{}:{}", npub.to_string(), emoji)
}

pub fn upsert_user(
    db: &Db,
    npub: XOnlyPublicKey,
    emoji: &str,
    config: UserConfig,
) -> anyhow::Result<()> {
    let key = get_key(npub, emoji);
    let value = serde_json::to_vec(&config).unwrap();
    db.insert(key.as_bytes(), value)?;

    Ok(())
}

pub fn get_user(
    db: &Db,
    npub: XOnlyPublicKey,
    emoji: &str,
    retry: bool,
) -> anyhow::Result<Option<UserConfig>> {
    let key = get_key(npub, emoji);
    let value = db.get(key.as_bytes())?;

    match value {
        Some(value) => {
            let config = serde_json::from_slice(&value)?;
            Ok(Some(config))
        }
        None => match emoji {
            "⚡️" => {
                if retry {
                    get_user(db, npub, "⚡", false)
                } else {
                    Ok(None)
                }
            }
            "⚡" => {
                if retry {
                    get_user(db, npub, "⚡️", false)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        },
    }
}

pub fn get_user_configs(db: &Db, npub: XOnlyPublicKey) -> anyhow::Result<Vec<UserConfig>> {
    let value = db.scan_prefix(npub.to_string().as_bytes());

    let mut configs = vec![];
    for result in value {
        let (_, value) = result?;
        let config = serde_json::from_slice(&value)?;
        configs.push(config);
    }

    Ok(configs)
}

pub fn delete_user(db: &Db, npub: XOnlyPublicKey, emoji: &str) -> anyhow::Result<()> {
    let key = get_key(npub, emoji);
    db.remove(key.as_bytes())?;
    Ok(())
}
