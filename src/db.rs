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

pub fn get_user(db: &Db, npub: XOnlyPublicKey, emoji: &str) -> anyhow::Result<Option<UserConfig>> {
    let key = get_key(npub, emoji);
    let value = db.get(key.as_bytes())?;

    match value {
        Some(value) => {
            let config = serde_json::from_slice(&value)?;
            Ok(Some(config))
        }
        None => Ok(None),
    }
}

pub fn delete_user(db: &Db, npub: XOnlyPublicKey, emoji: &str) -> anyhow::Result<()> {
    let key = get_key(npub, emoji);
    db.remove(key.as_bytes())?;
    Ok(())
}

pub fn run_migration(db: &Db) -> anyhow::Result<usize> {
    let mut count = 0;

    for key in db.iter().keys() {
        let key = key?;
        let value = db.get(key.clone())?;

        if let Some(value) = value {
            let mut config = serde_json::from_slice::<UserConfig>(&value)?;
            let emoji = config.emoji();
            config.emoji = None;

            if let Ok(npub) = XOnlyPublicKey::from_slice(key.as_ref()) {
                upsert_user(db, npub, &emoji, config)?;

                db.remove(npub.serialize())?;
                count += 1;
            }
        }
    }

    Ok(count)
}
