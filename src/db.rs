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
        emoji: Option<String>,
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
            emoji,
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

pub fn upsert_user(db: &Db, npub: XOnlyPublicKey, config: UserConfig) -> anyhow::Result<()> {
    let value = serde_json::to_vec(&config).unwrap();
    db.insert(npub.serialize(), value)?;

    Ok(())
}

pub fn get_user(db: &Db, npub: XOnlyPublicKey) -> anyhow::Result<Option<UserConfig>> {
    let value = db.get(npub.serialize())?;

    match value {
        Some(value) => {
            let config = serde_json::from_slice(&value)?;
            Ok(Some(config))
        }
        None => Ok(None),
    }
}
