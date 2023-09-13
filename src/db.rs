use crate::models;
use diesel::PgConnection;
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

    pub fn donations(&self) -> Vec<DonationConfig> {
        self.donations.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DonationConfig {
    pub amount_sats: u64,
    pub lnurl: LnUrl,
}

pub fn migrate_to_postgres(db: &Db, conn: &mut PgConnection) -> anyhow::Result<()> {
    for result in db.iter() {
        let (key, value) = result?;

        let str = String::from_utf8(key.to_vec())?;
        // take first 64 chars
        let pubkey_str = str.chars().take(64).collect::<String>();
        let npub = XOnlyPublicKey::from_str(&pubkey_str)?;
        let emoji = str[65..].to_string();
        let config: UserConfig = serde_json::from_slice(&value)?;

        models::upsert_user(conn, &npub, emoji, config)?;
    }

    Ok(())
}
