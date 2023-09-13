use lnurl::lnurl::LnUrl;
use nostr::nips::nip47::NostrWalletConnectURI;
use serde::{Deserialize, Serialize};
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
