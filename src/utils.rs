use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::hashes::{sha256, Hash};
use lazy_static::lazy_static;
use nostr::PublicKey;
use regex::Regex;

lazy_static! {
    static ref LN_REG: Regex =
        Regex::new(r"^\u{26A1}[\u{FE00}-\u{FE0F}]?$").expect("Invalid regex");
}

pub fn map_emoji(emoji: &str) -> Option<&str> {
    match emoji {
        "❤" | "+" | "" => Some("❤️"),
        "⚡️" => Some("⚡"),
        str => {
            if LN_REG.is_match(str) {
                Some("⚡")
            } else {
                None
            }
        }
    }
}

/// Calculate the NWA secret from the xpriv and the public key
pub(crate) fn calculate_nwa_secret(xpriv: ExtendedPrivKey, public_key: PublicKey) -> String {
    let mut bytes = xpriv.private_key.secret_bytes().to_vec();
    bytes.extend_from_slice(&public_key.serialize());

    let hash = sha256::Hash::hash(&bytes);

    let mut str = hash.to_string();
    // Truncate to 16 characters, we don't need the full hash
    // and it keeps the QR code smaller
    str.truncate(16);
    str
}
