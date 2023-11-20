use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::XOnlyPublicKey;

pub fn map_emoji(emoji: &str) -> Option<&str> {
    match emoji {
        "❤" | "+" | "" => Some("❤️"),
        "⚡️" => Some("⚡"),
        _ => None,
    }
}

/// Calculate the NWA secret from the xpriv and the public key
pub(crate) fn calculate_nwa_secret(xpriv: ExtendedPrivKey, public_key: XOnlyPublicKey) -> String {
    let mut bytes = xpriv.private_key.secret_bytes().to_vec();
    bytes.extend_from_slice(&public_key.serialize());

    let hash = sha256::Hash::hash(&bytes);

    let mut str = hash.to_hex();
    // Truncate to 16 characters, we don't need the full hash
    // and it keeps the QR code smaller
    str.truncate(16);
    str
}
