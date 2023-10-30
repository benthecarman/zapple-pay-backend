use crate::models::schema::zap_configs::dsl;
use crate::DEFAULT_AUTH_RELAY;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use nostr::prelude::NostrWalletConnectURI;
use nostr::secp256k1::SecretKey;
use nostr::{Url, SECP256K1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use super::schema::users;
use super::schema::zap_configs;

#[derive(
    Associations,
    Queryable,
    Insertable,
    Identifiable,
    AsChangeset,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
)]
#[diesel(primary_key(id))]
#[diesel(belongs_to(crate::models::user::User, foreign_key = user_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ZapConfig {
    pub id: i32,
    pub user_id: i32,
    pub emoji: String,
    pub amount: i32,
    nwc: Option<String>,
    created_at: chrono::NaiveDateTime,
    pub auth_index: Option<i32>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = zap_configs)]
pub struct NewZapConfig<'a> {
    pub user_id: i32,
    pub emoji: &'a str,
    pub amount: i32,
    pub nwc: Option<String>,
    pub auth_index: Option<i32>,
}

impl ZapConfig {
    pub fn nwc(
        &self,
        xpriv: ExtendedPrivKey,
        user_public_key: Option<XOnlyPublicKey>,
    ) -> NostrWalletConnectURI {
        match (self.nwc.as_deref(), self.auth_index) {
            (Some(str), None) => NostrWalletConnectURI::from_str(str).unwrap(),
            (None, Some(index)) => {
                let secret = xpriv
                    .derive_priv(
                        SECP256K1,
                        &[ChildNumber::from_hardened_idx(index as u32).unwrap()],
                    )
                    .unwrap()
                    .private_key;

                NostrWalletConnectURI::new(
                    user_public_key.expect("Missing user public key from database"),
                    Url::parse(DEFAULT_AUTH_RELAY).unwrap(),
                    Some(secret),
                    None,
                )
                .unwrap()
            }
            _ => panic!("Invalid ZapConfig"),
        }
    }

    pub fn amount_msats(&self) -> u64 {
        (self.amount * 1_000) as u64
    }

    pub fn get_config_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = zap_configs::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn get_nwc_secrets(conn: &mut PgConnection) -> anyhow::Result<Vec<SecretKey>> {
        let strings: Vec<Option<String>> = zap_configs::table
            .select(zap_configs::nwc)
            .filter(zap_configs::nwc.is_not_null())
            .distinct()
            .load(conn)?;
        let mut secrets: Vec<SecretKey> = strings
            .into_iter()
            .flatten()
            .filter_map(|s| NostrWalletConnectURI::from_str(&s).ok())
            .map(|nwc| nwc.secret)
            .collect();

        secrets.sort();
        secrets.dedup();

        Ok(secrets)
    }

    pub fn get_nwc_relays(conn: &mut PgConnection) -> anyhow::Result<HashMap<Url, usize>> {
        let strings: Vec<Option<String>> = zap_configs::table
            .select(zap_configs::nwc)
            .filter(zap_configs::nwc.is_not_null())
            .distinct()
            .load(conn)?;
        let relays: Vec<Url> = strings
            .into_iter()
            .flatten()
            .filter_map(|s| NostrWalletConnectURI::from_str(&s).ok())
            .map(|nwc| nwc.relay_url)
            .collect();

        // count the relays
        let mut counts = HashMap::new();
        for relay in relays {
            counts.entry(relay).and_modify(|c| *c += 1).or_insert(1);
        }

        Ok(counts)
    }

    pub fn get_by_pubkey(
        conn: &mut PgConnection,
        pubkey: &XOnlyPublicKey,
    ) -> anyhow::Result<Vec<Self>> {
        let configs = zap_configs::table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_hex()))
            .select(dsl::zap_configs::all_columns())
            .load::<Self>(conn)?;

        Ok(configs)
    }

    pub fn get_by_pubkey_and_emoji(
        conn: &mut PgConnection,
        pubkey: &XOnlyPublicKey,
        emoji: &str,
    ) -> anyhow::Result<Option<Self>> {
        // handle different emoji representations
        let table = match emoji {
            "⚡️" => zap_configs::table
                .filter(zap_configs::emoji.eq(emoji))
                .or_filter(zap_configs::emoji.eq("⚡")),
            "⚡" => zap_configs::table
                .filter(zap_configs::emoji.eq(emoji))
                .or_filter(zap_configs::emoji.eq("⚡️")),
            _ => zap_configs::table
                .filter(zap_configs::emoji.eq(emoji))
                .or_filter(zap_configs::emoji.eq(emoji)),
        };

        Ok(table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_hex()))
            .select(dsl::zap_configs::all_columns())
            .first::<Self>(conn)
            .optional()?)
    }

    pub fn delete_by_id(conn: &mut PgConnection, id: i32) -> anyhow::Result<usize> {
        let count =
            diesel::delete(zap_configs::table.filter(zap_configs::id.eq(id))).execute(conn)?;
        Ok(count)
    }
}
