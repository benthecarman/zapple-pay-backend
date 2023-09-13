use crate::models::schema::zap_configs::dsl;
use bitcoin::hashes::hex::ToHex;
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use nostr::prelude::NostrWalletConnectURI;
use serde::{Deserialize, Serialize};
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
    nwc: String,
    created_at: chrono::NaiveDateTime,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = zap_configs)]
pub struct NewZapConfig<'a> {
    pub user_id: i32,
    pub emoji: &'a str,
    pub amount: i32,
    pub nwc: &'a str,
}

impl ZapConfig {
    pub fn nwc(&self) -> NostrWalletConnectURI {
        NostrWalletConnectURI::from_str(&self.nwc).expect("invalid nwc")
    }

    pub fn amount_msats(&self) -> u64 {
        (self.amount * 1_000) as u64
    }

    pub fn get_config_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = zap_configs::table.count().get_result(conn)?;
        Ok(count)
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
    ) -> Option<Self> {
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

        table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_hex()))
            .select(dsl::zap_configs::all_columns())
            .first::<Self>(conn)
            .ok()
    }
}
