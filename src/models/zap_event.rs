use crate::models::ConfigType;
use bitcoin::hashes::hex::ToHex;
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::schema::zap_events;

#[derive(
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
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ZapEvent {
    pub id: i32,
    from_npub: String,
    to_npub: String,
    config_type: String,
    amount: i32,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = zap_events)]
pub struct NewZapEvent<'a> {
    pub from_npub: &'a str,
    pub to_npub: &'a str,
    pub config_type: &'a str,
    pub amount: i32,
}

impl ZapEvent {
    #[allow(clippy::wrong_self_convention)]
    pub fn from_npub(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(&self.from_npub).expect("Invalid XOnlyPublicKey")
    }

    pub fn to_npub(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(&self.to_npub).expect("Invalid XOnlyPublicKey")
    }

    pub fn get_zap_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = zap_events::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn create_zap_event(
        conn: &mut PgConnection,
        from_npub: &XOnlyPublicKey,
        to_npub: &XOnlyPublicKey,
        config_type: ConfigType,
        amount: i32,
    ) -> anyhow::Result<ZapEvent> {
        let from_npub_str = from_npub.to_hex();
        let to_npub_str = to_npub.to_hex();
        let new_zap_event = NewZapEvent {
            from_npub: &from_npub_str,
            to_npub: &to_npub_str,
            config_type: &config_type.to_string(),
            amount,
        };
        let zap_event = diesel::insert_into(zap_events::table)
            .values(&new_zap_event)
            .get_result(conn)?;
        Ok(zap_event)
    }
}
