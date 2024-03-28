use crate::models::schema::zap_events::dsl;
use crate::models::ConfigType;
use chrono::NaiveDateTime;
use diesel::dsl::sum;
use diesel::prelude::*;
use nostr::key::PublicKey;
use nostr::prelude::SecretKey;
use nostr::{EventId, Timestamp};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::schema::zap_events_to_subscription_configs;
use super::schema::{zap_events, zap_events_to_zap_configs};

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
    pub created_at: NaiveDateTime,
    secret_key: String,
    pub payment_hash: String,
    event_id: String,
    pub paid_at: Option<NaiveDateTime>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = zap_events)]
pub struct NewZapEvent<'a> {
    pub from_npub: &'a str,
    pub to_npub: &'a str,
    pub config_type: &'a str,
    pub amount: i32,
    pub secret_key: &'a str,
    pub payment_hash: &'a str,
    pub event_id: &'a str,
}

impl ZapEvent {
    #[allow(clippy::wrong_self_convention)]
    pub fn from_npub(&self) -> PublicKey {
        PublicKey::from_str(&self.from_npub).expect("Invalid PublicKey")
    }

    pub fn to_npub(&self) -> PublicKey {
        PublicKey::from_str(&self.to_npub).expect("Invalid PublicKey")
    }

    pub fn config_type(&self) -> ConfigType {
        ConfigType::from_str(&self.config_type).expect("Invalid ConfigType")
    }

    pub fn secret_key(&self) -> SecretKey {
        SecretKey::from_str(&self.secret_key).expect("Invalid SecretKey")
    }

    pub fn event_id(&self) -> EventId {
        EventId::from_str(&self.event_id).expect("Invalid EventId")
    }

    pub fn get_zap_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = zap_events::table
            .filter(zap_events::paid_at.is_not_null())
            .count()
            .get_result(conn)?;
        Ok(count)
    }

    pub fn get_unconfirmed_zap_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = zap_events::table
            .filter(zap_events::paid_at.is_null())
            .count()
            .get_result(conn)?;
        Ok(count)
    }

    pub fn get_zap_total(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let total: Option<i64> = zap_events::table
            .filter(zap_events::paid_at.is_not_null())
            .select(sum(zap_events::amount))
            .get_result(conn)?;

        Ok(total.unwrap_or_default())
    }

    pub fn create_zap_event(
        conn: &mut PgConnection,
        from_npub: &PublicKey,
        to_npub: &PublicKey,
        config_type: ConfigType,
        amount: i32,
        secret_key: SecretKey,
        payment_hash: [u8; 32],
        event_id: EventId,
    ) -> anyhow::Result<ZapEvent> {
        let from_npub_str = from_npub.to_string();
        let to_npub_str = to_npub.to_string();
        let secret_key = hex::encode(secret_key.secret_bytes());
        let payment_hash = hex::encode(payment_hash);
        let new_zap_event = NewZapEvent {
            from_npub: &from_npub_str,
            to_npub: &to_npub_str,
            config_type: &config_type.to_string(),
            amount,
            secret_key: secret_key.as_str(),
            payment_hash: payment_hash.as_str(),
            event_id: &event_id.to_hex(),
        };
        let zap_event = diesel::insert_into(zap_events::table)
            .values(&new_zap_event)
            .get_result(conn)?;
        Ok(zap_event)
    }

    pub fn find_by_event_id(
        conn: &mut PgConnection,
        event_id: EventId,
    ) -> anyhow::Result<Option<ZapEvent>> {
        let zap_event = zap_events::table
            .filter(zap_events::event_id.eq(event_id.to_hex()))
            .first::<ZapEvent>(conn)
            .optional()?;
        Ok(zap_event)
    }

    pub fn delete_by_event_id(
        conn: &mut PgConnection,
        event_id: EventId,
    ) -> anyhow::Result<Option<ZapEvent>> {
        let zap_event =
            diesel::delete(zap_events::table.filter(zap_events::event_id.eq(event_id.to_hex())))
                .get_result(conn)
                .optional()?;
        Ok(zap_event)
    }

    pub fn mark_zap_paid(
        conn: &mut PgConnection,
        event_id: EventId,
        timestamp: Timestamp,
    ) -> anyhow::Result<ZapEvent> {
        let time =
            NaiveDateTime::from_timestamp_opt(timestamp.as_i64(), 0).expect("Invalid timestamp");
        let zap_event = diesel::update(zap_events::table)
            .filter(zap_events::event_id.eq(event_id.to_hex()))
            .set(zap_events::paid_at.eq(time))
            .get_result(conn)?;
        Ok(zap_event)
    }

    pub fn get_unpaid_zaps(
        conn: &mut PgConnection,
        cfg_type: ConfigType,
    ) -> anyhow::Result<Vec<ZapEvent>> {
        let zaps = zap_events::table
            .filter(zap_events::paid_at.is_null())
            .filter(zap_events::config_type.eq(cfg_type.to_string()))
            .load::<ZapEvent>(conn)?;
        Ok(zaps)
    }

    pub fn find_newest_zap_event_for_subscription(
        conn: &mut PgConnection,
        config_id: i32,
        best_time: NaiveDateTime,
    ) -> anyhow::Result<Option<ZapEvent>> {
        let zap_events = zap_events::table
            .filter(zap_events::paid_at.is_not_null())
            .filter(zap_events::created_at.gt(best_time));

        let zap_event = zap_events
            .inner_join(zap_events_to_subscription_configs::table)
            .filter(zap_events_to_subscription_configs::subscription_config_id.eq(config_id))
            .select(dsl::zap_events::all_columns())
            .first(conn)
            .optional()?;

        Ok(zap_event)
    }

    pub fn find_newest_zap_event_for_zap_config(
        conn: &mut PgConnection,
        config_id: i32,
        best_time: NaiveDateTime,
    ) -> anyhow::Result<Option<ZapEvent>> {
        let zap_events = zap_events::table
            .filter(zap_events::paid_at.is_not_null())
            .filter(zap_events::created_at.gt(best_time));

        let zap_event = zap_events
            .inner_join(zap_events_to_zap_configs::table)
            .filter(zap_events_to_zap_configs::zap_config_id.eq(config_id))
            .select(dsl::zap_events::all_columns())
            .first(conn)
            .optional()?;

        Ok(zap_event)
    }
}
