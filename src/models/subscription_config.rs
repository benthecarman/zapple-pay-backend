use crate::routes::{SubscriptionPeriod, ALL_SUBSCRIPTION_PERIODS};
use bitcoin::hashes::hex::ToHex;
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use nostr::prelude::NostrWalletConnectURI;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::schema::subscription_configs;
use super::schema::users;

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
pub struct SubscriptionConfig {
    pub id: i32,
    pub user_id: i32,
    pub to_npub: String,
    pub amount: i32,
    time_period: String,
    nwc: String,
    created_at: chrono::NaiveDateTime,
    pub last_paid: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = subscription_configs)]
pub struct NewSubscriptionConfig<'a> {
    pub user_id: i32,
    pub to_npub: &'a str,
    pub amount: i32,
    pub time_period: &'a str,
    pub nwc: &'a str,
    pub last_paid: Option<chrono::NaiveDateTime>,
}

impl SubscriptionConfig {
    pub fn to_npub(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_str(&self.to_npub).expect("invalid to_npub")
    }

    pub fn time_period(&self) -> SubscriptionPeriod {
        SubscriptionPeriod::from_str(&self.time_period).expect("invalid time period")
    }

    pub fn nwc(&self) -> NostrWalletConnectURI {
        NostrWalletConnectURI::from_str(&self.nwc).expect("invalid nwc")
    }

    pub fn amount_msats(&self) -> u64 {
        (self.amount * 1_000) as u64
    }

    pub fn needs_payment(&self) -> bool {
        match self.last_paid {
            None => true,
            Some(last_paid) => {
                let period_start = self.time_period().period_start();
                last_paid < period_start
            }
        }
    }

    pub fn get_config_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = subscription_configs::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn get_by_pubkey(
        conn: &mut PgConnection,
        pubkey: &XOnlyPublicKey,
    ) -> anyhow::Result<Vec<Self>> {
        let configs = subscription_configs::table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_hex()))
            .select(subscription_configs::all_columns)
            .load::<Self>(conn)?;

        Ok(configs)
    }

    pub fn get_by_pubkey_and_to_npub(
        conn: &mut PgConnection,
        pubkey: &XOnlyPublicKey,
        to_npub: &XOnlyPublicKey,
    ) -> anyhow::Result<Option<Self>> {
        Ok(subscription_configs::table
            .filter(subscription_configs::to_npub.eq(to_npub.to_hex()))
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_hex()))
            .select(subscription_configs::all_columns)
            .first::<Self>(conn)
            .optional()?)
    }

    pub fn get_needs_payment(conn: &mut PgConnection) -> anyhow::Result<Vec<Self>> {
        conn.transaction(|conn| {
            // get never never paid configs
            let mut configs = subscription_configs::table
                .filter(subscription_configs::last_paid.is_null())
                .load::<Self>(conn)?;

            for period in ALL_SUBSCRIPTION_PERIODS {
                let new_configs = subscription_configs::table
                    .filter(subscription_configs::time_period.eq(period.to_string()))
                    .filter(subscription_configs::last_paid.lt(period.period_start()))
                    .load::<Self>(conn)?;

                configs.extend(new_configs);
            }

            // double check that we don't have any configs that don't need payment
            configs.retain(|config| config.needs_payment());

            Ok(configs)
        })
    }
}