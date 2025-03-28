use crate::nip49::{SubscriptionPeriod, ALL_SUBSCRIPTION_PERIODS};
use crate::DEFAULT_AUTH_RELAY;
use bitcoin::bip32::{ChildNumber, ExtendedPrivKey};
use diesel::prelude::*;
use nostr::key::PublicKey;
use nostr::prelude::{NostrWalletConnectURI, SecretKey};
use nostr::{Url, SECP256K1};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    nwc: Option<String>,
    created_at: chrono::NaiveDateTime,
    pub last_paid: Option<chrono::NaiveDateTime>,
    pub auth_index: Option<i32>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = subscription_configs)]
#[diesel(treat_none_as_null = true)]
pub struct NewSubscriptionConfig<'a> {
    pub user_id: i32,
    pub to_npub: &'a str,
    pub amount: i32,
    pub time_period: &'a str,
    pub nwc: Option<String>,
    pub last_paid: Option<chrono::NaiveDateTime>,
    pub auth_index: Option<i32>,
}

impl SubscriptionConfig {
    pub fn to_npub(&self) -> PublicKey {
        PublicKey::from_str(&self.to_npub).expect("invalid to_npub")
    }

    pub fn time_period(&self) -> SubscriptionPeriod {
        SubscriptionPeriod::from_str(&self.time_period).expect("invalid time period")
    }

    pub fn nwc(
        &self,
        xpriv: ExtendedPrivKey,
        user_public_key: Option<PublicKey>,
        relay: Option<&str>,
    ) -> NostrWalletConnectURI {
        match (self.nwc.as_deref(), self.auth_index) {
            (Some(str), None) => NostrWalletConnectURI::from_str(str).unwrap(),
            (None, Some(index)) => {
                let secret = xpriv
                    .derive_priv(
                        &SECP256K1,
                        &[ChildNumber::from_hardened_idx(index as u32).unwrap()],
                    )
                    .unwrap()
                    .private_key;

                NostrWalletConnectURI::new(
                    user_public_key.expect("Missing user public key from database"),
                    Url::parse(relay.unwrap_or(DEFAULT_AUTH_RELAY)).unwrap(),
                    secret.into(),
                    None,
                )
            }
            _ => panic!("Invalid SubscriptionConfig"),
        }
    }

    pub fn relay_url(&self) -> Url {
        let url = self
            .nwc
            .as_deref()
            .map(|s| NostrWalletConnectURI::from_str(s).unwrap().relay_url)
            .unwrap_or(Url::from_str(DEFAULT_AUTH_RELAY).expect("invalid relay url"));

        if url == Url::from_str("ws://alby-mainnet-nostr-relay/v1").unwrap() {
            Url::from_str("wss://relay.getalby.com/v1").unwrap()
        } else {
            url
        }
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

    pub fn needs_prune(&self) -> bool {
        match self.last_paid {
            None => false,
            Some(last_paid) => last_paid < self.time_period().five_periods_ago(),
        }
    }

    pub fn get_config_count(conn: &mut PgConnection) -> anyhow::Result<i64> {
        let count = subscription_configs::table.count().get_result(conn)?;
        Ok(count)
    }

    pub fn get_nwc_secrets(conn: &mut PgConnection) -> anyhow::Result<Vec<SecretKey>> {
        let strings: Vec<Option<String>> = subscription_configs::table
            .select(subscription_configs::nwc)
            .filter(subscription_configs::nwc.is_not_null())
            .distinct()
            .load(conn)?;
        let secrets = strings
            .into_iter()
            .flatten()
            .filter_map(|s| NostrWalletConnectURI::from_str(&s).ok())
            .map(|nwc| nwc.secret)
            .collect();
        Ok(secrets)
    }

    pub fn get_by_pubkey(conn: &mut PgConnection, pubkey: &PublicKey) -> anyhow::Result<Vec<Self>> {
        let configs = subscription_configs::table
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_string()))
            .select(subscription_configs::all_columns)
            .load::<Self>(conn)?;

        Ok(configs)
    }

    pub fn get_by_to_npub(
        conn: &mut PgConnection,
        to_npub: &PublicKey,
    ) -> anyhow::Result<Vec<Self>> {
        let configs = subscription_configs::table
            .filter(subscription_configs::to_npub.eq(to_npub.to_string()))
            .select(subscription_configs::all_columns)
            .load::<Self>(conn)?;

        Ok(configs)
    }

    pub fn get_by_pubkey_and_to_npub(
        conn: &mut PgConnection,
        pubkey: &PublicKey,
        to_npub: &PublicKey,
    ) -> anyhow::Result<Option<Self>> {
        Ok(subscription_configs::table
            .filter(subscription_configs::to_npub.eq(to_npub.to_string()))
            .inner_join(users::table)
            .filter(users::npub.eq(pubkey.to_string()))
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

            // make sure there is no duplicates
            configs.sort_by_key(|config| config.id);
            configs.dedup();

            Ok(configs)
        })
    }

    pub fn get_to_npubs(conn: &mut PgConnection) -> anyhow::Result<Vec<PublicKey>> {
        let strings = subscription_configs::table
            .select(subscription_configs::to_npub)
            .load::<String>(conn)?;

        Ok(strings
            .into_iter()
            .filter_map(|s| PublicKey::from_str(&s).ok())
            .collect())
    }

    pub fn get_nwc_relays(conn: &mut PgConnection) -> anyhow::Result<HashMap<Url, usize>> {
        let strings: Vec<Option<String>> = subscription_configs::table
            .select(subscription_configs::nwc)
            .filter(subscription_configs::nwc.is_not_null())
            .distinct()
            .load(conn)?;
        let relays: Vec<Url> = strings
            .into_iter()
            .flatten()
            .filter_map(|s| NostrWalletConnectURI::from_str(&s).ok())
            .map(|nwc| nwc.relay_url)
            .filter(|u| !u.to_string().contains("mutinywallet")) // these are dead/old
            .collect();

        // count the relays
        let mut counts = HashMap::with_capacity(relays.len());
        for relay in relays {
            counts.entry(relay).and_modify(|c| *c += 1).or_insert(1);
        }

        Ok(counts)
    }

    pub fn delete_by_id(conn: &mut PgConnection, id: i32) -> anyhow::Result<()> {
        diesel::delete(subscription_configs::table.filter(subscription_configs::id.eq(id)))
            .execute(conn)?;
        Ok(())
    }

    pub fn prune_unpaid(conn: &mut PgConnection) -> anyhow::Result<usize> {
        conn.transaction(|conn| {
            let unpaid_configs = SubscriptionConfig::get_needs_payment(conn)?;
            let unpaid_configs = unpaid_configs
                .into_iter()
                .filter(|config| config.needs_prune())
                .map(|config| config.id)
                .collect::<Vec<_>>();

            Ok(diesel::delete(
                subscription_configs::table
                    .filter(subscription_configs::id.eq_any(&unpaid_configs)),
            )
            .execute(conn)?)
        })
    }
}
