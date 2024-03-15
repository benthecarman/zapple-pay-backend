use super::schema::donations;
use crate::models::zap_config::ZapConfig;
use diesel::prelude::*;
use lnurl::lnurl::LnUrl;
use nostr::key::PublicKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
    Eq,
)]
#[diesel(primary_key(id))]
#[diesel(belongs_to(ZapConfig, foreign_key = config_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Donation {
    pub id: i32,
    pub config_id: i32,
    pub lnurl: Option<String>,
    pub amount: i32,
    pub npub: Option<String>,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = donations)]
pub struct NewDonation {
    pub config_id: i32,
    pub lnurl: Option<String>,
    pub amount: i32,
    pub npub: Option<String>,
}

impl Donation {
    pub fn new(
        config_id: i32,
        lnurl: Option<&LnUrl>,
        npub: Option<PublicKey>,
        amount: i32,
    ) -> Self {
        Self {
            id: 0,
            config_id,
            lnurl: lnurl.map(|l| l.to_string()),
            amount,
            npub: npub.map(|n| n.to_string()),
        }
    }

    pub fn lnurl(&self) -> Option<LnUrl> {
        self.lnurl
            .as_ref()
            .map(|l| LnUrl::from_str(l).expect("invalid lnurl"))
    }

    pub fn npub(&self) -> Option<PublicKey> {
        self.npub
            .as_ref()
            .map(|l| PublicKey::from_str(l).expect("invalid npub"))
    }

    pub fn amount_msats(&self) -> u64 {
        (self.amount * 1_000) as u64
    }

    pub fn get_by_zap_config(
        conn: &mut PgConnection,
        zap_config: &ZapConfig,
    ) -> anyhow::Result<Vec<Self>> {
        let res = donations::table
            .filter(donations::config_id.eq(zap_config.id))
            .load::<Self>(conn)?;

        Ok(res)
    }

    pub fn get_by_zap_configs(conn: &mut PgConnection, ids: Vec<i32>) -> anyhow::Result<Vec<Self>> {
        let res = donations::table
            .filter(donations::config_id.eq_any(ids))
            .load::<Self>(conn)?;

        Ok(res)
    }
}
