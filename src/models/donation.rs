use super::schema::donations;
use crate::models::zap_config::ZapConfig;
use diesel::prelude::*;
use lnurl::lnurl::LnUrl;
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
    pub lnurl: String,
    pub amount: i32,
}

#[derive(Insertable, AsChangeset)]
#[diesel(table_name = donations)]
pub struct NewDonation {
    pub config_id: i32,
    pub lnurl: String,
    pub amount: i32,
}

impl Donation {
    pub fn new(config_id: i32, lnurl: &LnUrl, amount: i32) -> Self {
        Self {
            id: 0,
            config_id,
            lnurl: lnurl.to_string(),
            amount,
        }
    }

    pub fn lnurl(&self) -> LnUrl {
        LnUrl::from_str(&self.lnurl).expect("invalid lnurl")
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
