use crate::db::UserConfig;
use crate::models::donation::{Donation, NewDonation};
use crate::models::user::NewUser;
use crate::models::zap_config::{NewZapConfig, ZapConfig};
use bitcoin::hashes::hex::ToHex;
use bitcoin::XOnlyPublicKey;
use diesel::prelude::*;
use diesel::result::Error;
use diesel::upsert::on_constraint;
use diesel::{PgConnection, QueryDsl, RunQueryDsl};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub mod donation;
pub mod schema;
pub mod user;
pub mod zap_config;
pub mod zap_event;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfigType {
    Zap,
    Subscription,
}

impl core::fmt::Display for ConfigType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigType::Zap => write!(f, "Zap"),
            ConfigType::Subscription => write!(f, "Subscription"),
        }
    }
}

impl FromStr for ConfigType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Zap" => Ok(ConfigType::Zap),
            "Subscription" => Ok(ConfigType::Subscription),
            _ => Err(anyhow::anyhow!("Invalid ConfigType")),
        }
    }
}

pub struct UserZapConfig {
    pub npub: XOnlyPublicKey,
    pub zap_config: ZapConfig,
    pub donations: Vec<Donation>,
}

pub fn upsert_user(
    conn: &mut PgConnection,
    npub: &XOnlyPublicKey,
    emoji: String,
    config: UserConfig,
) -> anyhow::Result<()> {
    conn.transaction::<_, Error, _>(|conn| {
        let user = NewUser {
            npub: &npub.to_hex(),
        };

        let user_id: i32 = diesel::insert_into(schema::users::table)
            .values(&user)
            .returning(schema::users::id)
            .on_conflict(schema::users::npub)
            .do_update()
            .set(&user)
            .get_result(conn)?;

        let zap_config = NewZapConfig {
            user_id,
            emoji: &emoji,
            amount: config.amount_sats as i32,
            nwc: &config.nwc().to_string(),
        };

        let config_id: i32 = diesel::insert_into(schema::zap_configs::table)
            .values(&zap_config)
            .returning(schema::zap_configs::id)
            .on_conflict(on_constraint("zap_configs_user_id_emoji_unique"))
            .do_update()
            .set(&zap_config)
            .get_result(conn)?;

        // delete current donations configs
        diesel::delete(schema::donations::table.filter(schema::donations::config_id.eq(config_id)))
            .execute(conn)?;

        // insert new donations configs
        let donate_configs = config.donations();
        if !donate_configs.is_empty() {
            let donations = donate_configs
                .into_iter()
                .map(|donate_config| NewDonation {
                    config_id,
                    lnurl: donate_config.lnurl.to_string(),
                    amount: donate_config.amount_sats as i32,
                })
                .collect::<Vec<_>>();

            diesel::insert_into(schema::donations::table)
                .values(&donations)
                .execute(conn)?;
        }

        Ok(())
    })?;

    Ok(())
}

pub fn get_user_zap_config(
    conn: &mut PgConnection,
    npub: XOnlyPublicKey,
    content: &str,
) -> anyhow::Result<Option<UserZapConfig>> {
    // todo could do one query here, currently in two

    conn.transaction(|conn| {
        let Some(zap_config) = ZapConfig::get_by_pubkey_and_emoji(conn, &npub, content) else {
            return Ok(None);
        };

        let donations = Donation::get_by_zap_config(conn, &zap_config)?;

        Ok(Some(UserZapConfig {
            npub,
            zap_config,
            donations,
        }))
    })
}

pub fn get_user_zap_configs(
    conn: &mut PgConnection,
    npub: XOnlyPublicKey,
) -> anyhow::Result<Vec<UserZapConfig>> {
    // todo could do one query here, currently in two

    conn.transaction(|conn| {
        let configs = ZapConfig::get_by_pubkey(conn, &npub)?;

        if configs.is_empty() {
            return Ok(vec![]);
        }

        let ids = configs.iter().map(|c| c.id).collect();
        let donations = Donation::get_by_zap_configs(conn, ids)?;

        let vec = donations
            .grouped_by(&configs)
            .into_iter()
            .zip(configs)
            .map(|(donations, zap_config)| UserZapConfig {
                npub,
                zap_config,
                donations,
            })
            .collect();

        Ok(vec)
    })
}

pub fn delete_user(conn: &mut PgConnection, npub: XOnlyPublicKey) -> anyhow::Result<()> {
    conn.transaction(|conn| {
        use schema::{donations, users, zap_configs};

        let zap_configs = ZapConfig::get_by_pubkey(conn, &npub)?;

        let zap_config_ids = zap_configs.iter().map(|c| c.id).collect::<Vec<_>>();

        diesel::delete(donations::table.filter(donations::config_id.eq_any(&zap_config_ids)))
            .execute(conn)?;

        diesel::delete(zap_configs::table.filter(zap_configs::id.eq_any(zap_config_ids)))
            .execute(conn)?;

        // todo delete subscriptions

        diesel::delete(users::table.filter(users::npub.eq(npub.to_hex()))).execute(conn)?;

        Ok(())
    })
}

pub fn delete_user_config(
    conn: &mut PgConnection,
    npub: XOnlyPublicKey,
    emoji: &str,
) -> anyhow::Result<()> {
    conn.transaction(|conn| {
        use schema::{donations, zap_configs};

        let Some(zap_config) = ZapConfig::get_by_pubkey_and_emoji(conn, &npub, emoji) else {
            return Ok(());
        };

        diesel::delete(donations::table.filter(donations::config_id.eq(zap_config.id)))
            .execute(conn)?;

        diesel::delete(zap_configs::table.filter(zap_configs::id.eq(zap_config.id)))
            .execute(conn)?;

        Ok(())
    })
}