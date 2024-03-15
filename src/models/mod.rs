use crate::models::donation::{Donation, NewDonation};
use crate::models::subscription_config::{NewSubscriptionConfig, SubscriptionConfig};
use crate::models::user::NewUser;
use crate::models::wallet_auth::WalletAuth;
use crate::models::zap_config::{NewZapConfig, ZapConfig};
use crate::routes::{CreateUserSubscription, SetUserConfig};
use diesel::prelude::*;
use diesel::result::Error;
use diesel::upsert::on_constraint;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use log::error;
use nostr::PublicKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub mod donation;
pub mod schema;
pub mod subscription_config;
pub mod user;
pub mod wallet_auth;
pub mod zap_config;
pub mod zap_event;
pub mod zap_event_to_subscription_config;
pub mod zap_event_to_zap_config;

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
    pub npub: PublicKey,
    pub zap_config: ZapConfig,
    pub donations: Vec<Donation>,
}

pub fn upsert_user(conn: &mut PgConnection, config: SetUserConfig) -> anyhow::Result<()> {
    conn.transaction::<_, Error, _>(|conn| {
        let auth_index = if let Some(pubkey) = config.auth_id {
            Some(WalletAuth::get_index_by_pubkey(conn, pubkey)?.ok_or(Error::NotFound)?)
        } else {
            None
        };

        let user = NewUser {
            npub: &config.npub.to_string(),
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
            emoji: &config.emoji(),
            amount: config.amount_sats as i32,
            nwc: config.nwc.map(|x| x.to_string()),
            auth_index,
        };

        match (zap_config.nwc.as_ref(), zap_config.auth_index.as_ref()) {
            (None, None) => {
                error!("zap_config.nwc and zap_config.auth_index are both None, this should never happen");
            },
            (Some(nwc), Some(auth_index)) => {
                error!("zap_config.nwc {nwc} and zap_config.auth_index {auth_index} are both Some, this should never happen");
            },
            _ => {} // expected
        }

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
        let donate_configs = config.donations.unwrap_or_default();
        if !donate_configs.is_empty() {
            let donations = donate_configs
                .into_iter()
                .map(|donate_config| NewDonation {
                    config_id,
                    lnurl: donate_config.lnurl,
                    amount: donate_config.amount_sats as i32,
                    npub: donate_config.npub.map(|x| x.to_string()),
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

pub fn upsert_subscription(
    conn: &mut PgConnection,
    config: CreateUserSubscription,
) -> anyhow::Result<()> {
    conn.transaction::<_, Error, _>(|conn| {
        let auth_index = if let Some(pubkey) = config.auth_id {
            Some(WalletAuth::get_index_by_pubkey(conn, pubkey)?.ok_or(Error::NotFound)?)
        } else {
            None
        };

        let user = NewUser {
            npub: &config.npub.to_string(),
        };

        let user_id: i32 = diesel::insert_into(schema::users::table)
            .values(&user)
            .returning(schema::users::id)
            .on_conflict(schema::users::npub)
            .do_update()
            .set(&user)
            .get_result(conn)?;

        let sub_config = NewSubscriptionConfig {
            user_id,
            to_npub: &config.to_npub.to_string(),
            amount: config.amount_sats as i32,
            time_period: &config.time_period.to_string(),
            nwc: config.nwc.map(|x| x.to_string()),
            auth_index,
            last_paid: None,
        };

        match (sub_config.nwc.as_ref(), sub_config.auth_index.as_ref()) {
            (None, None) => {
                error!("sub_config.nwc and sub_config.auth_index are both None, this should never happen");
            },
            (Some(nwc), Some(auth_index)) => {
                error!("sub_config.nwc {nwc} and sub_config.auth_index {auth_index} are both Some, this should never happen");
            },
            _ => {} // expected
        }

        diesel::insert_into(schema::subscription_configs::table)
            .values(&sub_config)
            .on_conflict(on_constraint("subscription_configs_user_id_to_npub_unique"))
            .do_update()
            .set(&sub_config)
            .execute(conn)?;

        Ok(())
    })?;

    Ok(())
}

pub fn get_user_zap_config(
    conn: &mut PgConnection,
    npub: PublicKey,
    content: &str,
) -> anyhow::Result<Option<UserZapConfig>> {
    // todo could do one query here, currently in two

    conn.transaction(|conn| {
        let Some(zap_config) = ZapConfig::get_by_pubkey_and_emoji(conn, &npub, content)? else {
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
    npub: PublicKey,
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

pub fn delete_user(conn: &mut PgConnection, npub: PublicKey) -> anyhow::Result<()> {
    conn.transaction(|conn| {
        use schema::{donations, subscription_configs, users, zap_configs};

        let user = users::table
            .filter(users::npub.eq(npub.to_string()))
            .first::<user::User>(conn)
            .optional()?;

        let Some(user) = user else {
            return Ok(());
        };

        let zap_configs = ZapConfig::get_by_pubkey(conn, &npub)?;

        let zap_config_ids = zap_configs.iter().map(|c| c.id).collect::<Vec<_>>();

        diesel::delete(donations::table.filter(donations::config_id.eq_any(&zap_config_ids)))
            .execute(conn)?;

        diesel::delete(zap_configs::table.filter(zap_configs::user_id.eq(user.id)))
            .execute(conn)?;

        diesel::delete(
            subscription_configs::table.filter(subscription_configs::user_id.eq(user.id)),
        )
        .execute(conn)?;

        diesel::delete(users::table.filter(users::npub.eq(npub.to_string()))).execute(conn)?;

        Ok(())
    })
}

pub fn delete_user_config(
    conn: &mut PgConnection,
    npub: PublicKey,
    emoji: &str,
) -> anyhow::Result<()> {
    conn.transaction(|conn| {
        use schema::{donations, zap_configs};

        let Some(zap_config) = ZapConfig::get_by_pubkey_and_emoji(conn, &npub, emoji)? else {
            return Ok(());
        };

        diesel::delete(donations::table.filter(donations::config_id.eq(zap_config.id)))
            .execute(conn)?;

        diesel::delete(zap_configs::table.filter(zap_configs::id.eq(zap_config.id)))
            .execute(conn)?;

        Ok(())
    })
}

pub fn delete_user_subscription(
    conn: &mut PgConnection,
    npub: PublicKey,
    to_npub: PublicKey,
) -> anyhow::Result<()> {
    conn.transaction(|conn| {
        use schema::subscription_configs;

        let Some(config) = SubscriptionConfig::get_by_pubkey_and_to_npub(conn, &npub, &to_npub)?
        else {
            return Ok(());
        };

        diesel::delete(subscription_configs::table.filter(subscription_configs::id.eq(config.id)))
            .execute(conn)?;

        Ok(())
    })
}

#[allow(dead_code)]
pub fn delete_subscribed_user(
    conn: &mut PgConnection,
    to_npub: PublicKey,
) -> anyhow::Result<usize> {
    conn.transaction(|conn| {
        use schema::subscription_configs;

        let configs = SubscriptionConfig::get_by_to_npub(conn, &to_npub)?;
        let ids = configs.iter().map(|c| c.id).collect::<Vec<_>>();

        let count = diesel::delete(
            subscription_configs::table.filter(subscription_configs::id.eq_any(ids)),
        )
        .execute(conn)?;

        Ok(count)
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::nip49::SubscriptionPeriod;
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::Network;
    use diesel_migrations::MigrationHarness;
    use nostr::prelude::NostrWalletConnectURI;
    use nostr::SECP256K1;

    const PUBKEY: &str = "e1ff3bfdd4e40315959b08b4fcc8245eaa514637e1d4ec2ae166b743341be1af";
    const PUBKEY2: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const NWC: &str = "nostr+walletconnect://246be70a7e4966f138e9e48401f33c32a1c428bbfb7aab42e3946beb8bc15e7c?relay=wss%3A%2F%2Fnostr.mutinywallet.com%2F&secret=23ea701003500d852ba2756460099217f839e1fbc9665e493b56bd2d5912e31b";

    fn init_db() -> PgConnection {
        dotenv::dotenv().ok();
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let mut conn = PgConnection::establish(&url).expect("Could not connect to database");

        conn.run_pending_migrations(MIGRATIONS)
            .expect("migrations could not run");

        clear_database(&mut conn);

        conn
    }

    fn clear_database(conn: &mut PgConnection) {
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            diesel::delete(schema::zap_events::table).execute(conn)?;
            diesel::delete(schema::donations::table).execute(conn)?;
            diesel::delete(schema::subscription_configs::table).execute(conn)?;
            diesel::delete(schema::zap_configs::table).execute(conn)?;
            diesel::delete(schema::users::table).execute(conn)?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn test_create_subscription() {
        let mut conn = init_db();

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();

        let config = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 100,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc.clone()),
            auth_id: None,
        };

        upsert_subscription(&mut conn, config).unwrap();

        let config = SubscriptionConfig::get_by_pubkey_and_to_npub(&mut conn, &npub, &to_npub)
            .unwrap()
            .unwrap();
        assert_eq!(config.amount, 100);
        assert_eq!(config.time_period(), SubscriptionPeriod::Day);
        assert_eq!(config.nwc(xpriv, None, None), nwc);

        clear_database(&mut conn)
    }

    #[test]
    fn test_create_subscription_nwa() {
        let mut conn = init_db();

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();

        // setup wallet auth
        let wallet_auth = WalletAuth::create(&mut conn, xpriv).unwrap();
        let auth_id = wallet_auth.pubkey();
        let user_data = WalletAuth::get_user_data(&mut conn, wallet_auth.index).unwrap();
        assert_eq!(user_data, None);
        let user_pubkey = PublicKey::from_slice(&[2; 32]).unwrap();
        WalletAuth::add_user_data(&mut conn, auth_id, user_pubkey, None).unwrap();

        let config = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 100,
            time_period: SubscriptionPeriod::Day,
            nwc: None,
            auth_id: Some(auth_id),
        };

        upsert_subscription(&mut conn, config).unwrap();

        let config = SubscriptionConfig::get_by_pubkey_and_to_npub(&mut conn, &npub, &to_npub)
            .unwrap()
            .unwrap();
        assert_eq!(config.amount, 100);
        assert_eq!(config.time_period(), SubscriptionPeriod::Day);
        let nwc = config.nwc(xpriv, Some(user_pubkey), None);
        assert_eq!(nwc.public_key, user_pubkey);
        assert_eq!(nwc.secret.x_only_public_key(&SECP256K1).0, *auth_id);

        clear_database(&mut conn)
    }

    #[test]
    fn test_create_subscription_overwrite_with_nwa() {
        let mut conn = init_db();

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();

        // create subscription with nwc
        let config = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 100,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc.clone()),
            auth_id: None,
        };
        upsert_subscription(&mut conn, config).unwrap();

        // setup wallet auth
        let wallet_auth = WalletAuth::create(&mut conn, xpriv).unwrap();
        let auth_id = wallet_auth.pubkey();
        let user_pubkey = PublicKey::from_slice(&[2; 32]).unwrap();
        let relay = "wss://nostr.mutinywallet.com/".to_string();
        WalletAuth::add_user_data(&mut conn, auth_id, user_pubkey, Some(relay.clone())).unwrap();

        // overwrite subscription with NWA
        let config = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 99,
            time_period: SubscriptionPeriod::Week,
            nwc: None,
            auth_id: Some(auth_id),
        };
        upsert_subscription(&mut conn, config).unwrap();

        let config = SubscriptionConfig::get_by_pubkey_and_to_npub(&mut conn, &npub, &to_npub)
            .unwrap()
            .unwrap();
        assert_eq!(config.amount, 99);
        assert_eq!(config.time_period(), SubscriptionPeriod::Week);
        let new_nwc = config.nwc(xpriv, Some(user_pubkey), Some(&relay));
        assert_eq!(new_nwc.public_key, user_pubkey);
        assert_eq!(new_nwc.secret.x_only_public_key(&SECP256K1).0, *auth_id);
        assert_eq!(new_nwc.relay_url.to_string(), relay);
        assert_ne!(new_nwc, nwc);

        clear_database(&mut conn)
    }
}
