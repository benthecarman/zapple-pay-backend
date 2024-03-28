use crate::models::donation::{Donation, NewDonation};
use crate::models::subscription_config::{NewSubscriptionConfig, SubscriptionConfig};
use crate::models::user::NewUser;
use crate::models::wallet_auth::WalletAuth;
use crate::models::zap_config::{NewZapConfig, ZapConfig};
use crate::models::zap_event::ZapEvent;
use crate::models::zap_event_to_subscription_config::ZapEventToSubscriptionConfig;
use crate::models::zap_event_to_zap_config::ZapEventToZapConfig;
use crate::routes::{CreateUserSubscription, SetUserConfig};
use diesel::prelude::*;
use diesel::result::Error;
use diesel::upsert::on_constraint;
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use log::{error, info};
use nostr::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

pub fn do_prunes(conn: &mut PgConnection) -> anyhow::Result<usize> {
    let mut num = SubscriptionConfig::prune_unpaid(conn)?;
    num += prune_dead_subscriptions(conn)?;
    num += prune_dead_zap_configs(conn)?;

    Ok(num)
}

pub(crate) fn prune_dead_zap_configs(conn: &mut PgConnection) -> anyhow::Result<usize> {
    conn.transaction(|conn| {
        let unpaid_zaps = ZapEvent::get_unpaid_zaps(conn, ConfigType::Zap)?;
        let links = ZapEventToZapConfig::find_by_zap_event_ids(
            conn,
            unpaid_zaps.iter().map(|zap| zap.id).collect(),
        )?;
        // group by zap config id
        let grouped: HashMap<i32, Vec<i32>> =
            links.into_iter().fold(HashMap::new(), |mut acc, link| {
                acc.entry(link.zap_config_id)
                    .or_default()
                    .push(link.zap_event_id);
                acc
            });

        let mut dead_configs: Vec<i32> = Vec::with_capacity(grouped.len());
        for (config_id, zap_ids) in grouped {
            if zap_ids.len() >= 100 {
                // try to newer successful zap
                let best_zap = unpaid_zaps
                    .iter()
                    .find(|zap| zap_ids.contains(&zap.id))
                    .unwrap();
                let best_time = best_zap.created_at;
                // join with ZapEventToZapConfig to find event with higher best time, paid_at and same config_id
                let opt =
                    ZapEvent::find_newest_zap_event_for_zap_config(conn, config_id, best_time)?;
                match opt {
                    Some(zap) => {
                        info!(
                            "Found a newer zap event at {:?}, not deleting!",
                            zap.paid_at
                        );
                        // delete zap events so we don't try to pay them again
                        diesel::delete(
                            schema::zap_events::table
                                .filter(schema::zap_events::id.eq_any(&zap_ids)),
                        )
                        .execute(conn)?;
                    }
                    None => {
                        // mark for deletion
                        dead_configs.push(config_id);
                        // delete zap events
                        diesel::delete(
                            schema::zap_events::table
                                .filter(schema::zap_events::id.eq_any(&zap_ids)),
                        )
                        .execute(conn)?;
                        // delete links
                        diesel::delete(schema::zap_events_to_zap_configs::table.filter(
                            schema::zap_events_to_zap_configs::zap_event_id.eq_any(zap_ids),
                        ))
                        .execute(conn)?;
                    }
                }
            }
        }

        // delete donation configs
        diesel::delete(
            schema::donations::table.filter(schema::donations::config_id.eq_any(&dead_configs)),
        )
        .execute(conn)?;

        // delete zap configs
        let num = diesel::delete(
            schema::zap_configs::table.filter(schema::zap_configs::id.eq_any(&dead_configs)),
        )
        .execute(conn)?;

        Ok(num)
    })
}

pub(crate) fn prune_dead_subscriptions(conn: &mut PgConnection) -> anyhow::Result<usize> {
    conn.transaction(|conn| {
        let unpaid_zaps = ZapEvent::get_unpaid_zaps(conn, ConfigType::Subscription)?;
        let links = ZapEventToSubscriptionConfig::find_by_zap_event_ids(
            conn,
            unpaid_zaps.iter().map(|zap| zap.id).collect(),
        )?;
        // group by subscription config id
        let grouped: HashMap<i32, Vec<i32>> =
            links.into_iter().fold(HashMap::new(), |mut acc, link| {
                acc.entry(link.subscription_config_id)
                    .or_default()
                    .push(link.zap_event_id);
                acc
            });

        let mut dead_configs: Vec<i32> = Vec::with_capacity(grouped.len());
        for (config_id, zap_ids) in grouped {
            if zap_ids.len() >= 5 {
                // try to newer successful zap
                let best_zap = unpaid_zaps
                    .iter()
                    .find(|zap| zap_ids.contains(&zap.id))
                    .unwrap();
                let best_time = best_zap.created_at;
                // join with ZapEventToSubscriptionConfig to find event with higher best time, paid_at and same config_id
                let opt =
                    ZapEvent::find_newest_zap_event_for_subscription(conn, config_id, best_time)?;
                match opt {
                    Some(zap) => {
                        info!(
                            "Found a newer zap event at {:?}, not deleting!",
                            zap.paid_at
                        );
                        // delete zap events so we don't try to pay them again
                        diesel::delete(
                            schema::zap_events::table
                                .filter(schema::zap_events::id.eq_any(&zap_ids)),
                        )
                        .execute(conn)?;
                    }
                    None => {
                        // mark for deletion
                        dead_configs.push(config_id);
                        // delete zap events
                        diesel::delete(
                            schema::zap_events::table
                                .filter(schema::zap_events::id.eq_any(&zap_ids)),
                        )
                        .execute(conn)?;
                        // delete links
                        diesel::delete(
                            schema::zap_events_to_subscription_configs::table.filter(
                                schema::zap_events_to_subscription_configs::zap_event_id
                                    .eq_any(zap_ids),
                            ),
                        )
                        .execute(conn)?;
                    }
                }
            }
        }

        // delete subscription configs
        let num = diesel::delete(
            schema::subscription_configs::table
                .filter(schema::subscription_configs::id.eq_any(&dead_configs)),
        )
        .execute(conn)?;

        Ok(num)
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
    use crate::routes::DonationConfig;
    use bitcoin::bip32::ExtendedPrivKey;
    use bitcoin::Network;
    use chrono::{NaiveDateTime, Utc};
    use diesel_migrations::MigrationHarness;
    use nostr::prelude::NostrWalletConnectURI;
    use nostr::{EventId, Timestamp, SECP256K1};

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

    fn do_test_clear_dead_subscriptions(expect_prune: bool) {
        let mut conn = init_db();

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();

        // create a subscription
        let config = CreateUserSubscription {
            npub,
            to_npub,
            amount_sats: 100,
            time_period: SubscriptionPeriod::Day,
            nwc: Some(nwc),
            auth_id: None,
        };
        upsert_subscription(&mut conn, config).unwrap();

        let config = SubscriptionConfig::get_by_pubkey_and_to_npub(&mut conn, &npub, &to_npub)
            .unwrap()
            .unwrap();

        let zap_event = ZapEvent::create_zap_event(
            &mut conn,
            &npub,
            &to_npub,
            ConfigType::Subscription,
            100,
            xpriv.private_key.into(),
            [0; 32],
            EventId::from_slice(&[0xff; 32]).unwrap(),
        )
        .unwrap();
        ZapEventToSubscriptionConfig::new(&mut conn, zap_event.id, config.id).unwrap();

        // should not delete subscription
        let num = prune_dead_subscriptions(&mut conn).unwrap();
        assert_eq!(num, 0);

        // make a bunch of unpaid zaps
        for i in 0..10 {
            let zap_event = ZapEvent::create_zap_event(
                &mut conn,
                &npub,
                &to_npub,
                ConfigType::Subscription,
                100,
                xpriv.private_key.into(),
                [0; 32],
                EventId::from_slice(&[i; 32]).unwrap(),
            )
            .unwrap();
            ZapEventToSubscriptionConfig::new(&mut conn, zap_event.id, config.id).unwrap();
        }

        // get unpaid subscriptions
        let unpaid_zaps = ZapEvent::get_unpaid_zaps(&mut conn, ConfigType::Subscription).unwrap();
        assert_eq!(unpaid_zaps.len(), 11);
        let links = ZapEventToSubscriptionConfig::find_by_zap_event_ids(
            &mut conn,
            unpaid_zaps.iter().map(|zap| zap.id).collect(),
        )
        .unwrap();
        assert_eq!(links.len(), 11);

        // make one paid zap
        let paid = ZapEvent::create_zap_event(
            &mut conn,
            &npub,
            &to_npub,
            ConfigType::Subscription,
            100,
            xpriv.private_key.into(),
            [0; 32],
            EventId::from_slice(&[0xfd; 32]).unwrap(),
        )
        .unwrap();
        ZapEventToSubscriptionConfig::new(&mut conn, paid.id, config.id).unwrap();
        ZapEvent::mark_zap_paid(&mut conn, paid.event_id(), Timestamp::now()).unwrap();

        if expect_prune {
            // delete paid zap
            ZapEvent::delete_by_event_id(&mut conn, paid.event_id()).unwrap();
            // should delete subscription
            let num = prune_dead_subscriptions(&mut conn).unwrap();
            assert_eq!(num, 1);
        } else {
            // should not delete subscription
            let num = prune_dead_subscriptions(&mut conn).unwrap();
            assert_eq!(num, 0);
        }

        clear_database(&mut conn)
    }

    #[test]
    fn test_clear_dead_subscriptions() {
        do_test_clear_dead_subscriptions(true);
        do_test_clear_dead_subscriptions(false);
    }

    fn do_test_clear_dead_zap_configs(expect_prune: bool) {
        let mut conn = init_db();

        let npub = PublicKey::from_str(PUBKEY).unwrap();
        let to_npub = PublicKey::from_str(PUBKEY2).unwrap();
        let nwc = NostrWalletConnectURI::from_str(NWC).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Bitcoin, &[0; 32]).unwrap();

        // create a zap config
        let emoji = "🍕".to_string();
        let donation = DonationConfig {
            amount_sats: 5,
            lnurl: None,
            npub: Some(to_npub),
        };
        let config = SetUserConfig {
            npub,
            amount_sats: 100,
            nwc: Some(nwc),
            auth_id: None,
            emoji: Some(emoji.clone()),
            donations: Some(vec![donation]),
        };
        upsert_user(&mut conn, config).unwrap();

        let config = ZapConfig::get_by_pubkey_and_emoji(&mut conn, &npub, &emoji)
            .unwrap()
            .unwrap();

        let zap_event = ZapEvent::create_zap_event(
            &mut conn,
            &npub,
            &to_npub,
            ConfigType::Zap,
            100,
            xpriv.private_key.into(),
            [0; 32],
            EventId::from_slice(&[0xff; 32]).unwrap(),
        )
        .unwrap();
        ZapEventToZapConfig::new(&mut conn, zap_event.id, config.id).unwrap();

        // should not delete zap config
        let num = prune_dead_zap_configs(&mut conn).unwrap();
        assert_eq!(num, 0);

        // make a bunch of unpaid zaps
        for i in 0..100 {
            let zap_event = ZapEvent::create_zap_event(
                &mut conn,
                &npub,
                &to_npub,
                ConfigType::Zap,
                100,
                xpriv.private_key.into(),
                [0; 32],
                EventId::from_slice(&[i; 32]).unwrap(),
            )
            .unwrap();
            ZapEventToZapConfig::new(&mut conn, zap_event.id, config.id).unwrap();
        }

        // get unpaid zap events
        let unpaid_zaps = ZapEvent::get_unpaid_zaps(&mut conn, ConfigType::Zap).unwrap();
        assert_eq!(unpaid_zaps.len(), 101);
        let links = ZapEventToZapConfig::find_by_zap_event_ids(
            &mut conn,
            unpaid_zaps.iter().map(|zap| zap.id).collect(),
        )
        .unwrap();
        assert_eq!(links.len(), 101);

        // make one paid zap
        let paid = ZapEvent::create_zap_event(
            &mut conn,
            &npub,
            &to_npub,
            ConfigType::Zap,
            100,
            xpriv.private_key.into(),
            [0; 32],
            EventId::from_slice(&[0xfd; 32]).unwrap(),
        )
        .unwrap();
        ZapEventToZapConfig::new(&mut conn, paid.id, config.id).unwrap();
        ZapEvent::mark_zap_paid(&mut conn, paid.event_id(), Timestamp::now()).unwrap();

        if expect_prune {
            // delete paid zap
            ZapEvent::delete_by_event_id(&mut conn, paid.event_id()).unwrap();
            // should delete zap config
            let num = prune_dead_zap_configs(&mut conn).unwrap();
            assert_eq!(num, 1);
        } else {
            // should not delete zap config
            let num = prune_dead_zap_configs(&mut conn).unwrap();
            assert_eq!(num, 0);
        }

        clear_database(&mut conn)
    }

    #[test]
    fn test_clear_dead_zap_configs() {
        do_test_clear_dead_zap_configs(true);
        do_test_clear_dead_zap_configs(false);
    }

    #[test]
    fn test_prune_subscription() {
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

        // should not prune, it hasn't even attempted to pay
        let num = SubscriptionConfig::prune_unpaid(&mut conn).unwrap();
        assert_eq!(num, 0);

        // set last paid to now
        let now = Utc::now();
        diesel::update(schema::subscription_configs::table)
            .set(schema::subscription_configs::last_paid.eq(Some(now)))
            .execute(&mut conn)
            .unwrap();

        // should not prune, it just paid
        let num = SubscriptionConfig::prune_unpaid(&mut conn).unwrap();
        assert_eq!(num, 0);

        // set last paid to 1.5 periods ago
        let diff: i64 = (86_400.0 * 1.5) as i64;
        let small_time_ago = NaiveDateTime::from_timestamp_opt(now.timestamp() - diff, 0)
            .expect("Invalid timestamp");
        diesel::update(schema::subscription_configs::table)
            .set(schema::subscription_configs::last_paid.eq(Some(small_time_ago)))
            .execute(&mut conn)
            .unwrap();

        // should not prune, not far enough back
        let num = SubscriptionConfig::prune_unpaid(&mut conn).unwrap();
        assert_eq!(num, 0);

        // set last paid to 6 periods ago
        let diff: i64 = 86_400 * 6;
        let too_far_ago = NaiveDateTime::from_timestamp_opt(now.timestamp() - diff, 0)
            .expect("Invalid timestamp");
        diesel::update(schema::subscription_configs::table)
            .set(schema::subscription_configs::last_paid.eq(Some(too_far_ago)))
            .execute(&mut conn)
            .unwrap();

        // should not prune, not far enough back
        let num = SubscriptionConfig::prune_unpaid(&mut conn).unwrap();
        assert_eq!(num, 1);

        let config =
            SubscriptionConfig::get_by_pubkey_and_to_npub(&mut conn, &npub, &to_npub).unwrap();
        assert_eq!(config, None);

        clear_database(&mut conn)
    }
}
