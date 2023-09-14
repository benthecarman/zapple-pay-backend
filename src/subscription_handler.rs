use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::zap_event::ZapEvent;
use crate::models::{schema, ConfigType};
use crate::LnUrlCacheResult;
use bitcoin::XOnlyPublicKey;
use chrono::{Timelike, Utc};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{Connection, PgConnection, RunQueryDsl};
use futures::future::FutureExt;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::Builder;
use nostr::Keys;
use nostr_sdk::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub async fn start_subscription_handler(
    keys: Keys,
    relays: Vec<String>,
    db_pool: Pool<ConnectionManager<PgConnection>>,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let lnurl_client = Builder::default().build_blocking()?;

    println!("Starting subscription handler..");

    loop {
        let start = Utc::now().naive_utc();
        let mut conn = db_pool.get()?;

        let (subscriptions, user_keys) = conn.transaction::<_, anyhow::Error, _>(|conn| {
            let subscriptions = SubscriptionConfig::get_needs_payment(conn)?;
            let user_ids = subscriptions
                .iter()
                .map(|subscription| subscription.user_id)
                .collect::<Vec<i32>>();

            let user_keys = User::get_by_user_ids(conn, user_ids)?;

            Ok((subscriptions, user_keys))
        })?;
        drop(conn);

        println!("Found {} subscriptions", subscriptions.len());

        if subscriptions.is_empty() {
            sleep_until_next_min(start.second()).await;
            continue;
        }

        let client = Client::new(&keys);
        for relay in relays.iter() {
            client.add_relay(relay.as_str(), None).await?;
        }
        client.connect().await;

        // get unique to_npubs
        let mut to_npubs = subscriptions
            .iter()
            .map(|subscription| subscription.to_npub())
            .collect::<Vec<XOnlyPublicKey>>();
        to_npubs.sort();
        to_npubs.dedup();

        // populate lnurl cache
        let mut futs = Vec::with_capacity(subscriptions.len());
        for to_npub in to_npubs {
            let fut = crate::profile_handler::get_user_lnurl(to_npub, &lnurl_cache, &client);
            futs.push(fut);
        }
        futures::future::join_all(futs).await;

        client.disconnect().await?;

        let lnurls = {
            let cache = lnurl_cache.lock().await;
            cache.clone()
        };

        // pay users
        let mut futs = Vec::with_capacity(subscriptions.len());
        let total = subscriptions.len();
        for sub in subscriptions {
            let from_user = user_keys.get(&sub.user_id).unwrap();
            let to_npub = sub.to_npub();
            let lnurl = match lnurls.get(&to_npub) {
                None => {
                    println!("No lnurl found for {to_npub}");
                    continue;
                }
                Some(LnUrlCacheResult::Timestamp(_)) => {
                    println!("Profile with no lnurl found for {to_npub}");
                    continue;
                }
                Some(LnUrlCacheResult::LnUrl((lnurl, _))) => lnurl.clone(),
            };
            let nwc = sub.nwc();
            let fut = crate::profile_handler::pay_to_lnurl(
                &keys,
                *from_user,
                None,
                None,
                lnurl,
                &lnurl_client,
                sub.amount_msats(),
                nwc,
                &pay_cache,
            )
            .map(|_| sub);

            futs.push(fut);
        }
        let successful: Vec<SubscriptionConfig> = futures::future::join_all(futs).await;
        let num_successful = successful.len();
        let num_failed = total - num_successful;

        if successful.is_empty() {
            if num_failed > 0 {
                println!("Failed to pay {num_failed} subscriptions");
            }

            sleep_until_next_min(start.second()).await;
            continue;
        }

        // save zap events and update last_paid
        let mut conn = db_pool.get()?;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            for mut sub in successful {
                sub.last_paid = Some(start);

                let from_user = user_keys.get(&sub.user_id).unwrap();
                let to_npub = sub.to_npub();
                // create zap event
                ZapEvent::create_zap_event(
                    conn,
                    from_user,
                    &to_npub,
                    ConfigType::Subscription,
                    sub.amount,
                )?;

                // update last_paid
                diesel::update(schema::subscription_configs::table)
                    .set(sub)
                    .execute(conn)?;
            }

            Ok(())
        })?;
        drop(conn);

        if num_successful > 0 {
            println!("Successfully paid {num_successful} subscriptions");
        }
        if num_failed > 0 {
            println!("Failed to pay {num_failed} subscriptions");
        }

        sleep_until_next_min(start.second()).await;
    }
}

async fn sleep_until_next_min(start_second: u32) {
    let mut now = Utc::now().naive_utc();
    // handle if function takes less than a second
    if now.second() == start_second {
        tokio::time::sleep(Duration::from_secs(1)).await;
        now = Utc::now().naive_utc();
    };

    // sleep until next top of the next minute
    let start = now + chrono::Duration::seconds(60 - now.second() as i64);
    let start = start.with_nanosecond(0).unwrap();
    let sleep_duration = (start - now).num_seconds() as u64 + 1; // add 1 second to be safe
    println!("Sleeping for {sleep_duration} seconds..");
    tokio::time::sleep(Duration::from_secs(sleep_duration)).await;
}
