use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::zap_event::ZapEvent;
use crate::models::zap_event_to_subscription_config::ZapEventToSubscriptionConfig;
use crate::models::{schema, ConfigType};
use crate::profile_handler::SentInvoice;
use crate::LnUrlCacheResult;
use bitcoin::XOnlyPublicKey;
use chrono::{Timelike, Utc};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{Connection, ExpressionMethods, PgConnection, RunQueryDsl};
use itertools::Itertools;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::Builder;
use nostr::Keys;
use nostr_sdk::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
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
    let lnurl_client = Builder::default().build_async()?;

    println!("Starting subscription handler..");

    loop {
        let start = Utc::now();
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

        let subs_by_relay = subscriptions
            .into_iter()
            .sorted_by_key(|s| s.nwc().relay_url)
            .group_by(|s| s.nwc().relay_url.clone())
            .into_iter()
            .map(|(url, subs)| (url, subs.collect::<Vec<_>>()))
            .collect::<Vec<_>>();

        for (relay, subs) in subs_by_relay {
            let client = Client::new(&keys);

            let proxy = if relay.host_str().is_some_and(|h| h.ends_with(".onion")) {
                Some(SocketAddr::from_str("127.0.0.1:9050")?)
            } else {
                None
            };

            client.add_relay(relay, proxy).await?;
            client.connect().await;

            for sub in subs {
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
                    Some(LnUrlCacheResult::LnUrl((lnurl, _))) => (lnurl.clone(), None),
                    Some(LnUrlCacheResult::MultipleLnUrl((lnurl, lnurl2, _))) => {
                        (lnurl.clone(), Some(lnurl2.clone()))
                    }
                };
                let nwc = sub.nwc();
                let tried_lnurl = lnurl.0.clone();
                let keys = keys.clone();
                let lnurl_client = lnurl_client.clone();
                let pay_cache = pay_cache.clone();
                let client = client.clone();
                let fut = async move {
                    let amount_msats = sub.amount_msats();
                    match crate::profile_handler::pay_to_lnurl(
                        &keys,
                        *from_user,
                        Some(to_npub),
                        None,
                        None,
                        lnurl,
                        &lnurl_client,
                        amount_msats,
                        nwc,
                        &pay_cache,
                        Some(client),
                    )
                    .await
                    {
                        Err(e) => {
                            eprintln!(
                                "Error paying to lnurl {tried_lnurl} {amount_msats} msats: {e}"
                            );
                            Err(e)
                        }
                        Ok(res) => Ok((res, sub)),
                    }
                };

                futs.push(fut);
            }
        }
        let successful: Vec<(SentInvoice, SubscriptionConfig)> = futures::future::join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect();
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
            for (sent, sub) in successful.iter() {
                let from_user = user_keys.get(&sub.user_id).unwrap();
                let to_npub = sub.to_npub();
                // save to db
                let event = ZapEvent::create_zap_event(
                    conn,
                    from_user,
                    &to_npub,
                    ConfigType::Subscription,
                    sub.amount,
                    sub.nwc().secret,
                    sent.payment_hash,
                    sent.event_id,
                )?;

                ZapEventToSubscriptionConfig::new(conn, event.id, sub.id)?;
            }

            // update last_paid
            diesel::update(schema::subscription_configs::table)
                .filter(
                    schema::subscription_configs::id.eq_any(
                        successful
                            .iter()
                            .map(|(_, sub)| sub.id)
                            .collect::<Vec<i32>>(),
                    ),
                )
                .set(schema::subscription_configs::last_paid.eq(Some(start.naive_local())))
                .execute(conn)?;

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
