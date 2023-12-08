use crate::models::subscription_config::SubscriptionConfig;
use crate::models::user::User;
use crate::models::wallet_auth::WalletAuth;
use crate::models::zap_event::ZapEvent;
use crate::models::zap_event_to_subscription_config::ZapEventToSubscriptionConfig;
use crate::models::{schema, ConfigType};
use crate::profile_handler::SentInvoice;
use crate::LnUrlCacheResult;
use anyhow::anyhow;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::XOnlyPublicKey;
use chrono::{Timelike, Utc};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{Connection, ExpressionMethods, PgConnection, RunQueryDsl};
use itertools::Itertools;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::{AsyncClient, Builder};
use log::*;
use nostr::prelude::NostrWalletConnectURI;
use nostr::prelude::ToBech32;
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
    xpriv: ExtendedPrivKey,
    relays: Vec<String>,
    db_pool: Pool<ConnectionManager<PgConnection>>,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let lnurl_client = Builder::default().build_async()?;

    info!("Starting subscription handler..");

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

        info!("Found {} subscriptions", subscriptions.len());

        if subscriptions.is_empty() {
            sleep_until_next_min(start.second()).await;
            continue;
        }

        // get unique to_npubs
        let mut to_npubs = subscriptions
            .iter()
            .map(|subscription| subscription.to_npub())
            .collect::<Vec<XOnlyPublicKey>>();
        to_npubs.sort();
        to_npubs.dedup();

        // populate lnurl cache
        populate_lnurl_cache(to_npubs, &relays, keys.clone(), lnurl_cache.clone()).await?;

        let lnurls = {
            let cache = lnurl_cache.lock().await;
            cache.clone()
        };

        // get subscriptions with their nwc
        let mut conn = db_pool.get()?;
        let subscriptions = subscriptions
            .into_iter()
            .map(|sub| {
                let (user_nwc_key, relay) = if let Some(auth_index) = sub.auth_index {
                    let (key, relay) = WalletAuth::get_user_data(&mut conn, auth_index)?
                        .ok_or(anyhow!("No user pubkey found"))?;
                    (Some(key), relay)
                } else {
                    (None, None)
                };
                let nwc = sub.nwc(xpriv, user_nwc_key, relay.as_deref());

                Ok((sub, nwc))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        drop(conn);

        // pay users
        let total = subscriptions.len();
        let mut successful: Vec<(SentInvoice, NostrWalletConnectURI, SubscriptionConfig)> =
            Vec::with_capacity(total);

        let subs_by_relay = subscriptions
            .into_iter()
            .sorted_by_key(|(_, nwc)| nwc.relay_url.clone())
            .group_by(|(_, nwc)| nwc.relay_url.clone())
            .into_iter()
            .map(|(url, subs)| (url, subs.collect::<Vec<_>>()))
            .collect::<Vec<_>>();

        for (relay, subs) in subs_by_relay {
            if subs.is_empty() {
                continue;
            }

            let client = Client::new(&keys);

            let proxy = if relay.host_str().is_some_and(|h| h.ends_with(".onion")) {
                Some(SocketAddr::from_str("127.0.0.1:9050")?)
            } else {
                None
            };

            client.add_relay(relay, proxy).await?;
            client.connect().await;

            let mut first = true;
            // group subscriptions into groups of 10
            let chunks = subs.chunks(10);
            for chunk in chunks {
                // sleep for 3 seconds between chunks
                if !first {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    first = false;
                }

                // pay subscriptions in chunk
                for (sub, nwc) in chunk {
                    if let Err(e) = pay_subscription(
                        sub.clone(),
                        nwc.clone(),
                        &user_keys,
                        &lnurls,
                        &pay_cache,
                        &lnurl_client,
                        &keys,
                        &mut successful,
                        &client,
                    )
                    .await
                    {
                        error!("Error paying subscription ({}): {e}", sub.id);
                    }
                }
            }

            client.disconnect().await?;
        }
        let num_successful = successful.len();
        let num_failed = total - num_successful;

        if successful.is_empty() {
            if num_failed > 0 {
                warn!("Failed to pay {num_failed} subscriptions");
            }

            sleep_until_next_min(start.second()).await;
            continue;
        }

        // save zap events and update last_paid
        let mut conn = db_pool.get()?;
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            for (sent, nwc, sub) in successful.iter() {
                let from_user = user_keys.get(&sub.user_id).unwrap();
                let to_npub = sub.to_npub();
                // save to db
                let event = ZapEvent::create_zap_event(
                    conn,
                    from_user,
                    &to_npub,
                    ConfigType::Subscription,
                    sub.amount,
                    nwc.secret,
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
                            .map(|(_, _, sub)| sub.id)
                            .collect::<Vec<i32>>(),
                    ),
                )
                .set(schema::subscription_configs::last_paid.eq(Some(start.naive_local())))
                .execute(conn)?;

            Ok(())
        })?;
        drop(conn);

        if num_successful > 0 {
            info!("Successfully paid {num_successful} subscriptions");
        }
        if num_failed > 0 {
            warn!("Failed to pay {num_failed} subscriptions");
        }

        sleep_until_next_min(start.second()).await;
    }
}

async fn pay_subscription(
    sub: SubscriptionConfig,
    nwc: NostrWalletConnectURI,
    user_keys: &HashMap<i32, XOnlyPublicKey>,
    lnurls: &HashMap<XOnlyPublicKey, LnUrlCacheResult>,
    pay_cache: &Mutex<HashMap<LnUrl, PayResponse>>,
    lnurl_client: &AsyncClient,
    keys: &Keys,
    successful: &mut Vec<(SentInvoice, NostrWalletConnectURI, SubscriptionConfig)>,
    client: &Client,
) -> anyhow::Result<()> {
    let from_user = user_keys.get(&sub.user_id).unwrap();
    let to_npub = sub.to_npub();
    let lnurl = match lnurls.get(&to_npub) {
        None => {
            debug!("No lnurl found for {}", to_npub.to_bech32().unwrap());
            return Ok(());
        }
        Some(LnUrlCacheResult::Timestamp(_)) => {
            debug!(
                "Profile with no lnurl found for {} on subscription {}",
                to_npub.to_bech32().unwrap(),
                sub.id
            );
            return Ok(());
        }
        Some(LnUrlCacheResult::LnUrl((lnurl, _))) => (lnurl.clone(), None),
        Some(LnUrlCacheResult::MultipleLnUrl((lnurl, lnurl2, _))) => {
            (lnurl.clone(), Some(lnurl2.clone()))
        }
    };
    let tried_lnurl = lnurl.0.clone();
    let amount_msats = sub.amount_msats();

    match crate::profile_handler::pay_to_lnurl(
        keys,
        *from_user,
        Some(to_npub),
        None,
        None,
        lnurl,
        lnurl_client,
        amount_msats,
        nwc.clone(),
        pay_cache,
        Some(client.clone()),
    )
    .await
    {
        Err(e) => {
            error!(
                "Error paying to lnurl {tried_lnurl} {amount_msats} msats on {} for subscription {}: {e}",
                nwc.relay_url.to_string(), sub.id
            );
        }
        Ok(res) => successful.push((res, nwc, sub)),
    }

    Ok(())
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
    debug!("Sleeping for {sleep_duration} seconds..");
    tokio::time::sleep(Duration::from_secs(sleep_duration)).await;
}

pub async fn populate_lnurl_cache(
    to_npubs: Vec<XOnlyPublicKey>,
    relays: &[String],
    keys: Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
) -> anyhow::Result<()> {
    let client = Client::new(&keys);
    for relay in relays.iter() {
        client.add_relay(relay.as_str(), None).await?;
    }
    client.connect().await;

    // populate lnurl cache
    let mut futs = Vec::with_capacity(to_npubs.len());
    for to_npub in to_npubs {
        let fut = crate::profile_handler::get_user_lnurl(to_npub, &lnurl_cache, &client);
        futs.push(fut);
    }
    futures::future::join_all(futs).await;

    client.disconnect().await?;

    Ok(())
}
