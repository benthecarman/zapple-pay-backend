use crate::models::subscription_config::SubscriptionConfig;
use crate::models::wallet_auth::WalletAuth;
use crate::models::zap_config::ZapConfig;
use crate::models::zap_event::ZapEvent;
use crate::models::zap_event_to_subscription_config::ZapEventToSubscriptionConfig;
use crate::models::zap_event_to_zap_config::ZapEventToZapConfig;
use crate::models::ConfigType;
use crate::nip49::NIP49Confirmation;
use crate::profile_handler::{get_user_lnurl, pay_to_lnurl};
use crate::utils::map_emoji;
use crate::{utils, LnUrlCacheResult, DEFAULT_AUTH_RELAY};
use anyhow::anyhow;
use bitcoin::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{Connection, PgConnection};
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::{AsyncClient, Builder};
use log::*;
use nostr::hashes::sha256;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip04::decrypt;
use nostr::nips::nip47::{Method, NIP47Error, Response, ResponseResult};
use nostr::prelude::ErrorCode;
use nostr::{Event, EventId, Filter, Keys, Kind, Tag, TagKind, Timestamp, SECP256K1};
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use itertools::Itertools;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

pub async fn start_listener(
    mut relays: Vec<String>,
    db_pool: Pool<ConnectionManager<PgConnection>>,
    mut pubkey_receiver: Receiver<Vec<XOnlyPublicKey>>,
    mut secret_receiver: Receiver<Vec<XOnlyPublicKey>>,
    mut auth_receiver: Receiver<Vec<XOnlyPublicKey>>,
    keys: Keys,
    xpriv: ExtendedPrivKey,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    debug!("Using relays: {:?}", relays);
    let lnurl_client = Builder::default().build_async()?;

    loop {
        let client = Client::new(&keys);

        let mut conn = db_pool.get()?;
        let nwc_relays = ZapConfig::get_nwc_relays(&mut conn)?;
        drop(conn);
        relays.extend(nwc_relays.into_keys().map(|r| r.to_string()));
        relays.push(DEFAULT_AUTH_RELAY.to_string());
        relays.sort();
        relays.dedup();

        for relay in relays.iter() {
            if relay.is_empty() {
                continue;
            }
            if relay.contains("localhost") {
                continue;
            }
            client.add_relay(relay.as_str()).await?;
        }
        client.connect().await;

        let tagged: Vec<XOnlyPublicKey> = secret_receiver.borrow().clone();
        let authors: Vec<XOnlyPublicKey> = pubkey_receiver.borrow().clone();

        let auth_keys: Vec<XOnlyPublicKey> = auth_receiver.borrow().clone();

        let kinds = vec![
            Kind::Reaction,
            Kind::TextNote,
            Kind::Regular(1311),
            Kind::WalletConnectResponse,
            Kind::ParameterizedReplaceable(33194),
        ];

        let now = Timestamp::now();

        // filters for reactions
        let mut filters: Vec<Filter> = authors
            .chunks(250)
            .map(|keys| {
                Filter::new()
                    .kinds(kinds.clone())
                    .authors(keys.to_vec())
                    .since(now)
            })
            .collect();

        // filters for responses
        filters.extend(tagged.chunks(250).map(|keys| {
            Filter::new()
                .kind(Kind::WalletConnectResponse)
                .pubkeys(keys.to_vec())
                .since(now)
        }));

        // filters for NWA
        filters.extend(auth_keys.chunks(250).map(|keys| {
            Filter::new()
                .kind(Kind::ParameterizedReplaceable(33194))
                .identifiers(keys.iter().map(|k| k.to_string()).collect_vec())
                .since(now)
        }));

        client.subscribe(filters).await;

        info!("Listening for events...");

        let mut notifications = client.notifications();
        loop {
            tokio::select! {
                Ok(notification) = notifications.recv() => {
                    match notification {
                        RelayPoolNotification::Event { event, .. } => {
                            if kinds.contains(&event.kind) && event.tags.iter().any(|tag| matches!(tag, Tag::PublicKey { uppercase: false, .. } | Tag::Identifier(_))) {
                                tokio::spawn({
                                    let db_pool = db_pool.clone();
                                    let lnurl_client = lnurl_client.clone();
                                    let keys = keys.clone();
                                    let lnurl_cache = lnurl_cache.clone();
                                    let pay_cache = pay_cache.clone();
                                    async move {
                                        let fut = handle_event(
                                            &db_pool,
                                            &lnurl_client,
                                            event,
                                            &keys,
                                            xpriv,
                                            lnurl_cache.clone(),
                                            pay_cache.clone(),
                                        );

                                        match tokio::time::timeout(Duration::from_secs(30), fut).await {
                                            Ok(Ok(_)) => {}
                                            Ok(Err(e)) => error!("Error: {e}"),
                                            Err(_) => error!("Timeout"),
                                        }
                                    }
                                });
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            warn!("Relay pool shutdown");
                            break;
                        }
                        RelayPoolNotification::Stop => {}
                        RelayPoolNotification::Message { .. } => {}
                        RelayPoolNotification::RelayStatus{ .. } => {}}
                }
                _ = pubkey_receiver.changed() => {
                    break;
                }
                _ = secret_receiver.changed() => {
                    break;
                }
                _ = auth_receiver.changed() => {
                    let auth_keys: Vec<String> = auth_receiver.borrow().iter().map(|x| x.to_string()).collect();

                    let auth = Filter::new()
                        .kind(Kind::ParameterizedReplaceable(33194))
                        .identifiers(auth_keys)
                        .since(Timestamp::now());
                    client.subscribe(vec![auth]).await;
                }
            }
        }

        client.disconnect().await?;
    }
}

async fn handle_event(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: ExtendedPrivKey,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    event.verify()?;

    match event.kind {
        Kind::ParameterizedReplaceable(33194) => handle_auth_response(db_pool, xpriv, event).await,
        Kind::WalletConnectResponse => handle_nwc_response(db_pool, event).await,
        Kind::TextNote | Kind::Reaction => {
            handle_reaction(
                db_pool,
                lnurl_client,
                event,
                keys,
                xpriv,
                lnurl_cache,
                pay_cache,
            )
            .await
        }
        Kind::Regular(1311) => {
            handle_live_chat(
                db_pool,
                lnurl_client,
                event,
                keys,
                xpriv,
                lnurl_cache,
                pay_cache,
            )
            .await
        }
        Kind::Metadata => Ok(()),
        kind => Err(anyhow!("Invalid event kind, got: {kind:?}")),
    }
}

// struct for handling alby not sending result type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseNoType {
    /// Request Method
    pub result_type: Option<String>,
    /// NIP47 Error
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    pub result: Option<Value>,
}

impl ResponseNoType {
    pub fn into_response(mut self) -> anyhow::Result<Response> {
        if self
            .result_type
            .as_ref()
            .filter(|s| !s.is_empty())
            .is_none()
        {
            self.result_type = Some("pay_invoice".to_string());
        }
        let json = json!(self);
        let res: Response = serde_json::from_value(json)?;
        Ok(res)
    }
}

async fn handle_auth_response(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    xpriv: ExtendedPrivKey,
    event: Event,
) -> anyhow::Result<()> {
    trace!("Received auth response: {}", event.id);

    let d_tag = event.tags.iter().find_map(|tag| {
        if let Tag::Identifier(pk) = tag {
            XOnlyPublicKey::from_str(pk).ok()
        } else {
            None
        }
    });
    let d_tag = match d_tag {
        Some(pk) => pk,
        None => return Err(anyhow!("No d tag found")),
    };

    let mut conn = db_pool.get()?;
    let Some(auth) = WalletAuth::get_by_pubkey(&mut conn, d_tag)? else {
        return Err(anyhow!("No auth found"));
    };
    if auth.user_pubkey().is_some() {
        return Err(anyhow!("Auth already has user_pubkey"));
    }

    let secret = xpriv
        .derive_priv(
            &SECP256K1,
            &[ChildNumber::from_hardened_idx(auth.index as u32).unwrap()],
        )
        .unwrap()
        .private_key;
    let content = decrypt(&secret, &event.pubkey, &event.content)?;
    let confirmation: NIP49Confirmation = serde_json::from_str(&content)?;

    if !confirmation.commands.contains(&Method::PayInvoice) {
        return Err(anyhow!("Invalid confirmation, missing pay_invoice"));
    }
    if confirmation.secret != utils::calculate_nwa_secret(xpriv, auth.pubkey()) {
        return Err(anyhow!("Invalid secret"));
    }

    WalletAuth::add_user_data(&mut conn, d_tag, event.pubkey, confirmation.relay)?;

    info!("Successfully registered with Nostr Wallet Auth");

    Ok(())
}

async fn handle_nwc_response(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    event: Event,
) -> anyhow::Result<()> {
    trace!("Received nwc response: {}", event.id);

    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags
        .iter()
        .find_map(|tag| {
            if let Tag::Event { event_id, .. } = tag {
                Some(*event_id)
            } else {
                None
            }
        })
        .ok_or(anyhow!("No e tag found"))?;

    let mut conn = db_pool.get()?;

    let Some(zap_event) = ZapEvent::find_by_event_id(&mut conn, event_id)? else {
        return Ok(());
    };

    let content = decrypt(&zap_event.secret_key(), &event.pubkey, &event.content)?;
    let response: ResponseNoType = serde_json::from_str(&content).map_err(|e| {
        error!("Error parsing response: {content}");
        e
    })?;
    let response = response.into_response()?;

    if response.result_type != Method::PayInvoice {
        return Ok(());
    }

    if let Some(e) = response.error {
        // this means the user deleted it from alby, safe to delete from db
        if matches!(e.code, ErrorCode::Unauthorized)
            && e.message == "The public key does not have a wallet connected."
        {
            let mut conn = db_pool.get()?;
            conn.transaction::<_, anyhow::Error, _>(|conn| {
                let event_opt = ZapEvent::delete_by_event_id(conn, event_id)?;

                if let Some(event) = event_opt {
                    match event.config_type() {
                        ConfigType::Zap => {
                            if let Some(to) =
                                ZapEventToZapConfig::find_by_zap_event_id(conn, event.id)?
                            {
                                ZapConfig::delete_by_id(conn, to.zap_config_id)?;
                                info!("Deleted user's zap config");
                            }
                        }
                        ConfigType::Subscription => {
                            if let Some(to) =
                                ZapEventToSubscriptionConfig::find_by_zap_event_id(conn, event.id)?
                            {
                                SubscriptionConfig::delete_by_id(conn, to.subscription_config_id)?;
                                info!("Deleted user's subscription config");
                            }
                        }
                    }
                }

                Ok(())
            })?;
        }

        return Err(anyhow!(
            "Received error, code: {:?}, message: {}",
            e.code,
            e.message
        ));
    }

    if let Some(ResponseResult::PayInvoice(res)) = response.result {
        let preimage: [u8; 32] = FromHex::from_hex(&res.preimage)?;

        if sha256::Hash::hash(&preimage).to_string() == zap_event.payment_hash {
            debug!("Payment successful: {}", zap_event.payment_hash);
            ZapEvent::mark_zap_paid(&mut conn, event_id, event.created_at)?;
        } else {
            return Err(anyhow!("Invalid preimage"));
        }
    }

    Ok(())
}

async fn handle_live_chat(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: ExtendedPrivKey,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags.iter().find_map(|tag| {
        if let Tag::Event { event_id, .. } = tag {
            Some(*event_id)
        } else {
            None
        }
    });

    let p_tag = tags.iter().find_map(|tag| {
        if let Tag::PublicKey {
            public_key,
            uppercase: false,
            ..
        } = tag
        {
            Some(*public_key)
        } else {
            None
        }
    });

    // if no p tag we are zapping the streamer, need to get pubkey from a tag
    let (user_key, a_tag) = match p_tag {
        Some(p) => (p, None),
        None => {
            let a_tag = tags.into_iter().find(|t| t.kind() == TagKind::A);
            let user_key = a_tag.as_ref().and_then(|tag| {
                let tag = tag.as_vec();
                let kpi: Vec<&str> = tag[1].split(':').collect();
                let kind = Kind::from_str(kpi[0]).ok();
                let pk = XOnlyPublicKey::from_str(kpi[1]).ok();

                if kind.is_some_and(|k| k.as_u64() == 30311) {
                    pk
                } else {
                    None
                }
            });

            match user_key {
                Some(pk) => (pk, a_tag),
                None => return Err(anyhow!("No a tag found")),
            }
        }
    };

    pay_user(
        user_key,
        event_id,
        a_tag,
        db_pool,
        lnurl_client,
        event,
        keys,
        xpriv,
        lnurl_cache,
        pay_cache,
    )
    .await
}

async fn handle_reaction(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: ExtendedPrivKey,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags.iter().find_map(|tag| {
        if let Tag::Event { event_id, .. } = tag {
            Some(*event_id)
        } else {
            None
        }
    });

    let p_tag = tags.into_iter().find_map(|tag| {
        if let Tag::PublicKey {
            public_key,
            uppercase: false,
            ..
        } = tag
        {
            Some(public_key)
        } else {
            None
        }
    });

    let p_tag = match p_tag {
        None => return Err(anyhow!("No p tag found")),
        Some(p) => p,
    };

    pay_user(
        p_tag,
        event_id,
        None,
        db_pool,
        lnurl_client,
        event,
        keys,
        xpriv,
        lnurl_cache,
        pay_cache,
    )
    .await
}

async fn pay_user(
    user_key: XOnlyPublicKey,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    xpriv: ExtendedPrivKey,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let content = if event.kind == Kind::Reaction {
        map_emoji(&event.content).unwrap_or(&event.content)
    } else {
        &event.content
    };

    let mut conn = db_pool.get()?;
    if let Some(user) = crate::models::get_user_zap_config(&mut conn, event.pubkey, content)? {
        debug!(
            "Received reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );

        let (user_nwc_key, relay) = if let Some(auth_index) = user.zap_config.auth_index {
            let (key, relay) = WalletAuth::get_user_data(&mut conn, auth_index)?
                .ok_or(anyhow!("No user pubkey found"))?;
            (Some(key), relay)
        } else {
            (None, None)
        };

        let nwc = user.zap_config.nwc(xpriv, user_nwc_key, relay.as_deref());

        let lnurl = get_user_lnurl(user_key, &lnurl_cache, lnurl_client).await?;

        // pay to lnurl
        let sent = pay_to_lnurl(
            keys,
            event.pubkey,
            Some(user_key),
            event_id,
            a_tag,
            lnurl,
            lnurl_client,
            user.zap_config.amount_msats(),
            nwc.clone(),
            &pay_cache,
            None,
        )
        .await?;
        // pay donations too
        let mut futs = vec![];
        for donation in user.donations {
            let (lnurl, to_user) = match donation.lnurl() {
                Some(lnurl) => ((lnurl, None), None),
                None => {
                    let npub = donation.npub().unwrap();
                    let lnurl = get_user_lnurl(npub, &lnurl_cache, lnurl_client).await?;

                    (lnurl, Some(npub))
                }
            };

            futs.push(pay_to_lnurl(
                keys,
                event.pubkey,
                to_user,
                None,
                None,
                lnurl,
                lnurl_client,
                donation.amount_msats(),
                nwc.clone(),
                &pay_cache,
                None,
            ));
        }
        futures::future::join_all(futs).await;

        // save to db
        conn.transaction::<_, anyhow::Error, _>(|conn| {
            let event = ZapEvent::create_zap_event(
                conn,
                &user_key,
                &event.pubkey,
                ConfigType::Zap,
                user.zap_config.amount,
                nwc.secret,
                sent.payment_hash,
                sent.event_id,
            )?;

            ZapEventToZapConfig::new(conn, event.id, user.zap_config.id)?;

            Ok(())
        })?;

        info!(
            "Successful reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );
    } else {
        if log_enabled!(Level::Debug) {
            let truncated: String = content.chars().take(5).collect();
            // if we truncated, add ...
            if content != truncated {
                debug!("Config not found: {} {truncated}…", event.pubkey)
            } else {
                debug!("Config not found: {} {truncated}", event.pubkey)
            };
        }

        return Ok(());
    }

    Ok(())
}
