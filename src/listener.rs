use crate::models::zap_event::ZapEvent;
use crate::models::ConfigType;
use crate::profile_handler::{get_user_lnurl, pay_to_lnurl};
use crate::LnUrlCacheResult;
use anyhow::anyhow;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::Hash;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::{AsyncClient, Builder};
use nostr::hashes::sha256;
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::{Method, NIP47Error, Response, ResponseResult};
use nostr::prelude::decrypt;
use nostr::{Event, EventId, Filter, Keys, Kind, Tag, TagKind, Timestamp};
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

pub async fn start_listener(
    relays: Vec<String>,
    db_pool: Pool<ConnectionManager<PgConnection>>,
    mut pubkey_receiver: Receiver<Vec<String>>,
    mut secret_receiver: Receiver<Vec<XOnlyPublicKey>>,
    keys: Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    println!("Using relays: {:?}", relays);
    let lnurl_client = Builder::default().build_async()?;

    loop {
        let client = Client::new(&keys);
        for relay in relays.iter() {
            client.add_relay(relay.as_str(), None).await?;
        }
        client.connect().await;

        let tagged: Vec<XOnlyPublicKey> = secret_receiver.borrow().clone();
        let authors: Vec<String> = pubkey_receiver.borrow().clone();

        let kinds = vec![
            Kind::Reaction,
            Kind::TextNote,
            Kind::Regular(1311),
            Kind::WalletConnectResponse,
        ];

        let reactions = Filter::new()
            .kinds(kinds.clone())
            .authors(authors)
            .since(Timestamp::now());

        let responses = Filter::new()
            .kind(Kind::WalletConnectResponse)
            .pubkeys(tagged)
            .since(Timestamp::now());

        client.subscribe(vec![reactions, responses]).await;

        println!("Listening for events...");

        let mut notifications = client.notifications();
        loop {
            tokio::select! {
                Ok(notification) = notifications.recv() => {
                    match notification {
                        RelayPoolNotification::Event(_url, event) => {
                            if kinds.contains(&event.kind) && event.tags.iter().any(|tag| matches!(tag, Tag::PubKey(_, _))) {
                                tokio::spawn({
                                    let db_pool = db_pool.clone();
                                    let client = client.clone();
                                    let lnurl_client = lnurl_client.clone();
                                    let keys = keys.clone();
                                    let lnurl_cache = lnurl_cache.clone();
                                    let pay_cache = pay_cache.clone();
                                    async move {
                                        let fut = handle_event(
                                            &db_pool,
                                            &client,
                                            &lnurl_client,
                                            event,
                                            &keys,
                                            lnurl_cache.clone(),
                                            pay_cache.clone(),
                                        );

                                        match tokio::time::timeout(Duration::from_secs(30), fut).await {
                                            Ok(Ok(_)) => {}
                                            Ok(Err(e)) => eprintln!("Error: {e}"),
                                            Err(_) => eprintln!("Timeout"),
                                        }
                                    }
                                });
                            }
                        }
                        RelayPoolNotification::Shutdown => {
                            println!("Relay pool shutdown");
                            break;
                        }
                        RelayPoolNotification::Stop => {}
                        RelayPoolNotification::Message(_, _) => {}
                    }
                }
                _ = pubkey_receiver.changed() => {
                    break;
                }
                _ = secret_receiver.changed() => {
                    break;
                }
            }
        }

        client.disconnect().await?;
    }
}

async fn handle_event(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    client: &Client,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    match event.kind {
        Kind::WalletConnectResponse => handle_nwc_response(db_pool, event).await,
        Kind::TextNote | Kind::Reaction => {
            handle_reaction(
                db_pool,
                client,
                lnurl_client,
                event,
                keys,
                lnurl_cache,
                pay_cache,
            )
            .await
        }
        Kind::Regular(1311) => {
            handle_live_chat(
                db_pool,
                client,
                lnurl_client,
                event,
                keys,
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
    pub result_type: Option<Method>,
    /// NIP47 Error
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    pub result: Option<Value>,
}

impl ResponseNoType {
    pub fn into_response(mut self) -> anyhow::Result<Response> {
        if self.result_type.is_none() {
            self.result_type = Some(Method::PayInvoice);
        }
        let json = json!(self);
        let res: Response = serde_json::from_value(json)?;
        Ok(res)
    }
}

async fn handle_nwc_response(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    event: Event,
) -> anyhow::Result<()> {
    println!("Received nwc response: {}", event.id);

    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags
        .iter()
        .find_map(|tag| {
            if let Tag::Event(id, _, _) = tag {
                Some(*id)
            } else {
                None
            }
        })
        .ok_or(anyhow!("No e tag found"))?;

    let mut conn = db_pool.get()?;

    let Some(zap_event) = ZapEvent::find_by_event_id(&mut conn, event_id)? else {
        return Ok(());
    };

    let content = decrypt(&zap_event.secret_key(), &event.pubkey, event.content)?;
    let response: ResponseNoType = serde_json::from_str(&content).map_err(|e| {
        eprintln!("Error parsing response: {content}");
        e
    })?;
    let response = response.into_response()?;

    if response.result_type != Method::PayInvoice {
        return Ok(());
    }

    if let Some(e) = response.error {
        return Err(anyhow!(
            "Received error, code: {:?}, message: {}",
            e.code,
            e.message
        ));
    }

    if let Some(ResponseResult::PayInvoice(res)) = response.result {
        let preimage: [u8; 32] = FromHex::from_hex(&res.preimage)?;

        if sha256::Hash::hash(&preimage).to_hex() == zap_event.payment_hash {
            println!("Payment successful: {}", zap_event.payment_hash);
            ZapEvent::mark_zap_paid(&mut conn, event_id, event.created_at)?;
        } else {
            return Err(anyhow!("Invalid preimage"));
        }
    }

    Ok(())
}

async fn handle_live_chat(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    client: &Client,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags.iter().find_map(|tag| {
        if let Tag::Event(id, _, _) = tag {
            Some(*id)
        } else {
            None
        }
    });

    let p_tag = tags.iter().find_map(|tag| {
        if let Tag::PubKey(p, _) = tag {
            Some(p.to_owned())
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
        client,
        lnurl_client,
        event,
        keys,
        lnurl_cache,
        pay_cache,
    )
    .await
}

async fn handle_reaction(
    db_pool: &Pool<ConnectionManager<PgConnection>>,
    client: &Client,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags.iter().find_map(|tag| {
        if let Tag::Event(id, _, _) = tag {
            Some(*id)
        } else {
            None
        }
    });

    let p_tag = tags.into_iter().find_map(|tag| {
        if let Tag::PubKey(p, _) = tag {
            Some(p)
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
        client,
        lnurl_client,
        event,
        keys,
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
    client: &Client,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let content =
        if event.kind == Kind::Reaction && (event.content.is_empty() || event.content == "+") {
            "❤️"
        } else {
            &event.content
        };

    let mut conn = db_pool.get()?;
    if let Some(user) = crate::models::get_user_zap_config(&mut conn, event.pubkey, content)? {
        println!(
            "Received reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );

        let nwc = user.zap_config.nwc();

        let lnurl = get_user_lnurl(user_key, &lnurl_cache, client).await?;

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
        )
        .await?;
        // pay donations too
        let mut futs = vec![];
        for donation in user.donations {
            let (lnurl, to_user) = match donation.lnurl() {
                Some(lnurl) => ((lnurl, None), None),
                None => {
                    let npub = donation.npub().unwrap();
                    let lnurl = get_user_lnurl(npub, &lnurl_cache, client).await?;

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
            ));
        }
        futures::future::join_all(futs).await;

        // save to db
        ZapEvent::create_zap_event(
            &mut conn,
            &user_key,
            &event.pubkey,
            ConfigType::Zap,
            user.zap_config.amount,
            nwc.secret,
            sent.payment_hash,
            sent.event_id,
        )?;
    } else {
        let truncated: String = content.chars().take(5).collect();

        // if we truncated, add ...
        let err = if content != truncated {
            anyhow!("Config not found: {} {}…", event.pubkey, truncated)
        } else {
            anyhow!("Config not found: {} {}", event.pubkey, truncated)
        };

        return Err(err);
    }

    Ok(())
}
