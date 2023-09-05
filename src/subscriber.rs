use crate::db::get_user;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use futures::future::Either;
use futures::future::Either::{Left, Right};
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::LnUrlResponse::LnUrlPayResponse;
use lnurl::{BlockingClient, Builder};
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::{Method, NostrWalletConnectURI, Request, RequestParams};
use nostr::prelude::{encrypt, PayInvoiceRequestParams, ToBech32};
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, Tag, TagKind, Timestamp};
use nostr_sdk::{Client, RelayPoolNotification};
use serde_json::Value;
use sled::Db;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch::Receiver;

pub async fn start_subscription(
    db: Db,
    mut rx: Receiver<Vec<String>>,
    keys: Keys,
) -> anyhow::Result<()> {
    let lnurl_client = Builder::default().build_blocking()?;

    let lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, Either<LnUrl, u64>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let client = Client::new(&keys);
        // todo make this configurable
        client.add_relay("wss://nostr.wine", None).await?;
        client.add_relay("wss://nos.lol", None).await?;
        client.add_relay("wss://nostr.fmt.wiz.biz", None).await?;
        client.add_relay("wss://nostr.zbd.gg", None).await?;
        client.add_relay("wss://relay.damus.io", None).await?;
        client.add_relay("wss://purplepag.es", None).await?;
        client.connect().await;

        let authors: Vec<String> = rx.borrow().clone();

        let kinds = vec![Kind::Reaction, Kind::TextNote, Kind::Regular(1311)];

        let subscription = Filter::new()
            .kinds(kinds.clone())
            .authors(authors)
            .since(Timestamp::now());

        client.subscribe(vec![subscription]).await;

        println!("Listening for events...");

        let mut notifications = client.notifications();
        loop {
            tokio::select! {
                Ok(notification) = notifications.recv() => {
                    match notification {
                        RelayPoolNotification::Event(_url, event) => {
                                tokio::spawn({
                                    let db = db.clone();
                                    let client = client.clone();
                                    let lnurl_client = lnurl_client.clone();
                                    let keys = keys.clone();
                                    let lnurl_cache = lnurl_cache.clone();
                                    let pay_cache = pay_cache.clone();
                                    async move {
                                        let fut = handle_event(
                                            &db,
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
                        RelayPoolNotification::Shutdown => {
                            println!("Relay pool shutdown");
                            break;
                        }
                        RelayPoolNotification::Stop => {}
                        RelayPoolNotification::Message(_, _) => {}
                    }
                }
                _ = rx.changed() => {
                    break;
                }
            }
        }

        client.disconnect().await?;
    }
}

async fn handle_event(
    db: &Db,
    client: &Client,
    lnurl_client: &BlockingClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, Either<LnUrl, u64>>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    match event.kind {
        Kind::TextNote | Kind::Reaction => {
            handle_reaction(
                db,
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
                db,
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

async fn handle_live_chat(
    db: &Db,
    client: &Client,
    lnurl_client: &BlockingClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, Either<LnUrl, u64>>>>,
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
            let user_key = a_tag.clone().and_then(|tag| {
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
        db,
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
    db: &Db,
    client: &Client,
    lnurl_client: &BlockingClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, Either<LnUrl, u64>>>>,
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
        db,
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
    db: &Db,
    client: &Client,
    lnurl_client: &BlockingClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, Either<LnUrl, u64>>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let content =
        if event.kind == Kind::Reaction && (event.content.is_empty() || event.content == "+") {
            "❤️"
        } else {
            &event.content
        };

    if let Some(user) = get_user(db, event.pubkey, content, true)? {
        println!(
            "Received reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );

        let nwc = user.nwc();

        let lnurl = {
            let (cache_result, timestamp) = {
                let cache = lnurl_cache.lock().unwrap();
                let cache = cache.get(&user_key);
                match cache {
                    None => (None, None),
                    Some(either) => match either {
                        Left(lnurl) => (Some(lnurl.clone()), None),
                        Right(timestamp) => (None, Some(*timestamp)),
                    },
                }
            };
            match cache_result {
                Some(lnurl) => lnurl,
                None => {
                    println!("No lnurl in cache, fetching...");

                    let mut metadata_filter = Filter::new()
                        .kind(Kind::Metadata)
                        .author(user_key.to_hex())
                        .limit(1);

                    if let Some(timestamp) = timestamp {
                        metadata_filter = metadata_filter.since(Timestamp::from(timestamp));
                    }

                    let timeout = Duration::from_secs(20);
                    let events = client
                        .get_events_of(vec![metadata_filter], Some(timeout))
                        .await?;

                    let mut lnurl: Option<LnUrl> = None;

                    for event in events {
                        if event.pubkey == user_key && event.kind == Kind::Metadata {
                            let json: Value = serde_json::from_str(&event.content)?;
                            if let Value::Object(map) = json {
                                // try parse lightning address
                                let lud16 = map
                                    .get("lud16")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| LightningAddress::from_str(s).ok());
                                if let Some(lnaddr) = lud16 {
                                    lnurl = Some(lnaddr.lnurl());
                                    break;
                                }

                                // try parse lnurl pay
                                let lud06 = map
                                    .get("lud06")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| LnUrl::from_str(s).ok());
                                if let Some(url) = lud06 {
                                    lnurl = Some(url);
                                    break;
                                }

                                let mut cache = lnurl_cache.lock().unwrap();
                                cache.insert(user_key, Right(event.created_at.as_u64()));

                                return Err(anyhow!("Profile has no lnurl or lightning address"));
                            }
                        }
                    }

                    // handle None case
                    let lnurl: LnUrl = match lnurl {
                        None => return Err(anyhow!("No lnurl found")),
                        Some(lnurl) => lnurl,
                    };

                    let mut cache = lnurl_cache.lock().unwrap();
                    cache.insert(user_key, Left(lnurl.clone()));

                    lnurl
                }
            }
        };

        // pay to lnurl
        pay_to_lnurl(
            keys,
            event.pubkey,
            Some(user_key),
            event_id,
            a_tag,
            lnurl,
            lnurl_client,
            user.amount_sats * 1_000,
            &nwc,
            pay_cache.clone(),
        )
        .await?;
        // pay donations too
        let mut futs = vec![];
        for donation in user.donations() {
            futs.push(pay_to_lnurl(
                keys,
                event.pubkey,
                None,
                None,
                None,
                donation.lnurl,
                lnurl_client,
                donation.amount_sats * 1_000,
                &nwc,
                pay_cache.clone(),
            ));
        }
        futures::future::join_all(futs).await;
    } else {
        let truncated: String = content.chars().take(5).collect();

        // if we truncated, add ...
        let err = if content != truncated {
            anyhow!("Config not found: {} {}...", event.pubkey, truncated)
        } else {
            anyhow!("Config not found: {} {}", event.pubkey, truncated)
        };

        return Err(err);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn get_invoice_from_lnurl(
    keys: &Keys,
    from_user: XOnlyPublicKey,
    user_key: Option<XOnlyPublicKey>,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    lnurl: &LnUrl,
    lnurl_client: &BlockingClient,
    amount_msats: u64,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<Bolt11Invoice> {
    let pay = {
        let cache_result = {
            let cache = pay_cache.lock().unwrap();
            cache.get(lnurl).cloned()
        };
        match cache_result {
            Some(pay) => pay,
            None => {
                println!("No pay in cache, fetching...");
                let resp = if lnurl.url.contains(".onion") {
                    Builder::default()
                        .proxy("127.0.0.1:9050")
                        .build_blocking()?
                        .make_request(&lnurl.url)?
                } else {
                    lnurl_client.make_request(&lnurl.url)?
                };

                if let LnUrlPayResponse(pay) = resp {
                    // don't cache voltage lnurls, they change everytime
                    if !lnurl.url.contains("vlt.ge") {
                        let mut cache = pay_cache.lock().unwrap();
                        cache.insert(lnurl.clone(), pay.clone());
                    }
                    pay
                } else {
                    return Err(anyhow::anyhow!("Invalid lnurl response"));
                }
            }
        }
    };

    let zap_request = match user_key {
        Some(user_key) => {
            let mut tags = vec![
                Tag::PubKey(user_key, None),
                Tag::Amount(amount_msats),
                Tag::Lnurl(lnurl.to_string()),
                Tag::Relays(vec!["wss://nostr.mutinywallet.com".into()]),
            ];
            if let Some(event_id) = event_id {
                tags.push(Tag::Event(event_id, None, None));
            }
            if let Some(a_tag) = a_tag {
                tags.push(a_tag);
            }
            let content = format!("From: nostr:{}", from_user.to_bech32().unwrap());
            EventBuilder::new(Kind::ZapRequest, content, &tags)
                .to_event(keys)
                .ok()
        }
        None => None,
    };

    let invoice = {
        let res =
            lnurl_client.get_invoice(&pay, amount_msats, zap_request.clone().map(|e| e.as_json()));

        match res {
            Ok(inv) => inv.invoice(),
            Err(_) => lnurl_client
                .get_invoice(
                    &pay,
                    amount_msats,
                    zap_request.map(|e| urlencoding::encode(&e.as_json()).to_string()),
                )?
                .invoice(),
        }
    };

    if !invoice
        .amount_milli_satoshis()
        .is_some_and(|a| a == amount_msats)
    {
        return Err(anyhow::anyhow!(
            "Got invoice with invalid amount expected: {amount_msats} msats got: {:?} msats",
            invoice.amount_milli_satoshis()
        ));
    }

    Ok(invoice)
}

#[allow(clippy::too_many_arguments)]
async fn pay_to_lnurl(
    keys: &Keys,
    from_user: XOnlyPublicKey,
    user_key: Option<XOnlyPublicKey>,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    lnurl: LnUrl,
    lnurl_client: &BlockingClient,
    amount_msats: u64,
    nwc: &NostrWalletConnectURI,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let invoice = match get_invoice_from_lnurl(
        keys,
        from_user,
        user_key,
        event_id,
        a_tag,
        &lnurl,
        lnurl_client,
        amount_msats,
        pay_cache,
    )
    .await
    {
        Ok(invoice) => invoice,
        Err(e) => {
            return Err(anyhow!(
                "Error getting invoice from lnurl ({}): {e}",
                lnurl.url
            ));
        }
    };

    let event = create_nwc_request(nwc, invoice.to_string());

    let keys = Keys::new(nwc.secret);
    let client = Client::new(&keys);

    let proxy = if nwc
        .relay_url
        .host_str()
        .is_some_and(|h| h.ends_with(".onion"))
    {
        Some(SocketAddr::from_str("127.0.0.1:9050")?)
    } else {
        None
    };

    client.add_relay(&nwc.relay_url, proxy).await?;
    client.connect().await;
    client.send_event(event).await?;
    client.disconnect().await?;

    println!("Sent event to {}", nwc.relay_url);
    Ok(())
}

fn create_nwc_request(nwc: &NostrWalletConnectURI, invoice: String) -> Event {
    let req = Request {
        method: Method::PayInvoice,
        params: RequestParams::PayInvoice(PayInvoiceRequestParams { invoice }),
    };

    let encrypted = encrypt(&nwc.secret, &nwc.public_key, req.as_json()).unwrap();
    let p_tag = Tag::PubKey(nwc.public_key, None);

    EventBuilder::new(Kind::WalletConnectRequest, encrypted, &[p_tag])
        .to_event(&Keys::new(nwc.secret))
        .unwrap()
}
