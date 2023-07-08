use crate::db::get_user;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use lightning_invoice::Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::LnUrlResponse::LnUrlPayResponse;
use lnurl::{AsyncClient, Builder};
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::{Method, NostrWalletConnectURI, Request, RequestParams};
use nostr::prelude::encrypt;
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, Tag, Timestamp};
use nostr_sdk::{Client, RelayPoolNotification};
use serde_json::Value;
use sled::Db;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch::Receiver;

pub async fn start_subscription(
    db: Db,
    rx: Receiver<Vec<String>>,
    keys: Keys,
) -> anyhow::Result<()> {
    let lnurl_client = Builder::default().build_async()?;

    let lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrl>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>> = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let client = Client::new(&keys);
        // todo make this configurable
        client.add_relay("wss://nostr.wine", None).await?;
        client.add_relay("wss://nos.lol", None).await?;
        client.add_relay("wss://nostr.fmt.wiz.biz", None).await?;
        client.add_relay("wss://nostr.zebedee.cloud", None).await?;
        client.add_relay("wss://relay.damus.io", None).await?;
        client.connect().await;

        let authors: Vec<String> = rx.borrow().clone();

        let subscription = Filter::new()
            .kind(Kind::Reaction)
            .authors(authors)
            .since(Timestamp::now());

        client.subscribe(vec![subscription]).await;

        println!("Listening for nip 7 reactions...");

        let mut notifications = client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
                if event.kind == Kind::Reaction {
                    tokio::spawn({
                        let db = db.clone();
                        let lnurl_client = lnurl_client.clone();
                        let keys = keys.clone();
                        let lnurl_cache = lnurl_cache.clone();
                        let pay_cache = pay_cache.clone();
                        async move {
                            let fut = handle_reaction(
                                &db,
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
        }
    }
}

async fn handle_reaction(
    db: &Db,
    lnurl_client: &AsyncClient,
    event: Event,
    keys: &Keys,
    lnurl_cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrl>>>,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let mut tags = event.tags.clone();
    tags.reverse();
    let event_id = tags.into_iter().find_map(|tag| {
        if let Tag::Event(id, _, _) = tag {
            Some(id)
        } else {
            None
        }
    });

    let event_id = match event_id {
        None => return Err(anyhow!("No e tag found")),
        Some(e) => e,
    };

    let p_tag = event.tags.into_iter().find_map(|tag| {
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

    if let Some(user) = get_user(db, event.pubkey)? {
        if user.emoji() != event.content {
            return Ok(());
        }

        println!(
            "Received reaction: {} {} {}",
            event.id, event.content, event.pubkey
        );

        let nwc = user.nwc();

        let client = Client::new(&Keys::generate());

        client.add_relay("wss://nostr.wine", None).await?;
        client.add_relay("wss://nos.lol", None).await?;
        client.add_relay("wss://nostr.fmt.wiz.biz", None).await?;
        client.add_relay("wss://relay.damus.io", None).await?;
        client.connect().await;

        let lnurl = {
            let cache_result = {
                let cache = lnurl_cache.lock().unwrap();
                cache.get(&p_tag).cloned()
            };
            match cache_result {
                Some(lnurl) => lnurl,
                None => {
                    println!("No lnurl in cache, fetching...");
                    let metadata_filter = Filter::new()
                        .kind(Kind::Metadata)
                        .author(p_tag.to_hex())
                        .limit(1);
                    client.subscribe(vec![metadata_filter]).await;

                    let mut lnurl: Option<LnUrl> = None;
                    let mut notifications = client.notifications();
                    while let Ok(notification) = notifications.recv().await {
                        if let RelayPoolNotification::Event(_url, event) = notification {
                            if event.pubkey == p_tag && event.kind == Kind::Metadata {
                                let json: Value = serde_json::from_str(&event.content)?;
                                if let Value::Object(map) = json {
                                    let lud06 = map
                                        .get("lud06")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| LnUrl::from_str(s).ok());
                                    // parse lnurl
                                    if let Some(url) = lud06 {
                                        lnurl = Some(url);
                                        break;
                                    }
                                    let lud16 = map
                                        .get("lud16")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| LightningAddress::from_str(s).ok());
                                    // try lightning address
                                    if let Some(lnaddr) = lud16 {
                                        lnurl = Some(lnaddr.lnurl());
                                        break;
                                    }
                                }
                            }
                        };
                    }

                    // handle None case
                    let lnurl: LnUrl = match lnurl {
                        None => return Err(anyhow!("No lnurl found")),
                        Some(lnurl) => lnurl,
                    };

                    let mut cache = lnurl_cache.lock().unwrap();
                    cache.insert(p_tag, lnurl.clone());

                    lnurl
                }
            }
        };

        // pay to lnurl
        pay_to_lnurl(
            keys,
            Some(p_tag),
            Some(event_id),
            lnurl,
            lnurl_client,
            user.amount_sats * 1_000,
            &nwc,
            pay_cache.clone(),
        )
        .await?;
        // pay donations too
        for donation in user.donations() {
            pay_to_lnurl(
                keys,
                None,
                None,
                donation.lnurl,
                lnurl_client,
                donation.amount_sats * 1_000,
                &nwc,
                pay_cache.clone(),
            )
            .await?;
        }
    } else {
        return Err(anyhow!("User not found"));
    }

    Ok(())
}

async fn get_invoice_from_lnurl(
    keys: &Keys,
    user_key: Option<XOnlyPublicKey>,
    event_id: Option<EventId>,
    lnurl: &LnUrl,
    lnurl_client: &AsyncClient,
    amount_msats: u64,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<Invoice> {
    let pay = {
        let cache_result = {
            let cache = pay_cache.lock().unwrap();
            cache.get(lnurl).cloned()
        };
        match cache_result {
            Some(pay) => pay,
            None => {
                println!("No pay in cache, fetching...");
                let resp = lnurl_client.make_request(&lnurl.url).await?;
                if let LnUrlPayResponse(pay) = resp {
                    let mut cache = pay_cache.lock().unwrap();
                    cache.insert(lnurl.clone(), pay.clone());
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
                Tag::Relays(vec!["wss://nostr.mutinywallet.com".into()]),
            ];
            if let Some(event_id) = event_id {
                tags.push(Tag::Event(event_id, None, None));
            }
            EventBuilder::new(Kind::ZapRequest, "", &tags)
                .to_event(keys)
                .ok()
        }
        None => None,
    };

    let invoice = lnurl_client
        .get_invoice(&pay, amount_msats, zap_request)
        .await?
        .invoice();

    if !invoice
        .amount_milli_satoshis()
        .is_some_and(|a| a == amount_msats)
    {
        return Err(anyhow::anyhow!("Got invoice with invalid amount"));
    }

    Ok(invoice)
}

#[allow(clippy::too_many_arguments)]
async fn pay_to_lnurl(
    keys: &Keys,
    user_key: Option<XOnlyPublicKey>,
    event_id: Option<EventId>,
    lnurl: LnUrl,
    lnurl_client: &AsyncClient,
    amount_msats: u64,
    nwc: &NostrWalletConnectURI,
    pay_cache: Arc<Mutex<HashMap<LnUrl, PayResponse>>>,
) -> anyhow::Result<()> {
    let invoice = match get_invoice_from_lnurl(
        keys,
        user_key,
        event_id,
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
    client.add_relay(nwc.relay_url.clone(), None).await?;
    client.connect().await;
    client.send_event(event).await?;

    println!("Sent event to {}", nwc.relay_url);
    Ok(())
}

fn create_nwc_request(nwc: &NostrWalletConnectURI, invoice: String) -> Event {
    let req = Request {
        method: Method::PayInvoice,
        params: RequestParams { invoice },
    };

    let encrypted = encrypt(&nwc.secret, &nwc.public_key, req.as_json()).unwrap();
    let p_tag = Tag::PubKey(nwc.public_key, None);

    EventBuilder::new(Kind::WalletConnectRequest, encrypted, &[p_tag])
        .to_event(&Keys::new(nwc.secret))
        .unwrap()
}
