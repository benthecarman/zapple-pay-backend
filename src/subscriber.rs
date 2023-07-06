use crate::db::get_user;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use lnurl::LnUrlResponse::LnUrlPayResponse;
use lnurl::{BlockingClient, Builder};
use nostr::key::XOnlyPublicKey;
use nostr::nips::nip47::{Method, NostrWalletConnectURI, Request, RequestParams};
use nostr::prelude::encrypt;
use nostr::{Event, EventBuilder, Filter, Keys, Kind, Metadata, Tag, Timestamp};
use nostr_sdk::{Client, RelayPoolNotification};
use sled::Db;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::watch::Receiver;

pub async fn start_subscription(db: Db, rx: Receiver<Vec<String>>) -> anyhow::Result<()> {
    // just need ephemeral keys for this
    let keys = Keys::generate();
    let lnurl_client = Builder::default().build_blocking()?;

    let cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrl>>> = Arc::new(Mutex::new(HashMap::new()));

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
                        let cache = cache.clone();
                        async move {
                            if let Err(e) =
                                handle_reaction(&db, &lnurl_client, event, cache.clone()).await
                            {
                                eprintln!("Error: {e}");
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
    lnurl_client: &BlockingClient,
    event: Event,
    cache: Arc<Mutex<HashMap<XOnlyPublicKey, LnUrl>>>,
) -> anyhow::Result<()> {
    println!("Received reaction: {event:?}");
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

    if let Some(user) = get_user(db, event.pubkey)? {
        if user.emoji() != event.content {
            return Ok(());
        }

        let nwc = user.nwc();

        let client = Client::new(&Keys::generate());

        client.add_relay("wss://nostr.wine", None).await?;
        client.add_relay("wss://nos.lol", None).await?;
        client.add_relay("wss://nostr.fmt.wiz.biz", None).await?;
        client.add_relay("wss://relay.damus.io", None).await?;
        client.connect().await;

        let event_filter = Filter::new().event(event_id).limit(1);
        client.subscribe(vec![event_filter]).await;

        let mut original_event: Option<Event> = None;
        let mut notifications = client.notifications();
        // todo time this out
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
                if event.id == event_id {
                    original_event = Some(event);
                    break;
                }
            };
        }

        // handle None case
        let original_event: Event = match original_event {
            None => return Err(anyhow!("No original event found")),
            Some(original_event) => original_event,
        };

        let lnurl = {
            let cache_result = {
                let cache = cache.lock().unwrap();
                cache.get(&original_event.pubkey).cloned()
            };
            match cache_result {
                Some(lnurl) => lnurl,
                None => {
                    let metadata_filter = Filter::new()
                        .kind(Kind::Metadata)
                        .author(original_event.pubkey.to_hex())
                        .limit(1);
                    client.subscribe(vec![metadata_filter]).await;

                    let mut lnurl: Option<LnUrl> = None;
                    let mut notifications = client.notifications();
                    // todo time this out
                    while let Ok(notification) = notifications.recv().await {
                        if let RelayPoolNotification::Event(_url, event) = notification {
                            if event.pubkey == original_event.pubkey && event.kind == Kind::Metadata
                            {
                                let metadata = Metadata::from_json(&event.content)?;
                                // parse lnurl
                                if let Some(lud06) = metadata.lud06 {
                                    if let Ok(url) = LnUrl::from_str(&lud06) {
                                        lnurl = Some(url);
                                        break;
                                    }
                                }
                                // try lightning address
                                if let Some(lud16) = metadata.lud16 {
                                    if let Ok(lnaddr) = LightningAddress::from_str(&lud16) {
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

                    let mut cache = cache.lock().unwrap();
                    cache.insert(original_event.pubkey, lnurl.clone());

                    lnurl
                }
            }
        };

        // pay to lnurl
        pay_to_lnurl(lnurl, lnurl_client, user.amount_sats * 1_000, &nwc).await?;
        // pay donations too
        for donation in user.donations() {
            pay_to_lnurl(
                donation.lnurl,
                lnurl_client,
                donation.amount_sats * 1_000,
                &nwc,
            )
            .await?;
        }
    }

    Ok(())
}

async fn pay_to_lnurl(
    lnurl: LnUrl,
    lnurl_client: &BlockingClient,
    amount_msats: u64,
    nwc: &NostrWalletConnectURI,
) -> anyhow::Result<()> {
    let resp = lnurl_client.make_request(&lnurl.url)?;
    let invoice = if let LnUrlPayResponse(pay) = resp {
        lnurl_client.get_invoice(&pay, amount_msats)?.invoice()
    } else {
        return Err(anyhow::anyhow!("Invalid lnurl response"));
    };

    if !invoice
        .amount_milli_satoshis()
        .is_some_and(|a| a == amount_msats)
    {
        return Err(anyhow::anyhow!("Got invoice with invalid amount"));
    }

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
