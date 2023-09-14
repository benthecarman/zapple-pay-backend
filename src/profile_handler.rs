use crate::LnUrlCacheResult;
use anyhow::anyhow;
use bitcoin::hashes::hex::ToHex;
use bitcoin::XOnlyPublicKey;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use lnurl::pay::PayResponse;
use lnurl::LnUrlResponse::LnUrlPayResponse;
use lnurl::{BlockingClient, Builder};
use nostr::nips::nip47::{Method, NostrWalletConnectURI, Request, RequestParams};
use nostr::prelude::{encrypt, PayInvoiceRequestParams, ToBech32};
use nostr::{Event, EventBuilder, EventId, Filter, Keys, Kind, Tag, Timestamp};
use nostr_sdk::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Mutex;

pub async fn get_user_lnurl(
    user_key: XOnlyPublicKey,
    lnurl_cache: &Mutex<HashMap<XOnlyPublicKey, LnUrlCacheResult>>,
    client: &Client,
) -> anyhow::Result<LnUrl> {
    let (cache_result, timestamp) = {
        let cache = lnurl_cache.lock().await;
        let cache = cache.get(&user_key);
        match cache {
            None => (None, None),
            Some(either) => match either {
                LnUrlCacheResult::LnUrl((lnurl, timestamp)) => {
                    // if we got the lnurl more than 24 hours ago, return None
                    if Timestamp::now().as_u64() - timestamp > 60 * 60 * 24 {
                        (None, None)
                    } else {
                        (Some(lnurl.clone()), None)
                    }
                }
                LnUrlCacheResult::Timestamp(timestamp) => (None, Some(*timestamp)),
            },
        }
    };
    let lnurl = match cache_result {
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

                        let mut cache = lnurl_cache.lock().await;
                        cache.insert(
                            user_key,
                            LnUrlCacheResult::Timestamp(event.created_at.as_u64()),
                        );

                        return Err(anyhow!("Profile has no lnurl or lightning address"));
                    }
                }
            }

            // handle None case
            let lnurl: LnUrl = match lnurl {
                None => return Err(anyhow!("No lnurl found")),
                Some(lnurl) => lnurl,
            };

            let mut cache = lnurl_cache.lock().await;
            let now = Timestamp::now().as_u64();
            cache.insert(user_key, LnUrlCacheResult::LnUrl((lnurl.clone(), now)));

            lnurl
        }
    };

    Ok(lnurl)
}

async fn get_invoice_from_lnurl(
    keys: &Keys,
    from_user: XOnlyPublicKey,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    lnurl: &LnUrl,
    lnurl_client: &BlockingClient,
    amount_msats: u64,
    pay_cache: &Mutex<HashMap<LnUrl, PayResponse>>,
) -> anyhow::Result<Bolt11Invoice> {
    let pay = {
        let cache_result = {
            let cache = pay_cache.lock().await;
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
                        let mut cache = pay_cache.lock().await;
                        cache.insert(lnurl.clone(), pay.clone());
                    }
                    pay
                } else {
                    return Err(anyhow::anyhow!("Invalid lnurl response"));
                }
            }
        }
    };

    let zap_request = {
        let mut tags = vec![
            Tag::PubKey(from_user, None),
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
    };

    let invoice = {
        let res = lnurl_client.get_invoice(
            &pay,
            amount_msats,
            zap_request.as_ref().map(|e| e.as_json()),
        );

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

pub async fn pay_to_lnurl(
    keys: &Keys,
    from_user: XOnlyPublicKey,
    event_id: Option<EventId>,
    a_tag: Option<Tag>,
    lnurl: LnUrl,
    lnurl_client: &BlockingClient,
    amount_msats: u64,
    nwc: NostrWalletConnectURI,
    pay_cache: &Mutex<HashMap<LnUrl, PayResponse>>,
) -> anyhow::Result<()> {
    let invoice = match get_invoice_from_lnurl(
        keys,
        from_user,
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

    let event = create_nwc_request(&nwc, invoice.to_string());

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
