use chrono::{Datelike, Duration, NaiveDateTime, Timelike, Utc};
use core::fmt;
use itertools::Itertools;
use nostr::key::PublicKey;
use nostr::nips::nip47::{Error, Method};
use nostr::prelude::url::form_urlencoded::byte_serialize;
use nostr::Url;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::str::FromStr;

fn url_encode<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    byte_serialize(data.as_ref()).collect()
}

pub const ALL_SUBSCRIPTION_PERIODS: [SubscriptionPeriod; 6] = [
    SubscriptionPeriod::Minute,
    SubscriptionPeriod::Hour,
    SubscriptionPeriod::Day,
    SubscriptionPeriod::Week,
    SubscriptionPeriod::Month,
    SubscriptionPeriod::Year,
];

/// How often a subscription should pay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionPeriod {
    /// Pays at the top of every minute
    Minute,
    /// Pays at the top of every hour
    Hour,
    /// Pays daily at midnight
    Day,
    /// Pays every week on sunday, midnight
    Week,
    /// Pays every month on the first, midnight
    Month,
    /// Pays every year on the January 1st, midnight
    Year,
}

impl SubscriptionPeriod {
    pub fn period_start(&self) -> NaiveDateTime {
        let now = Utc::now();
        match self {
            SubscriptionPeriod::Minute => now
                .date_naive()
                .and_hms_opt(now.hour(), now.minute(), 0)
                .unwrap(),
            SubscriptionPeriod::Hour => now.date_naive().and_hms_opt(now.hour(), 0, 0).unwrap(),
            SubscriptionPeriod::Day => now.date_naive().and_hms_opt(0, 0, 0).unwrap(),
            SubscriptionPeriod::Week => (now
                - Duration::days(now.weekday().num_days_from_sunday() as i64))
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap(),
            SubscriptionPeriod::Month => now
                .date_naive()
                .with_day(1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            SubscriptionPeriod::Year => NaiveDateTime::new(
                now.date_naive().with_ordinal(1).unwrap(),
                chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
        }
    }

    // Returns the start of the period that was 5 periods ago
    pub fn five_periods_ago(&self) -> NaiveDateTime {
        let now = Utc::now().timestamp();
        let diff = match self {
            SubscriptionPeriod::Minute => 60 * 5,
            SubscriptionPeriod::Hour => 60 * 60 * 5,
            SubscriptionPeriod::Day => 86_400 * 5,
            SubscriptionPeriod::Week => 86_400 * 7 * 5,
            SubscriptionPeriod::Month => 86_400 * 30 * 5,
            SubscriptionPeriod::Year => 86_400 * 365 * 5,
        };

        NaiveDateTime::from_timestamp_opt(now - diff, 0).expect("Invalid timestamp")
    }
}

impl Serialize for SubscriptionPeriod {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> Deserialize<'a> for SubscriptionPeriod {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SubscriptionPeriod::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SubscriptionPeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubscriptionPeriod::Minute => write!(f, "minute"),
            SubscriptionPeriod::Hour => write!(f, "hour"),
            SubscriptionPeriod::Day => write!(f, "day"),
            SubscriptionPeriod::Week => write!(f, "week"),
            SubscriptionPeriod::Month => write!(f, "month"),
            SubscriptionPeriod::Year => write!(f, "year"),
        }
    }
}

impl FromStr for SubscriptionPeriod {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "minute" => Ok(SubscriptionPeriod::Minute),
            "hour" => Ok(SubscriptionPeriod::Hour),
            "hourly" => Ok(SubscriptionPeriod::Hour),
            "day" => Ok(SubscriptionPeriod::Day),
            "daily" => Ok(SubscriptionPeriod::Day),
            "week" => Ok(SubscriptionPeriod::Week),
            "weekly" => Ok(SubscriptionPeriod::Week),
            "month" => Ok(SubscriptionPeriod::Month),
            "monthly" => Ok(SubscriptionPeriod::Month),
            "year" => Ok(SubscriptionPeriod::Year),
            "yearly" => Ok(SubscriptionPeriod::Year),
            _ => Err(anyhow::anyhow!("Invalid SubscriptionPeriod")),
        }
    }
}

/// NIP49 URI Scheme
pub const NIP49_URI_SCHEME: &str = "nostr+walletauth";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NIP49Budget {
    pub time_period: SubscriptionPeriod,
    pub amount: u64,
}

impl fmt::Display for NIP49Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.amount, self.time_period)
    }
}

impl FromStr for NIP49Budget {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        let amount = split
            .next()
            .ok_or(Error::InvalidURI)?
            .parse()
            .map_err(|_| Error::InvalidURI)?;
        let time_period = split
            .next()
            .ok_or(Error::InvalidURI)?
            .parse()
            .map_err(|_| Error::InvalidURI)?;

        Ok(Self {
            time_period,
            amount,
        })
    }
}

/// Nostr Wallet Auth URI
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NIP49URI {
    /// App Pubkey
    pub public_key: PublicKey,
    /// URL of the relay of choice where the `App` is connected and the `Signer` must send and listen for messages.
    pub relay_url: Url,
    /// A random identifier that the wallet will use to identify the connection.
    pub secret: String,
    /// Required commands
    pub required_commands: Vec<Method>,
    /// Optional commands
    pub optional_commands: Vec<Method>,
    /// Budget
    pub budget: Option<NIP49Budget>,
    /// App's pubkey for identity verification
    pub identity: Option<PublicKey>,
}

impl FromStr for NIP49URI {
    type Err = Error;
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let url = Url::parse(uri)?;

        if url.scheme() != NIP49_URI_SCHEME {
            return Err(Error::InvalidURIScheme);
        }

        if let Some(pubkey) = url.domain() {
            let public_key = PublicKey::from_str(pubkey)?;

            let mut relay_url: Option<Url> = None;
            let mut required_commands: Vec<Method> = vec![];
            let mut optional_commands: Vec<Method> = vec![];
            let mut budget: Option<NIP49Budget> = None;
            let mut secret: Option<String> = None;
            let mut identity: Option<PublicKey> = None;

            for (key, value) in url.query_pairs() {
                match key {
                    Cow::Borrowed("relay") => {
                        relay_url = Some(Url::parse(value.as_ref())?);
                    }
                    Cow::Borrowed("secret") => {
                        secret = Some(value.to_string());
                    }
                    Cow::Borrowed("required_commands") => {
                        required_commands = value
                            .split(' ')
                            .map(Method::from_str)
                            .collect::<Result<Vec<Method>, _>>()?;
                    }
                    Cow::Borrowed("optional_commands") => {
                        optional_commands = value
                            .split(' ')
                            .map(Method::from_str)
                            .collect::<Result<Vec<Method>, _>>()?;
                    }
                    Cow::Borrowed("budget") => {
                        budget = Some(NIP49Budget::from_str(value.as_ref())?);
                    }
                    Cow::Borrowed("identity") => {
                        identity = Some(PublicKey::from_str(value.as_ref())?);
                    }
                    _ => (),
                }
            }

            if required_commands.is_empty() {
                return Err(Error::InvalidURI);
            }

            if let Some((relay_url, secret)) = relay_url.zip(secret) {
                return Ok(Self {
                    public_key,
                    relay_url,
                    secret,
                    required_commands,
                    optional_commands,
                    budget,
                    identity,
                });
            }
        }

        Err(Error::InvalidURI)
    }
}

impl fmt::Display for NIP49URI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{NIP49_URI_SCHEME}://{}?relay={}&secret={}&required_commands={}",
            self.public_key,
            url_encode(self.relay_url.to_string()),
            self.secret,
            url_encode(
                self.required_commands
                    .iter()
                    .map(|x| x.to_string())
                    .join(" ")
            ),
        )?;
        if !self.optional_commands.is_empty() {
            write!(
                f,
                "&optional_commands={}",
                url_encode(
                    self.optional_commands
                        .iter()
                        .map(|x| x.to_string())
                        .join(" ")
                )
            )?;
        }
        if let Some(budget) = &self.budget {
            write!(f, "&budget={}", url_encode(budget.to_string()))?;
        }
        if let Some(identity) = &self.identity {
            write!(f, "&identity={identity}")?;
        }
        Ok(())
    }
}

impl Serialize for NIP49URI {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> Deserialize<'a> for NIP49URI {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let uri = String::deserialize(deserializer)?;
        NIP49URI::from_str(&uri).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NIP49Confirmation {
    /// A random identifier that the wallet will use to identify the connection.
    /// Should be the same as the one in the uri.
    pub secret: String,
    /// Commands they agreed to
    pub commands: Vec<Method>,
    /// Relay the wallet prefers
    pub relay: Option<String>,
}
