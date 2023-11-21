# Zapple Pay

Zapple Pay lets you use nostr wallet connect to automatically zap notes based on a configured emoji or to subscribe to a
user and zap them on a regular basis.

## Build

If you are having trouble building you may need to install `libpq-dev`.

```bash
sudo apt-get install libpq-dev
```

## API

### Set User

`POST /set-user`

payload:

the emoji and donations are optional

only one of `nwc` or `auth_id` can be set.

```json
{
  "npub": "user's npub",
  "amount_sats": 1000,
  "nwc": "user's nwc",
  "auth_id": "id from /wallet-auth",
  "emoji": "⚡",
  "donations": [
    {
      "amount_sats": 1000,
      "lnurl": "donation lnurl",
      "npub": "donation npub"
    }
  ]
}
```

returns:
the user's current configs

```json
{
  "zaps": [
    {
      "npub": "user's npub",
      "amount_sats": 1000,
      "emoji": "⚡",
      "donations": [
        {
          "amount_sats": 1000,
          "lnurl": "donation lnurl",
          "npub": "donation npub"
        }
      ]
    }
  ],
  "subscriptions": []
}
```

### Create Subscription

`POST /create-subscription`

time_period can be `minute`, `hour`, `day`, `week`, `month`, or `year`

only one of `nwc` or `auth_id` can be set.

payload:

```json
{
  "npub": "user's npub",
  "to_npub": "user to zap npub",
  "amount_sats": 1000,
  "time_period": "day",
  "nwc": "user's nwc",
  "auth_id": "id from /wallet-auth"
}
```

returns:
the user's current configs

```json
{
  "zaps": [],
  "subscriptions": [
    {
      "npub": "user's npub",
      "to_npub": "user to zap npub",
      "amount_sats": 1000,
      "time_period": "day"
    }
  ]
}
```

### Get User

`GET /get-user/:npub`

returns:
the user's current configs

```json
{
  "zaps": [
    {
      "npub": "user's npub",
      "amount_sats": 1000,
      "emoji": "⚡",
      "donations": [
        {
          "amount_sats": 1000,
          "lnurl": "donation lnurl",
          "npub": "donation npub"
        }
      ]
    }
  ],
  "subscriptions": [
    {
      "npub": "user's npub",
      "to_npub": "user to zap npub",
      "amount_sats": 1000,
      "time_period": "day"
    }
  ]
}
```

### Get User Zap Config

`GET /get-user/:npub/:emoji`

returns:
the user's current config

```json
{
  "npub": "user's npub",
  "amount_sats": 1000,
  "emoji": "⚡",
  "donations": [
    {
      "amount_sats": 1000,
      "lnurl": "donation lnurl",
      "npub": "donation npub"
    }
  ]
}
```

### Get User Subscription

`GET /get-subscriptions/:npub/:to_npub`

returns:
the user's current subscription config for `to_npub`

```json
{
  "npub": "user's npub",
  "to_npub": "user to zap npub",
  "amount_sats": 1000,
  "time_period": "day"
}
```

### Delete User

`GET /delete-user/:npub`

deletes all the user's zap configs and subscriptions

returns:
the user's current configs

```json
{
  "zaps": [
    {
      "npub": "user's npub",
      "amount_sats": 1000,
      "emoji": "⚡",
      "donations": [
        {
          "amount_sats": 1000,
          "lnurl": "donation lnurl",
          "npub": "donation npub"
        }
      ]
    }
  ],
  "subscriptions": [
    {
      "npub": "user's npub",
      "to_npub": "user to zap npub",
      "amount_sats": 1000,
      "time_period": "day"
    }
  ]
}
```

### Delete User

`GET /delete-user/:npub/:emoji`

returns:
the user's current configs

```json
{
  "zaps": [
    {
      "npub": "user's npub",
      "amount_sats": 1000,
      "emoji": "⚡",
      "donations": [
        {
          "amount_sats": 1000,
          "lnurl": "donation lnurl",
          "npub": "donation npub"
        }
      ]
    }
  ],
  "subscriptions": [
    {
      "npub": "user's npub",
      "to_npub": "user to zap npub",
      "amount_sats": 1000,
      "time_period": "day"
    }
  ]
}
```

### Delete User Subscription

`GET /delete-subscription/:npub/:to_npub`

returns:
the user's current configs

```json
{
  "zaps": [
    {
      "npub": "user's npub",
      "amount_sats": 1000,
      "emoji": "⚡",
      "donations": [
        {
          "amount_sats": 1000,
          "lnurl": "donation lnurl",
          "npub": "donation npub"
        }
      ]
    }
  ],
  "subscriptions": [
    {
      "npub": "user's npub",
      "to_npub": "user to zap npub",
      "amount_sats": 1000,
      "time_period": "day"
    }
  ]
}
```

### Nostr Wallet Auth

`GET /wallet-auth`

query params:

These query parameters are optional ways to modify the NWA uri given. If you are setting them `time_period` and `amount`
but both be set `identity` is optional.

- time_period: Time period for the budget. Can be one of `day`, `week`, `month`, or `year`
- amount: Amount in satoshis for the budget.
- identity: Hex encoded pubkey for which identity to be associated with this connection, if not given zapple pay's key
  will be used

returns:

Nostr Wallet Auth uri and id to reference in future api calls.

```json
{
  "id": "hex encoded id",
  "uri": "nostr+walletauth://blahblah"
}
```

### Nostr Wallet Status

`GET /check-wallet-auth`

query params:

- id: The `id` given in `/wallet-auth`

returns:

boolean for if we have successfully connected

```json
true
```

### Counts

`GET /count`

returns:
metrics on zapple pay

```json
{
  "users": 426,
  "zap_configs": 572,
  "subscription_configs": 2,
  "zap_count": 4909,
  "zap_total": 213485
}
```
