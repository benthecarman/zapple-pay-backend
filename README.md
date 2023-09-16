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

```json
{
  "npub": "user's npub",
  "amount_sats": 1000,
  "nwc": "user's nwc",
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
    "zaps" :[
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

payload:

```json
{
  "npub": "user's npub",
  "to_npub": "user to zap npub",
  "amount_sats": 1000,
  "time_period": "day",
  "nwc": "user's nwc"
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
