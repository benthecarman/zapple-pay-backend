# Zapple Pay

Zapple Pay lets you automatically zap notes based on if you give a ⚡ reaction.

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
      "lnurl": "donation lnurl"
    }
  ]
}
```

returns:
the user's current configs

```json
[
  {
    "npub": "user's npub",
    "amount_sats": 1000,
    "emoji": "⚡",
    "donations": [
      {
        "amount_sats": 1000,
        "lnurl": "donation lnurl"
      }
    ]
  }
]
```

### Get User

`GET /get-user/:npub`

returns:
the user's current configs

```json
[
  {
    "npub": "user's npub",
    "amount_sats": 1000,
    "emoji": "⚡",
    "donations": [
      {
        "amount_sats": 1000,
        "lnurl": "donation lnurl"
      }
    ]
  }
]
```

### Get User

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
      "lnurl": "donation lnurl"
    }
  ]
}
```

### Delete User

`GET /delete-user/:npub/:emoji`

returns:
the user's current configs

```json
[
  {
    "npub": "user's npub",
    "amount_sats": 1000,
    "emoji": "⚡",
    "donations": [
      {
        "amount_sats": 1000,
        "lnurl": "donation lnurl"
      }
    ]
  }
]
```