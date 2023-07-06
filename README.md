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

```json
null
```

### Get User

`GET /get-user/:npub`

returns:

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
