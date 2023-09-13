CREATE TABLE users
(
    id   SERIAL PRIMARY KEY,
    npub TEXT NOT NULL UNIQUE
);

CREATE UNIQUE INDEX users_npub_idx ON users (npub);

CREATE TABLE zap_configs
(
    id      SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id),
    emoji   TEXT    NOT NULL,
    amount  INTEGER NOT NULL,
    nwc     TEXT    NOT NULL,
    CONSTRAINT zap_configs_user_id_emoji_unique UNIQUE (user_id, emoji)
);

CREATE INDEX zap_configs_user_id_idx ON zap_configs (user_id);
CREATE INDEX zap_configs_emoji_idx ON zap_configs (emoji);
CREATE UNIQUE INDEX zap_configs_user_emoji_idx ON zap_configs (user_id, emoji);

CREATE TABLE donations
(
    id        SERIAL PRIMARY KEY,
    config_id INTEGER NOT NULL REFERENCES zap_configs (id),
    lnurl     TEXT    NOT NULL,
    amount    INTEGER NOT NULL
);

CREATE INDEX donations_config_id_idx ON donations (config_id);

CREATE TABLE subscription_configs
(
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users (id),
    to_npub     TEXT    NOT NULL,
    amount      INTEGER NOT NULL,
    time_period TEXT    NOT NULL,
    nwc         TEXT    NOT NULL,
    CONSTRAINT subscription_configs_user_id_to_npub_unique UNIQUE (user_id, to_npub)
);

CREATE INDEX subscription_configs_user_id_idx ON subscription_configs (user_id);
CREATE INDEX subscription_configs_to_npub_idx ON subscription_configs (to_npub);

CREATE TABLE zap_events
(
    id          SERIAL PRIMARY KEY,
    from_npub   TEXT    NOT NULL,
    to_npub     TEXT    NOT NULL,
    config_type TEXT    NOT NULL, -- if zap or subscription
    amount      INTEGER NOT NULL
);

CREATE INDEX zap_events_from_npub_idx ON zap_events (from_npub);
CREATE INDEX zap_events_to_npub_idx ON zap_events (to_npub);