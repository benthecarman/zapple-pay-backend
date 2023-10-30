CREATE TABLE wallet_auth
(
    index       SERIAL PRIMARY KEY,
    pubkey      TEXT UNIQUE             NOT NULL,
    user_pubkey TEXT,
    created_at  TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE UNIQUE INDEX wallet_auth_pubkey_idx ON wallet_auth (pubkey);

-- make zap_configs work with wallet_auth

ALTER TABLE zap_configs
    ALTER COLUMN nwc DROP NOT NULL;

ALTER TABLE zap_configs
    ADD COLUMN auth_index INTEGER REFERENCES wallet_auth (index);

ALTER TABLE zap_configs
    ADD CONSTRAINT zap_config_connection_check CHECK
        ((nwc IS NOT NULL AND auth_index IS NULL) OR (nwc IS NULL AND auth_index IS NOT NULL));


-- make subscription_configs work with wallet_auth

ALTER TABLE subscription_configs
    ALTER COLUMN nwc DROP NOT NULL;

ALTER TABLE subscription_configs
    ADD COLUMN auth_index INTEGER REFERENCES wallet_auth (index);

ALTER TABLE subscription_configs
    ADD CONSTRAINT subscription_configs_connection_check CHECK
        ((nwc IS NOT NULL AND auth_index IS NULL) OR (nwc IS NULL AND auth_index IS NOT NULL));
