-- Revert subscription_configs changes
ALTER TABLE subscription_configs
    DROP CONSTRAINT subscription_configs_connection_check;
ALTER TABLE subscription_configs
    DROP COLUMN auth_index;
ALTER TABLE subscription_configs
    ALTER COLUMN nwc SET NOT NULL;

-- Revert zap_configs changes
ALTER TABLE zap_configs
    DROP CONSTRAINT zap_config_connection_check;
ALTER TABLE zap_configs
    DROP COLUMN auth_index;
ALTER TABLE zap_configs
    ALTER COLUMN nwc SET NOT NULL;

-- Drop the wallet_auth table
DROP TABLE wallet_auth;
